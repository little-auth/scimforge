//! `/Groups` handlers -- same shape and same caveats as `src/users.rs`, kept smaller since
//! nothing in the live conformance test drives it: `little-auth/keycloak-scim-client`'s
//! `main` branch (Slice 1) has no group-sync feature at all -- its
//! `AdminUserEventInterpreter` only ever interprets `ResourceType.USER` admin events, so
//! there's no plugin-side config key or event path to exercise these routes against yet.
//! They exist so `/Groups` isn't a 404 against `scimforge`'s own group support, not because
//! the plugin under test currently propagates anything here.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use scimforge::common::{Meta, ResourceId};
use scimforge::group::{GROUP_SCHEMA_URI, Group, group_schema};
use scimforge::patch::apply_patch_with_schema;
use serde_json::Value;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;
use crate::patch_request::parse_patch_operations;

fn content_type_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn now_meta(id: &str, created: chrono::DateTime<Utc>) -> Meta {
    Meta {
        resource_type: "Group".to_string(),
        created,
        last_modified: Utc::now(),
        location: format!("/Groups/{id}"),
        version: None,
    }
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Response, ApiError> {
    let content_type = content_type_of(&headers);
    {
        let mut store = state.store.lock().unwrap();
        store.capture("Group", "POST", None, content_type, body.clone());
    }

    let mut group: Group =
        serde_json::from_value(body).map_err(|e| ApiError::InvalidBody(e.to_string()))?;

    let id = Uuid::new_v4().to_string();
    let created = Utc::now();
    group.id = Some(ResourceId::new(id.clone())); // server-assigned -- see users::create's comment on why this overwrite matters
    group.meta = Some(now_meta(&id, created));
    if group.schemas.is_empty() {
        group.schemas = vec![GROUP_SCHEMA_URI.to_string()];
    }

    let value = serde_json::to_value(&group).expect("Group always serializes");
    {
        let mut store = state.store.lock().unwrap();
        store.groups.insert(id.clone(), value.clone());
    }

    Ok((
        StatusCode::CREATED,
        [(axum::http::header::LOCATION, format!("/Groups/{id}"))],
        Json(value),
    )
        .into_response())
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let store = state.store.lock().unwrap();
    store
        .groups
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(id.clone()))
}

pub async fn list(State(state): State<AppState>) -> Json<Value> {
    let store = state.store.lock().unwrap();
    let resources: Vec<Value> = store.groups.values().cloned().collect();
    let total = resources.len();
    Json(serde_json::json!({
        "schemas": [scimforge::list_response::LIST_RESPONSE_SCHEMA_URI],
        "totalResults": total,
        "startIndex": 1,
        "itemsPerPage": total,
        "Resources": resources,
    }))
}

pub async fn patch(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let content_type = content_type_of(&headers);
    let existing = {
        let mut store = state.store.lock().unwrap();
        store.capture(
            "Group",
            "PATCH",
            Some(id.clone()),
            content_type,
            body.clone(),
        );
        store
            .groups
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(id.clone()))?
    };

    let operations = parse_patch_operations(&body)?;
    let mut patched = apply_patch_with_schema(&existing, &operations, &group_schema())?;
    if let Some(meta) = patched.get_mut("meta") {
        meta["lastModified"] = serde_json::to_value(Utc::now()).unwrap();
    }

    // Round-trip through the typed Group, same as users::patch: group_schema() only
    // models displayName/members (plus the universal PROTECTED_TOP_LEVEL guard for
    // id/meta/schemas in src/patch.rs), so any *other* attribute name a client PATCHes
    // in sails straight through the merge with no rejection -- check_mutability
    // explicitly no-ops on an attribute find_attribute can't resolve. Persisting the
    // typed round-trip instead of the raw merged Value drops any such smuggled
    // attribute before it can persist and be served back on every later GET/LIST.
    let group: Group = serde_json::from_value(patched.clone()).map_err(|e| {
        ApiError::InvalidBody(format!(
            "patched resource no longer deserializes as a typed Group: {e}"
        ))
    })?;
    let value = serde_json::to_value(&group).expect("Group always serializes");

    let mut store = state.store.lock().unwrap();
    // Re-check the group still exists under this fresh lock: the store was unlocked
    // for the whole patch/typed-round-trip computation above, so a concurrent DELETE
    // could have removed it in the meantime. Without this check, an unconditional
    // insert would resurrect a resource a racing client just explicitly deleted.
    if !store.groups.contains_key(&id) {
        return Err(ApiError::NotFound(id));
    }
    store.groups.insert(id, value.clone());
    Ok(Json(value))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let content_type = content_type_of(&headers);
    let mut store = state.store.lock().unwrap();
    store.capture(
        "Group",
        "DELETE",
        Some(id.clone()),
        content_type,
        Value::Null,
    );
    store
        .groups
        .remove(&id)
        .map(|_| StatusCode::NO_CONTENT)
        .ok_or(ApiError::NotFound(id))
}
