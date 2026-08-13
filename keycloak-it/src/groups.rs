//! `/Groups` handlers -- same shape and same caveats as `src/users.rs`, kept smaller
//! since the Keycloak conformance test's primary target is the `propagation-user` path;
//! `propagation-group` exercises the same PATCH/coercion code paths against a different
//! resource type, so this exists for completeness rather than needing its own richer
//! test surface.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use scimitar::common::{Meta, ResourceId};
use scimitar::group::{GROUP_SCHEMA_URI, Group, group_schema};
use scimitar::patch::apply_patch_with_schema;
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
        "schemas": [scimitar::list_response::LIST_RESPONSE_SCHEMA_URI],
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

    let mut store = state.store.lock().unwrap();
    store.groups.insert(id, patched.clone());
    Ok(Json(patched))
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
