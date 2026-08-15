//! `/Users` handlers. Deliberately minimal: no real persistence, no concurrency control,
//! no `PUT` conflict detection -- exists to get real Keycloak-plugin traffic in front of
//! scimforge's parsing/validation/PATCH code, not to be a usable SCIM server.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use scimforge::common::{Meta, ResourceId};
use scimforge::patch::apply_patch_with_schema;
use scimforge::user::{USER_SCHEMA_URI, User, user_schema};
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
        resource_type: "User".to_string(),
        created,
        last_modified: Utc::now(),
        location: format!("/Users/{id}"),
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
        store.capture("User", "POST", None, content_type, body.clone());
    }

    let mut user: User =
        serde_json::from_value(body).map_err(|e| ApiError::InvalidBody(e.to_string()))?;

    let id = Uuid::new_v4().to_string();
    let created = Utc::now();
    // RFC 7643 3.1: `id` "is always issued by the service provider and MUST NOT be
    // specified by the client" -- deserializing the request body above may have already
    // populated `user.id` from whatever the client sent (ResourceId's Deserialize impl
    // doesn't route through its `new()` constructor, only ordinary code paths do), so
    // this overwrite is deliberate, not incidental: the server-generated id always wins,
    // matching CVE-2025-41115's root-cause lesson (never trust a client-supplied
    // identifier as if it were server-assigned).
    user.id = Some(ResourceId::new(id.clone()));
    user.meta = Some(now_meta(&id, created));
    if user.schemas.is_empty() {
        user.schemas = vec![USER_SCHEMA_URI.to_string()];
    }

    let value = serde_json::to_value(&user).expect("User always serializes");
    {
        let mut store = state.store.lock().unwrap();
        store.users.insert(id.clone(), value.clone());
    }

    Ok((
        StatusCode::CREATED,
        [(axum::http::header::LOCATION, format!("/Users/{id}"))],
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
        .users
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(id.clone()))
}

pub async fn list(State(state): State<AppState>) -> Json<Value> {
    // Filter-query evaluation over a whole collection is deliberately out of scope for
    // scimforge itself (see src/filter.rs's module doc) and isn't exercised by the
    // Keycloak plugin's event-driven push path this harness targets (only its optional
    // periodic full-import sync would call this with a filter) -- so this ignores any
    // `?filter=` query and returns everything, documented rather than silently partial.
    let store = state.store.lock().unwrap();
    let resources: Vec<Value> = store.users.values().cloned().collect();
    let total = resources.len();
    Json(serde_json::json!({
        "schemas": [scimforge::list_response::LIST_RESPONSE_SCHEMA_URI],
        "totalResults": total,
        "startIndex": 1,
        "itemsPerPage": total,
        "Resources": resources,
    }))
}

pub async fn replace(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let content_type = content_type_of(&headers);
    {
        let mut store = state.store.lock().unwrap();
        store.capture("User", "PUT", Some(id.clone()), content_type, body.clone());
    }

    let existing_created = {
        let store = state.store.lock().unwrap();
        let existing = store
            .users
            .get(&id)
            .ok_or_else(|| ApiError::NotFound(id.clone()))?;
        existing
            .get("meta")
            .and_then(|m| m.get("created"))
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now)
    };

    let mut user: User =
        serde_json::from_value(body).map_err(|e| ApiError::InvalidBody(e.to_string()))?;
    user.id = Some(ResourceId::new(id.clone()));
    user.meta = Some(now_meta(&id, existing_created));
    if user.schemas.is_empty() {
        user.schemas = vec![USER_SCHEMA_URI.to_string()];
    }
    let value = serde_json::to_value(&user).expect("User always serializes");

    let mut store = state.store.lock().unwrap();
    // Re-check the user still exists under this fresh lock: the store was unlocked
    // between the existence check above and here, so a concurrent DELETE could have
    // removed it in the meantime. Without this check, an unconditional insert would
    // resurrect a resource a racing client just explicitly deleted.
    if !store.users.contains_key(&id) {
        return Err(ApiError::NotFound(id));
    }
    store.users.insert(id, value.clone());
    Ok(Json(value))
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
            "User",
            "PATCH",
            Some(id.clone()),
            content_type,
            body.clone(),
        );
        store
            .users
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(id.clone()))?
    };

    let operations = parse_patch_operations(&body)?;
    let mut patched = apply_patch_with_schema(&existing, &operations, &user_schema())?;
    if let Some(meta) = patched.get_mut("meta") {
        meta["lastModified"] = serde_json::to_value(Utc::now()).unwrap();
    }

    let user: User = serde_json::from_value(patched.clone()).map_err(|e| {
        ApiError::InvalidBody(format!(
            "patched resource no longer deserializes as a typed User: {e}"
        ))
    })?;
    let value = serde_json::to_value(&user).expect("User always serializes");

    let mut store = state.store.lock().unwrap();
    // Re-check the user still exists under this fresh lock: the store was unlocked for
    // the whole patch/typed-round-trip computation above, so a concurrent DELETE could
    // have removed it in the meantime. Without this check, an unconditional insert
    // would resurrect a resource a racing client just explicitly deleted.
    if !store.users.contains_key(&id) {
        return Err(ApiError::NotFound(id));
    }
    store.users.insert(id, value.clone());
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
        "User",
        "DELETE",
        Some(id.clone()),
        content_type,
        Value::Null,
    );
    store
        .users
        .remove(&id)
        .map(|_| StatusCode::NO_CONTENT)
        .ok_or(ApiError::NotFound(id))
}
