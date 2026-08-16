//! A disposable, in-memory SCIM 2.0 HTTP server built on `scimforge` -- exists solely to
//! give GitHub issue #1 (real-IdP conformance testing) a live consumer to point a real
//! Keycloak instance at. **Not a reference implementation**: no persistence, no
//! concurrency control beyond a single mutex, minimal error handling, a single shared
//! bearer token for auth. Do not copy this as a starting point for a production SCIM
//! server -- copy `scimforge`'s own module docs instead.

pub mod discovery;
pub mod error;
pub mod groups;
pub mod patch_request;
pub mod store;
pub mod users;

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};

use store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub bearer_token: Arc<str>,
}

impl AppState {
    pub fn new(bearer_token: impl Into<Arc<str>>) -> Self {
        let bearer_token = bearer_token.into();
        assert!(
            !bearer_token.is_empty(),
            "bearer_token must not be empty -- an empty token would make the literal header \
             \"Bearer \" a valid credential, authenticating any client that sends it"
        );
        AppState {
            store: Arc::new(Mutex::new(Store::default())),
            bearer_token,
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// RFC 7644 §3.1: "SCIM resources MUST include a Content-Type header field with the
/// value 'application/scim+json'." `axum::Json<T>` defaults to plain `application/json`,
/// which the SCIM SDK `little-auth/keycloak-scim-client` is built on validates strictly --
/// confirmed live: a genuine `201 Created` with a plain `application/json` Content-Type
/// was logged by the plugin as a *failed* create, purely because of this header, which
/// then cascaded into `mapping.getScimId()` never getting set and every later admin
/// action silently self-healing into a repeated CREATE instead of a real update. Applied
/// as the outermost layer in `build_router` so it covers error responses too, not just
/// success ones -- RFC 7644 §3.12's error body is itself a SCIM resource. Skips `204 No
/// Content` (DELETE): a Content-Type header on a response with no body is meaningless and
/// some strict clients flag it.
async fn set_scim_content_type(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if response.status() != StatusCode::NO_CONTENT {
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/scim+json"),
        );
    }
    response
}

async fn require_bearer_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, error::ApiError> {
    let expected = format!("Bearer {}", state.bearer_token);
    let ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()));
    if ok {
        Ok(next.run(request).await)
    } else {
        Err(error::ApiError::Unauthorized)
    }
}

async fn service_provider_config() -> Json<scimforge::discovery::ServiceProviderConfig> {
    Json(discovery::service_provider_config())
}

async fn resource_types() -> Json<Vec<scimforge::discovery::ResourceType>> {
    Json(discovery::resource_types())
}

async fn schemas() -> Json<Vec<scimforge::discovery::SchemaResource>> {
    Json(discovery::schemas())
}

/// Diagnostic-only, non-SCIM endpoint the integration test polls to inspect the raw
/// request bodies this server actually received -- see `src/store.rs`'s doc comment for
/// why this exists at all.
async fn captured(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let store = state.store.lock().unwrap();
    let entries = store
        .captured
        .iter()
        .map(|c| {
            serde_json::json!({
                "resourceType": c.resource_type,
                "method": c.method,
                "id": c.id,
                "contentType": c.content_type,
                "body": c.body,
            })
        })
        .collect();
    Json(entries)
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/ServiceProviderConfig", get(service_provider_config))
        .route("/ResourceTypes", get(resource_types))
        .route("/Schemas", get(schemas))
        .route("/Users", post(users::create).get(users::list))
        .route(
            "/Users/{id}",
            get(users::get)
                .put(users::replace)
                .patch(users::patch)
                .delete(users::delete),
        )
        .route("/Groups", post(groups::create).get(groups::list))
        .route(
            "/Groups/{id}",
            get(groups::get).patch(groups::patch).delete(groups::delete),
        )
        .route("/__captured/{resource}", get(captured_for))
        .route("/__captured", get(captured))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer_token,
        ))
        .layer(middleware::from_fn(set_scim_content_type))
        .with_state(state)
}

async fn captured_for(
    State(state): State<AppState>,
    axum::extract::Path(resource): axum::extract::Path<String>,
) -> Json<Vec<serde_json::Value>> {
    let store = state.store.lock().unwrap();
    let entries = store
        .captured
        .iter()
        .filter(|c| c.resource_type.eq_ignore_ascii_case(&resource))
        .map(|c| {
            serde_json::json!({
                "resourceType": c.resource_type,
                "method": c.method,
                "id": c.id,
                "contentType": c.content_type,
                "body": c.body,
            })
        })
        .collect();
    Json(entries)
}

pub const NOT_FOUND: StatusCode = StatusCode::NOT_FOUND;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_app() -> Router {
        build_router(AppState::new("test-token"))
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn rejects_requests_with_no_bearer_token() {
        let app = test_app();
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/ServiceProviderConfig")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_requests_with_the_wrong_bearer_token() {
        let app = test_app();
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/ServiceProviderConfig")
            .header(axum::http::header::AUTHORIZATION, "Bearer wrong-token")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn serves_service_provider_config_with_the_right_bearer_token() {
        let app = test_app();
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/ServiceProviderConfig")
            .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["patch"]["supported"], true);
    }
}
