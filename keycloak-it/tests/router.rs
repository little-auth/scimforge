//! In-process HTTP-layer tests against literal request bodies -- no Docker, no network,
//! no live Keycloak needed. This is the local TDD surface for "does a real Keycloak
//! SCIM-plugin request actually get accepted and parsed correctly end to end" (GitHub
//! issue #1): the request bodies here are shaped exactly as researched from
//! mitodl/keycloak-scim's source (`UserAdapter.toSCIM()`/`toPatchBuilder()`, pinned
//! commit eec8ecd14971886f0d00f3dc688b587c3002f252), not guessed at. The actual live
//! Keycloak run (`tests/keycloak_conformance.rs`, `#[ignore]`d) is the real-world trial;
//! this file is what makes that trial's outcome predictable ahead of time.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use keycloak_it::{AppState, build_router};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "test-token";

fn app() -> axum::Router {
    build_router(AppState::new(TOKEN))
}

async fn send(app: axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

fn authed(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
}

fn json_body(value: &Value) -> Body {
    Body::from(serde_json::to_vec(value).unwrap())
}

/// mitodl/keycloak-scim's `UserAdapter.toSCIM()` builds a create body with exactly these
/// fields populated -- externalId, userName, id (Keycloak's own bookkeeping, not a trust
/// signal -- see users::create's doc comment), displayName, name.{givenName,familyName},
/// a single-entry emails array with no `type`, and active.
fn keycloak_style_create_body() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "userName": "bjensen",
        "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "displayName": "Babs Jensen",
        "name": {"givenName": "Babs", "familyName": "Jensen"},
        "emails": [{"value": "bjensen@example.com"}],
        "active": true
    })
}

#[tokio::test]
async fn creates_a_user_from_a_keycloak_plugin_shaped_body() {
    let (status, body) = send(
        app(),
        authed("POST", "/Users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&keycloak_style_create_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["userName"], "bjensen");
    assert_eq!(body["active"], true);
    // The server-generated id must never equal the client-supplied one from the request
    // body above -- proving users::create's overwrite (see its doc comment) actually ran,
    // not just that the field happens to be present.
    assert_ne!(body["id"], json!("f47ac10b-58cc-4372-a567-0e02b2c3d479"));
    assert!(
        body["meta"]["location"]
            .as_str()
            .unwrap()
            .starts_with("/Users/")
    );
}

#[tokio::test]
async fn accepts_application_scim_plus_json_content_type() {
    // RFC 7644 3.1's registered media type -- some deployments configure the plugin's
    // "content-type" property to this instead of plain application/json.
    let (status, _) = send(
        app(),
        authed("POST", "/Users")
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(json_body(&keycloak_style_create_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn patches_a_boolean_attribute_sent_as_a_keycloak_plugin_shaped_string_value() {
    let router = app();
    let (_, created) = send(
        router.clone(),
        authed("POST", "/Users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&keycloak_style_create_body()))
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    // UserAdapter.toPatchBuilder()'s exact shape: value is the JSON string "false".
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "active", "value": "false"},
            {"op": "replace", "path": "userName", "value": "bjensen2"},
            {"op": "replace", "path": "displayName", "value": "Babs Jensen 2"}
        ]
    });
    let (status, patched) = send(
        router,
        authed("PATCH", &format!("/Users/{id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The core-library coercion (src/patch.rs) must have turned "false" into a real JSON
    // boolean here -- a strict RFC-literal server would have stored the string verbatim.
    assert_eq!(patched["active"], json!(false));
    assert_eq!(patched["userName"], "bjensen2");
}

#[tokio::test]
async fn deletes_a_user() {
    let router = app();
    let (_, created) = send(
        router.clone(),
        authed("POST", "/Users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&keycloak_style_create_body()))
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, _) = send(
        router.clone(),
        authed("DELETE", &format!("/Users/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        router,
        authed("GET", &format!("/Users/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_captured_diagnostic_endpoint_records_the_raw_patch_body_verbatim() {
    let router = app();
    let (_, created) = send(
        router.clone(),
        authed("POST", "/Users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&keycloak_style_create_body()))
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "Operations": [{"op": "replace", "path": "active", "value": "true"}]
    });
    send(
        router.clone(),
        authed("PATCH", &format!("/Users/{id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap(),
    )
    .await;

    let (status, captured) = send(
        router,
        authed("GET", "/__captured/user")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entries = captured.as_array().unwrap();
    let patch_entry = entries
        .iter()
        .find(|e| e["method"] == "PATCH")
        .expect("a captured PATCH entry");
    // Exactly the wire shape the plugin sent, string value and all -- proving this is
    // capturing what actually arrived, not a post-coercion reconstruction.
    assert_eq!(patch_entry["body"]["Operations"][0]["value"], json!("true"));
}

#[tokio::test]
async fn patching_password_never_echoes_or_persists_the_plaintext_value() {
    // Regression for a high-severity info-disclosure bug: PATCH used to operate on the
    // raw stored JSON instead of the typed User, so a client-supplied password (schema
    // mutability writeOnly, not blocked by check_mutability) was merged straight in and
    // survived into the PATCH response, the persisted record, and every future GET.
    let router = app();

    let (_, created) = send(
        router.clone(),
        authed("POST", "/Users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&keycloak_style_create_body()))
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "password", "value": "hunter2-plaintext"}
        ]
    });

    let (status, patch_response) = send(
        router.clone(),
        authed("PATCH", &format!("/Users/{id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        patch_response.get("password").is_none(),
        "PATCH response must never echo the plaintext password: {patch_response}"
    );

    let (_, get_response) = send(
        router,
        authed("GET", &format!("/Users/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        get_response.get("password").is_none(),
        "a later GET must not leak the persisted plaintext password: {get_response}"
    );
}

#[tokio::test]
async fn patching_a_group_with_an_unmodeled_attribute_does_not_persist_it() {
    // Regression: groups::patch used to persist the raw merged serde_json::Value
    // directly, unlike users::patch's typed round-trip -- group_schema() only models
    // displayName/members, so a client PATCHing in an attribute name outside that set
    // (not id/meta/schemas, which the crate's universal PROTECTED_TOP_LEVEL guard
    // already blocks) sailed straight through unmodeled_attribute's ReadWrite fallback
    // and persisted indefinitely, served back on every later GET/LIST.
    let router = app();

    let (_, created) = send(
        router.clone(),
        authed("POST", "/Groups")
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineering",
            })))
            .unwrap(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "value": {"smuggledAttribute": "attacker-controlled"}}
        ]
    });
    let (status, patch_response) = send(
        router.clone(),
        authed("PATCH", &format!("/Groups/{id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(&patch_body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        patch_response.get("smuggledAttribute").is_none(),
        "PATCH response must not echo an attribute outside the Group schema: {patch_response}"
    );

    let (_, get_response) = send(
        router,
        authed("GET", &format!("/Groups/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        get_response.get("smuggledAttribute").is_none(),
        "a later GET must not serve back a smuggled unmodeled attribute: {get_response}"
    );
}
