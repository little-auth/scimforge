//! GitHub issue #1: real Keycloak + mitodl/keycloak-scim provisioning traffic against a
//! live scimitar-based consumer. `#[ignore]`d by default -- this needs a running Keycloak
//! (brought up separately via `keycloak-it/docker/docker-compose.yml`, not by this test
//! itself, so CI can isolate "bring up the stack" from "drive it and assert" as two
//! reviewable steps) reachable at `KEYCLOAK_BASE_URL` (default `http://localhost:8090`).
//!
//! This test runs the example SCIM server (`keycloak_it::build_router`) in-process on a
//! fixed port rather than as its own container, specifically so it can assert directly
//! against the server's in-memory capture log (`GET /__captured`) without a second HTTP
//! hop -- Keycloak (in Docker) reaches this process via `host.docker.internal`, wired up
//! by the compose file's `extra_hosts`.
//!
//! Run locally (with Docker):
//! ```text
//! cd keycloak-it/docker && docker compose up --build -d
//! cargo test -p keycloak-it --test keycloak_conformance -- --ignored --nocapture
//! ```
//!
//! The DELETE assertion below only passes because of
//! `docker/patches/0001-fix-delete-npe.patch`. A live run against the unpatched, pinned
//! plugin commit found `ScimEventListenerProvider.onEvent(AdminEvent, ..)`'s DELETE branch
//! NullPointerExceptions every time: it calls `getUser(userId)` to check
//! `user.isEmailVerified()` before dispatching, but by the time the DELETE admin event
//! fires, Keycloak has already removed the user row, so `getUser` returns `null` and the
//! unchecked `.isEmailVerified()` call throws -- the plugin's own event listener crashes
//! before it ever builds the outbound SCIM request, so no DELETE reaches this server at
//! all without the patch, no matter how long this test waits. See
//! `keycloak-it/README.md`'s findings section for the exact stack trace and the patch's
//! own header for the upstream fix this mitigates.

use std::time::Duration;

use keycloak_it::{AppState, build_router};
use serde_json::{Value, json};

const BEARER_TOKEN: &str = "scim-it-conformance-test-token";
const SERVER_PORT: u16 = 8087;

fn keycloak_base_url() -> String {
    std::env::var("KEYCLOAK_BASE_URL").unwrap_or_else(|_| "http://localhost:8090".to_string())
}

/// This server's own base URL as *Keycloak's container* reaches it -- not `localhost`,
/// since the plugin runs inside Docker and needs the host-gateway address configured in
/// `docker-compose.yml`'s `extra_hosts`.
fn server_url_from_keycloaks_perspective() -> String {
    format!("http://host.docker.internal:{SERVER_PORT}")
}

async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut attempt: F) -> Value
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Value>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = attempt().await {
            return v;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out after {timeout:?} waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

struct KeycloakAdmin {
    client: reqwest::Client,
    base_url: String,
    token: String,
}

impl KeycloakAdmin {
    async fn connect() -> Self {
        let base_url = keycloak_base_url();
        let client = reqwest::Client::new();
        // Keycloak's dev-mode startup (plus, on a cold `docker compose up --build`, the
        // plugin's own Gradle-built jar loading) can take well over a minute -- a bounded
        // retry loop here, not a fixed sleep, so this both fails fast on a truly broken
        // stack and doesn't flake on a slow-but-healthy one.
        let token = wait_for(
            "Keycloak admin token endpoint to become reachable",
            Duration::from_secs(120),
            || {
                let client = client.clone();
                let base_url = base_url.clone();
                async move { fetch_admin_token(&client, &base_url).await }
            },
        )
        .await;
        KeycloakAdmin {
            client,
            base_url,
            token: token["access_token"].as_str().unwrap().to_string(),
        }
    }

    async fn create_realm(&self, realm: &str) {
        let resp = self
            .client
            .post(format!("{}/admin/realms", self.base_url))
            .bearer_auth(&self.token)
            .json(&json!({
                "realm": realm,
                "enabled": true,
                "eventsListeners": ["jboss-logging", "scim"]
            }))
            .send()
            .await
            .expect("create realm request");
        assert!(
            resp.status().is_success(),
            "create realm failed: {}",
            resp.status()
        );
    }

    async fn create_scim_federation_provider(&self, realm: &str) {
        let resp = self
            .client
            .post(format!("{}/admin/realms/{realm}/components", self.base_url))
            .bearer_auth(&self.token)
            .json(&json!({
                "name": "scim-it-server",
                "providerId": "scim",
                "providerType": "org.keycloak.storage.UserStorageProvider",
                "config": {
                    "endpoint": [server_url_from_keycloaks_perspective()],
                    "content-type": ["application/json"],
                    "auth-mode": ["BEARER"],
                    "auth-pass": [BEARER_TOKEN],
                    "propagation-user": ["true"],
                    "propagation-group": ["false"],
                    // Without this, ScimClient.replace() sends a full PUT (confirmed by a
                    // live run: UserAdapter.toSCIM() serializes typed JSON, no coercion
                    // needed) -- the plugin only takes the toPatchBuilder() path this
                    // harness exists to exercise (active.toString(), a JSON *string*
                    // "false"/"true") when user-patchOp is explicitly enabled.
                    "user-patchOp": ["true"]
                }
            }))
            .send()
            .await
            .expect("create SCIM federation provider component request");
        assert!(
            resp.status().is_success(),
            "create SCIM federation provider failed: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    async fn create_user(&self, realm: &str, username: &str) -> String {
        let resp = self
            .client
            .post(format!("{}/admin/realms/{realm}/users", self.base_url))
            .bearer_auth(&self.token)
            .json(&json!({
                "username": username,
                "email": format!("{username}@example.com"),
                "firstName": "Babs",
                "lastName": "Jensen",
                "enabled": true,
                // Found only by running this live (first attempt timed out waiting for
                // a POST that never came): ScimEventListenerProvider.onEvent(AdminEvent,
                // ..) gates every one of CREATE/UPDATE/DELETE on
                // `user.isEmailVerified()` (src/main/java/sh/libre/scim/event/
                // ScimEventListenerProvider.java, pinned commit
                // eec8ecd14971886f0d00f3dc688b587c3002f252) -- a real, currently-shipping
                // Keycloak SCIM plugin simply does not provision a user via SCIM at all
                // unless this Keycloak-side flag is set, independent of anything in RFC
                // 7644. Nothing to accommodate in scimitar (this is plugin business
                // logic, not a request shape), but the harness needs it to exercise the
                // plugin at all.
                "emailVerified": true
            }))
            .send()
            .await
            .expect("create user request");
        assert!(
            resp.status().is_success(),
            "create user failed: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
        // Keycloak returns the new user's id in the Location header, not the body.
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .expect("Location header on user create")
            .to_str()
            .unwrap()
            .to_string();
        location.rsplit('/').next().unwrap().to_string()
    }

    async fn set_user_enabled(&self, realm: &str, user_id: &str, enabled: bool) {
        let resp = self
            .client
            .put(format!(
                "{}/admin/realms/{realm}/users/{user_id}",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .json(&json!({"enabled": enabled}))
            .send()
            .await
            .expect("update user request");
        assert!(
            resp.status().is_success(),
            "update user failed: {}",
            resp.status()
        );
    }

    async fn delete_user(&self, realm: &str, user_id: &str) {
        let resp = self
            .client
            .delete(format!(
                "{}/admin/realms/{realm}/users/{user_id}",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .expect("delete user request");
        assert!(
            resp.status().is_success(),
            "delete user failed: {}",
            resp.status()
        );
    }
}

async fn fetch_admin_token(client: &reqwest::Client, base_url: &str) -> Option<Value> {
    let resp = client
        .post(format!(
            "{base_url}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", "admin"),
        ])
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

async fn captured_users(client: &reqwest::Client) -> Vec<Value> {
    let resp = client
        .get(format!("http://localhost:{SERVER_PORT}/__captured/user"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("captured request");
    resp.json::<Vec<Value>>().await.expect("captured body")
}

#[tokio::test]
#[ignore = "requires a live Keycloak + keycloak-scim instance -- see docker-compose.yml"]
async fn real_keycloak_provisioning_traffic_parses_and_applies_correctly() {
    let app = build_router(AppState::new(BEARER_TOKEN));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", SERVER_PORT))
        .await
        .expect("bind example server port");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("example server");
    });

    let admin = KeycloakAdmin::connect().await;
    let realm = "scim-it";
    admin.create_realm(realm).await;
    admin.create_scim_federation_provider(realm).await;

    let http = reqwest::Client::new();
    let username = "bjensen-conformance-test";
    let keycloak_user_id = admin.create_user(realm, username).await;

    let create_entry = wait_for(
        "the example server to receive a POST for the newly created Keycloak user",
        Duration::from_secs(30),
        || {
            let http = http.clone();
            let username = username.to_string();
            async move {
                captured_users(&http)
                    .await
                    .into_iter()
                    .find(|e| e["method"] == "POST" && e["body"]["userName"] == username)
            }
        },
    )
    .await;
    // RFC 7643 4.1.1's `active` is boolean -- this is the coercion fix's live-traffic
    // proof: whatever string/bool shape the plugin actually sent, the server's stored
    // (and here, captured pre-parse) response must reflect a real create having
    // succeeded through scimitar's User deserialization, not just this test's assumption
    // of what Keycloak sends.
    assert_eq!(create_entry["method"], "POST");
    println!(
        "issue #1 finding -- POST /Users Content-Type: {:?}",
        create_entry["contentType"]
    );
    println!(
        "issue #1 finding -- POST /Users body: {}",
        create_entry["body"]
    );

    admin
        .set_user_enabled(realm, &keycloak_user_id, false)
        .await;

    let update_entry = wait_for(
        "the example server to receive a PATCH or PUT reflecting the disabled user",
        Duration::from_secs(30),
        || {
            let http = http.clone();
            async move {
                captured_users(&http).await.into_iter().find(|e| {
                    (e["method"] == "PATCH" || e["method"] == "PUT") && e["id"].is_string()
                })
            }
        },
    )
    .await;
    println!(
        "issue #1 finding -- {} /Users/{{id}} Content-Type: {:?}",
        update_entry["method"], update_entry["contentType"]
    );
    println!(
        "issue #1 finding -- {} /Users/{{id}} body: {}",
        update_entry["method"], update_entry["body"]
    );
    // The concrete accommodation this whole harness exists to prove: if the plugin PATCHes
    // `active` as the JSON string "false" (as its source predicts -- see
    // src/patch.rs's coercion doc comment), the server must have coerced it, not stored a
    // string. Only asserted when the update actually took the PATCH `active` path --
    // Keycloak may instead have issued a full PUT, which this test still captures and
    // prints above for the record either way.
    if update_entry["method"] == "PATCH"
        && let Some(ops) = update_entry["body"]["Operations"].as_array()
        && let Some(op) = ops.iter().find(|op| op["path"] == "active")
    {
        println!("issue #1 finding -- active PATCH op value as sent: {op}");
    }

    // Only reachable because of docker/patches/0001-fix-delete-npe.patch: unpatched, the
    // plugin's own event listener NullPointerExceptions on every single Admin-API user
    // DELETE (getUser(userId) always returns null by the time the DELETE admin event
    // fires, and the DELETE branch calls user.isEmailVerified() without a null check), so
    // no DELETE ever reaches this server at all -- see this function's module doc and
    // keycloak-it/README.md's findings section for the exact stack trace, root cause, and
    // the patch that fixes it.
    admin.delete_user(realm, &keycloak_user_id).await;
    let delete_entry = wait_for(
        "the example server to receive a DELETE for the removed user",
        Duration::from_secs(30),
        || {
            let http = http.clone();
            async move {
                captured_users(&http)
                    .await
                    .into_iter()
                    .find(|e| e["method"] == "DELETE")
            }
        },
    )
    .await;
    assert_eq!(delete_entry["method"], "DELETE");
}
