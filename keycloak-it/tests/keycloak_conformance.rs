//! GitHub issue #1: real Keycloak + little-auth/keycloak-scim-client provisioning traffic
//! against a live scimforge-based consumer. `#[ignore]`d by default -- this needs a running
//! Keycloak (brought up separately via `keycloak-it/docker/docker-compose.yml`, not by this
//! test itself, so CI can isolate "bring up the stack" from "drive it and assert" as two
//! reviewable steps) reachable at `KEYCLOAK_BASE_URL` (default `http://localhost:8090`).
//!
//! Targets `keycloak-scim-client`'s `main` branch only (Slice 1: provider id
//! `keycloak-scim-target`, config keys `targetUrl`/`targetUrlAllowlistHosts`/
//! `credentialVaultRef`/`deletePolicy`/`syncEnabled`). The plugin's Basic-auth,
//! reconciliation-checkpointing, and hard-delete-confirmation-UI features live on separate
//! unmerged feature branches (`feat/basic-auth-support`,
//! `feat/reconciliation-checkpointing`, `feat/hard-delete-confirmation-ui`) and aren't
//! built or exercised here.
//!
//! This test runs the example SCIM server (`keycloak_it::build_router`) in-process on a
//! fixed port rather than as its own container, specifically so it can assert directly
//! against the server's in-memory capture log (`GET /__captured`) without a second HTTP
//! hop -- Keycloak (in Docker) reaches this process via `host.docker.internal`, wired up
//! by the compose file's `extra_hosts`.
//!
//! Run locally (with Docker), after creating the Vault-SPI secret file the SCIM target
//! component's `credentialVaultRef` resolves through (see `keycloak-it/README.md`'s
//! "Running the live conformance test" for the full walkthrough):
//! ```text
//! mkdir -p keycloak-it/docker/vault
//! printf '%s' "scim-it-conformance-test-token" > keycloak-it/docker/vault/scim-it_scim-target-token
//! cd keycloak-it/docker && docker compose up --build -d
//! cd ..
//! KEYCLOAK_BASE_URL=http://localhost:8090 \
//!   cargo test -p keycloak-it --test keycloak_conformance -- --ignored --nocapture
//! ```
//!
//! Deprovisioning below deliberately leaves `deletePolicy` unset, exercising the plugin's
//! default (`SOFT_DELETE`): a Keycloak user delete maps to a PATCH-with-PUT-fallback
//! deactivation (`active: false`) on the SCIM target, never a literal HTTP DELETE verb --
//! see `ScimTargetClient.deprovision`/`setActive`. This is also what proves the
//! `mitodl/keycloak-scim` NullPointerException class this harness used to work around
//! (via a now-deleted local patch) doesn't exist here: `AdminUserEventInterpreter.interpret`
//! derives the deleted user's id from `AdminEvent#getResourcePath()` alone, never by
//! re-fetching the (already-gone) user, so dispatch happens cleanly regardless of delete
//! policy. `HARD_DELETE` (a genuine DELETE verb) is a real, separate configuration this
//! harness doesn't exercise live -- filed as a follow-up rather than silently assumed
//! equivalent to what's tested here.

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
        // plugin's own Maven-built jar loading) can take well over a minute -- a bounded
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
                // "keycloak-scim-client" (ScimEventListenerProviderFactory.ID), not
                // mitodl's "scim" -- confirmed live: an unfixed "scim" here produces
                // "KC-SERVICES0083: Event listener 'scim' registered, but provider not
                // found" and no SCIM traffic ever leaves Keycloak, no matter how correct
                // the rest of the component config is.
                "eventsListeners": ["jboss-logging", "keycloak-scim-client"]
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
                "providerId": "keycloak-scim-target",
                "providerType": "org.keycloak.storage.UserStorageProvider",
                "config": {
                    "targetUrl": [server_url_from_keycloaks_perspective()],
                    // TargetUrlValidator (SSRF guard) rejects a non-HTTPS URL and any
                    // address in a private/internal range unless the host is explicitly
                    // allowlisted -- host.docker.internal is exactly the "local/CI
                    // conformance target" case its own doc comment names.
                    "targetUrlAllowlistHosts": ["host.docker.internal"],
                    // Resolved through Keycloak's Vault SPI at dispatch time, never a raw
                    // secret in this config -- see this file's module doc for the vault
                    // secret file this reference resolves against (REALM_UNDERSCORE_KEY
                    // convention: realm "scim-it" + key "scim-target-token").
                    "credentialVaultRef": ["${vault.scim-target-token}"],
                    // Live kill switch, default false -- omitting this would leave every
                    // admin event resolving to "sync disabled for realm" and every
                    // wait_for below timing out with a misleading panic instead of a
                    // clear cause.
                    "syncEnabled": ["true"]
                    // deletePolicy deliberately omitted -- see module doc for why this
                    // exercises the plugin's SOFT_DELETE default rather than HARD_DELETE.
                }
            }))
            .send()
            .await
            .expect("create SCIM target component request");
        assert!(
            resp.status().is_success(),
            "create SCIM target component failed: {} {}",
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
                "enabled": true
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

    /// Fetches the user's current full representation and PUTs it back with `enabled`
    /// toggled -- matching how Keycloak's own Admin Console actually updates a user
    /// (GET, mutate locally, PUT the complete representation back), not a minimal
    /// `{"enabled": ...}` body.
    ///
    /// Confirmed live this distinction is load-bearing, not cosmetic:
    /// `KeycloakUserMapper.toScimUser` maps whatever `AdminEvent#getRepresentation()`
    /// carries, which is the raw admin-request body Keycloak logged for that event, not a
    /// server-side merge with the persisted user -- a minimal `{"enabled": false}` body
    /// produces an admin event representation with no `userName`, and this server
    /// (correctly, per RFC 7643 4.1's REQUIRED `userName`) rejects the resulting outbound
    /// PUT with `400 missing field \`userName\``. `ScimEventListenerProvider`'s own
    /// module doc states its UPDATE handling "always carries a complete representation" --
    /// true for the common Admin-Console-driven case this method now matches, but not
    /// guaranteed for every possible Admin-REST-API caller. Filed as a follow-up against
    /// keycloak-scim-client rather than fixed here (out of this harness's scope).
    async fn set_user_enabled_via_full_representation(
        &self,
        realm: &str,
        user_id: &str,
        enabled: bool,
    ) {
        let current = self
            .client
            .get(format!(
                "{}/admin/realms/{realm}/users/{user_id}",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .send()
            .await
            .expect("get user request");
        assert!(
            current.status().is_success(),
            "get user failed: {}",
            current.status()
        );
        let mut representation: Value = current.json().await.expect("user representation body");
        representation["enabled"] = json!(enabled);

        let resp = self
            .client
            .put(format!(
                "{}/admin/realms/{realm}/users/{user_id}",
                self.base_url
            ))
            .bearer_auth(&self.token)
            .json(&representation)
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

/// True for a captured entry that's the deprovision deactivation this test waits for:
/// either a PATCH whose Operations array targets `active`, or a PUT whose body carries
/// `active: false`. Kept as its own predicate rather than inlined in the `wait_for`
/// closure -- the PATCH/PUT shape distinction is exactly the thing under test here, and a
/// tangled boolean expression inline was easy to get subtly wrong.
fn is_deactivation(entry: &Value) -> bool {
    match entry["method"].as_str() {
        Some("PATCH") => entry["body"]["Operations"]
            .as_array()
            .is_some_and(|ops| ops.iter().any(|op| op["path"] == "active")),
        Some("PUT") => entry["body"]["active"] == json!(false),
        _ => false,
    }
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
#[ignore = "requires a live Keycloak + keycloak-scim-client instance -- see docker-compose.yml"]
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
    assert_eq!(create_entry["method"], "POST");
    // little-auth/keycloak-scim-client's KeycloakUserMapper.toScimUser() never sets `id`
    // (only externalId, the Keycloak user id) -- proving this server never received a
    // client-supplied id to (incorrectly) trust in the first place, unlike mitodl's shape.
    assert!(create_entry["body"].get("id").is_none());
    assert_eq!(create_entry["body"]["externalId"], json!(keycloak_user_id));
    println!(
        "issue #1 finding -- POST /Users Content-Type: {:?}",
        create_entry["contentType"]
    );
    println!(
        "issue #1 finding -- POST /Users body: {}",
        create_entry["body"]
    );

    // Bridges a real gap this stateful plugin introduces that the old stateless mitodl
    // target didn't have: this server observing the POST only proves Keycloak's HTTP call
    // completed, not that the plugin's own SCIM_SYNC_MAPPING row (scimId) write -- which
    // happens synchronously right after, in the same background job, with no further
    // network round trip this server could wait on -- has landed yet. Without this, the
    // very next admin action below could race ahead of handleUpdate's
    // `mapping.getScimId() == null` self-heal check and trigger an unwanted second CREATE
    // instead of the intended PUT-replace.
    tokio::time::sleep(Duration::from_millis(500)).await;

    admin
        .set_user_enabled_via_full_representation(realm, &keycloak_user_id, false)
        .await;

    // General Keycloak UPDATE admin events always dispatch a full PUT
    // (ScimEventListenerProvider.handleUpdate -> ScimTargetClient.replaceUser) -- there is
    // no PATCH-on-plain-update path in keycloak-scim-client, unlike mitodl's
    // user-patchOp-gated behavior this harness used to exercise. Asserting PUT
    // specifically, not "PATCH or PUT", is itself a real conformance claim about this
    // plugin's actual behavior, not a loosened check.
    let update_entry = wait_for(
        "the example server to receive a PUT reflecting the disabled user",
        Duration::from_secs(30),
        || {
            let http = http.clone();
            async move {
                captured_users(&http)
                    .await
                    .into_iter()
                    .find(|e| e["method"] == "PUT" && e["id"].is_string())
            }
        },
    )
    .await;
    assert_eq!(update_entry["method"], "PUT");
    assert_eq!(update_entry["body"]["active"], json!(false));
    // Proves this PUT actually deserializes as a complete, acceptable SCIM User (RFC 7643
    // 4.1's REQUIRED userName present) -- the thing set_user_enabled_via_full_representation
    // exists to guarantee. A PUT missing userName would still get captured here (capture
    // happens before this server's own deserialization/validation), so this assertion is
    // what actually distinguishes "arrived" from "arrived and was acceptable."
    assert_eq!(update_entry["body"]["userName"], json!(username));
    println!(
        "issue #1 finding -- PUT /Users/{{id}} Content-Type: {:?}",
        update_entry["contentType"]
    );
    println!(
        "issue #1 finding -- PUT /Users/{{id}} body: {}",
        update_entry["body"]
    );

    // Snapshot how many captures exist before triggering delete: the deactivation search
    // below must find a *new* entry, not spuriously re-match update_entry above (both can
    // legitimately be a PUT carrying active:false, so a shape-only predicate isn't enough
    // on its own -- confirmed live this matters: without this guard, an actual delete-time
    // dispatch failure was masked by silently re-matching the update step's own capture).
    let captures_before_delete = captured_users(&http).await.len();

    // Only reachable at all because keycloak-scim-client's AdminUserEventInterpreter
    // derives the deleted user's id purely from AdminEvent#getResourcePath(), never by
    // re-fetching the (already-gone) user -- the exact bug class mitodl/keycloak-scim hit
    // (NullPointerException, every single Admin-API user DELETE, because its handler
    // called getUser(userId) and unconditionally dereferenced the null result) that this
    // harness used to work around with a now-deleted local source patch. With the
    // plugin's default SOFT_DELETE policy, a successful delete here dispatches a
    // PATCH-with-PUT-fallback deactivation, not a literal DELETE verb -- see this file's
    // module doc.
    admin.delete_user(realm, &keycloak_user_id).await;
    let deactivate_entry = wait_for(
        "the example server to receive a new PATCH or PUT deactivating the deleted user",
        Duration::from_secs(30),
        || {
            let http = http.clone();
            async move {
                captured_users(&http)
                    .await
                    .into_iter()
                    .skip(captures_before_delete)
                    .find(|e| e["id"].is_string() && is_deactivation(e))
            }
        },
    )
    .await;
    println!(
        "issue #1 finding -- deprovision {} /Users/{{id}} Content-Type: {:?}",
        deactivate_entry["method"], deactivate_entry["contentType"]
    );
    println!(
        "issue #1 finding -- deprovision {} /Users/{{id}} body: {}",
        deactivate_entry["method"], deactivate_entry["body"]
    );
    if deactivate_entry["method"] == "PATCH" {
        let ops = deactivate_entry["body"]["Operations"]
            .as_array()
            .expect("PATCH deprovision must carry an Operations array");
        let active_op = ops
            .iter()
            .find(|op| op["path"] == "active")
            .expect("PATCH deprovision must target the active attribute");
        // Confirmed live, and genuinely surprising: de.captaingoldfish:scim-sdk-client
        // (the SDK keycloak-scim-client is built on) wraps even a single-valued boolean
        // PATCH replace value in a JSON *array* -- `[false]`, not a bare `false` -- when
        // built via `.valueNode(BooleanNode.valueOf(active))`. Not mitodl's
        // string-coercion quirk (`"false"`); a different, SDK-specific wire shape this
        // harness had never seen before this migration.
        assert_eq!(active_op["value"], json!([false]));
        println!(
            "issue #1 finding -- scim-sdk-client wraps a single-valued boolean PATCH \
             replace value in a JSON array: {}",
            active_op["value"]
        );
    } else {
        assert_eq!(deactivate_entry["body"]["active"], json!(false));
    }

    // The strongest available proof this whole request actually applied correctly, not
    // just that this server's capture log recorded *something*: fetch the resource back
    // from this server's own store (still there under SOFT_DELETE -- deprovisioning
    // deactivates, it doesn't remove the resource) and check `active` landed as a real
    // JSON boolean. This is scimforge's own apply_patch_with_schema unwrapping the
    // array-wrapped value above, proven against real SDK traffic, not just the synthetic
    // shapes in tests/router.rs.
    let scim_id = deactivate_entry["id"]
        .as_str()
        .expect("deactivate_entry must carry the SCIM resource id");
    let get_resp = http
        .get(format!("http://localhost:{SERVER_PORT}/Users/{scim_id}"))
        .bearer_auth(BEARER_TOKEN)
        .send()
        .await
        .expect("get deactivated user request");
    assert!(
        get_resp.status().is_success(),
        "get user failed: {}",
        get_resp.status()
    );
    let persisted: Value = get_resp.json().await.expect("persisted user body");
    assert_eq!(persisted["active"], json!(false));
}
