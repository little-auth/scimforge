# keycloak-it

A disposable example SCIM 2.0 consumer plus a real-Keycloak conformance test harness for
`scimforge` (GitHub issue #1: "Real-IdP conformance testing"). **Not a reference
implementation** -- no persistence, no concurrency control beyond a single mutex, a
single shared bearer token for auth, minimal error handling. It exists to give real
Keycloak provisioning traffic somewhere to land, in front of `scimforge`'s own parsing and
PATCH-application code, so this repo's RFC-literal conformance claims can be checked
against what a real SCIM client actually sends -- not just against the spec text.

## What this targets

Keycloak acting as a SCIM *client*, pushing provisioning events to an external service
provider -- the same role Okta and Azure AD play against a real SCIM SP. That's the
opposite direction from Keycloak's own newer native "SCIM Realm API" (experimental as of
Keycloak 26.6), which makes Keycloak itself a SCIM *server*.

The plugin under test is [**little-auth/keycloak-scim-client**](https://github.com/little-auth/keycloak-scim-client)
-- an in-house Keycloak SCIM client plugin, replacing a prior third-party dependency this
harness used to build from source. Built on the same `de.captaingoldfish:scim-sdk-client`
SCIM SDK family, so requests are RFC-shaped by construction rather than hand-rolled per
call site.

**Targets `main` only, Slice 1 functionality.** As of this writing, `main` has:

- Provider id `keycloak-scim-target` (a User Storage Provider SPI component), config keys
  `targetUrl`, `targetUrlAllowlistHosts`, `credentialVaultRef` (a Keycloak Vault SPI
  reference, resolved to a Bearer token -- never a raw secret in config), `deletePolicy`
  (`SOFT_DELETE`/`HARD_DELETE`), `syncEnabled` (a live kill switch, default off).
- General Keycloak Admin-API `UPDATE` events always dispatch a full PUT
  (`ScimEventListenerProvider.handleUpdate` -> `ScimTargetClient.replaceUser`); there is no
  PATCH-on-plain-update path.
- Deprovisioning honors the realm's `deletePolicy`: `SOFT_DELETE` (the default) PATCHes
  `active` to `false` (falling back to a fetch-then-PUT if PATCH isn't supported or
  errors), `HARD_DELETE` issues a real `DELETE`.
- No group sync at all -- `AdminUserEventInterpreter` only interprets `ResourceType.USER`
  admin events.

Three other features -- Basic auth, reconciliation checkpointing, and a hard-delete
confirmation UI -- exist on separate branches (`feat/basic-auth-support`,
`feat/reconciliation-checkpointing`, `feat/hard-delete-confirmation-ui`) that are **not
merged into `main`** as of this writing. This harness targets what's actually on `main`
today, not those branches; nothing here should be read as covering them.

## Running the live conformance test

Requires Docker, and a local checkout of `little-auth/keycloak-scim-client` (a private
repo -- if `git clone`/`gh repo clone` fails with a permissions error, you need read
access added to that repo before any of this works) to build the plugin jar host-side --
`Dockerfile.keycloak-scim` `COPY`s a pre-built jar rather than cloning inside the image,
since baking clone credentials into a Dockerfile risks leaking them into cached image
layers. The plugin also resolves its target credential through Keycloak's Vault SPI, so a
plaintext secret file has to exist before `docker compose up` (never committed -- see
`.gitignore`):

```sh
# 1. Build the plugin jar (JDK 17, matching keycloak-scim-client's own .tool-versions).
#    Checking out the same commit CI pins to (see .github/workflows/keycloak-conformance.yml)
#    keeps a local run reproducible with CI rather than floating on whatever main has
#    moved to since this harness was last verified against it.
cd path/to/keycloak-scim-client
git checkout 845386c
./mvnw clean package -DskipTests
cp target/keycloak-scim-client-*.jar path/to/scimforge/keycloak-it/docker/keycloak-scim-client.jar

# 2. Create the vault secret the credentialVaultRef in the test's component config
#    resolves through (REALM_UNDERSCORE_KEY convention: realm "scim-it" + key
#    "scim-target-token")
cd path/to/scimforge
mkdir -p keycloak-it/docker/vault
printf '%s' "scim-it-conformance-test-token" > keycloak-it/docker/vault/scim-it_scim-target-token

# 3. Bring up Keycloak with the plugin installed, then run the live test
cd keycloak-it/docker
docker compose up --build -d
cd ..
KEYCLOAK_BASE_URL=http://localhost:8090 \
  cargo test -p keycloak-it --test keycloak_conformance -- --ignored --nocapture
```

The test prints (`println!`, hence `--nocapture`) the exact `Content-Type` and body of
every SCIM request the example server captured, prefixed `issue #1 finding --`, so a run's
raw output is itself the evidence for whatever it found.

In CI, this runs as its own workflow (`.github/workflows/keycloak-conformance.yml`),
separate from the fast `cargo test` gate (`.github/workflows/ci.yml`) -- see that
workflow file's own comments for why the separation is deliberate.

## Findings from actually running it

A real Docker daemon was available while this harness was built, so this section is a
genuine live run -- `docker compose up --build -d` against a real Keycloak 25.0.6 image
with a host-built `keycloak-scim-client` jar, then the `#[ignore]`d test against it -- not
inferred from reading source. The full CREATE / UPDATE / deprovision (deactivate) lifecycle
passes end to end, confirmed both by this harness's own assertions and by
`ScimEventListenerProvider`'s own `SCIM sync: ... -> SUCCESS` log lines inside the
Keycloak container.

Getting to a clean pass took five real, live-only findings -- exactly what this harness
exists to surface:

- **Realm event listener id.** The realm's `eventsListeners` config needs
  `keycloak-scim-client` (`ScimEventListenerProviderFactory.ID`). Get this wrong and
  Keycloak logs `KC-SERVICES0083: Event listener '<id>' registered, but provider not
  found`, and zero SCIM traffic ever leaves Keycloak -- easy to miss because Keycloak
  accepts the realm-create call with the wrong id just fine, the failure only shows up
  later, silently, as a timeout on the other end.
- **This harness's own server was missing the SCIM media type.** `scim-it-server`'s
  responses never set `Content-Type: application/scim+json` (axum's `Json<T>` defaults to
  plain `application/json`). `scim-sdk-client` -- the SDK `keycloak-scim-client` is built
  on -- validates the response `Content-Type` strictly: a genuine `201 Created` create was
  logged by the plugin as a *failed* create purely because of this header, and the
  resulting missing `SCIM_SYNC_MAPPING` row cascaded into every later admin action
  silently self-healing into a repeated CREATE instead of a real update. Fixed here (a
  `set_scim_content_type` response middleware, test-first) -- this was a bug in
  `keycloak-it`, not in `keycloak-scim-client`.
- **A real limitation in `keycloak-scim-client` itself** (not fixed here, per this
  migration's scope -- filed upstream instead): `KeycloakUserMapper.toScimUser` maps
  whatever `AdminEvent#getRepresentation()` carries verbatim. For Keycloak's Admin REST
  API, that's the raw request body a caller sent for that specific call, not a
  server-merged full representation. A minimal `{"enabled": false}` PUT -- a legitimate,
  minimal Admin-API usage pattern -- produces an outbound SCIM request missing the
  RFC-7643-REQUIRED `userName`, which this (and any RFC-literal) SCIM server correctly
  rejects with `400 missing field userName`. `ScimEventListenerProvider`'s own module doc
  states "every update carries a complete representation" -- true for Keycloak's own
  Admin Console (which GETs, mutates, and PUTs back the full representation, the pattern
  this harness's live test now uses), but not guaranteed for every Admin-REST-API caller.
- **A real `scimforge` core-library bug, found live and fixed.** `scim-sdk-client`'s PATCH
  builder (`.valueNode(BooleanNode.valueOf(active))`) wraps even a single-valued boolean
  replace value in a JSON *array*: `{"path":"active","value":[false]}`, not a bare
  `false`. `apply_patch_with_schema`'s `coerce_to_attribute_type` only recognized
  `Value::String`, so that array passed through untouched, landed in the merged document
  as a literal one-element array, and broke the very next typed round-trip
  (`serde_json::from_value::<User>`) with `invalid type: sequence, expected a boolean` --
  this server actually **rejected** the plugin's PATCH with a `400`. The first live run
  that hit this looked like a pass: `ScimTargetClient.setActive()` treats a `4xx` PATCH
  response as "PATCH not supported," records that, and silently falls back to a
  fetch-then-PUT that *does* succeed (a native, fully-typed representation needs no
  coercion) -- so the resource ended up correctly deactivated for the wrong reason, and
  it took comparing this server's own capture log against `ScimEventListenerProvider`'s
  Keycloak-side logs to catch that the "successful" run was actually PATCH-rejected,
  PUT-recovered. Fixed in `src/patch.rs` (`coerce_to_attribute_type` now unwraps a
  one-element array against a declared non-multi-valued attribute before coercing, RFC
  7644 3.5.2's `value` only ever legitimately being an array for a multi-valued one) --
  re-verified live afterward with a new assertion that counts captured requests, proving
  the PATCH now succeeds on the first attempt with no fallback PUT following it.
- **A race in this harness's own test, not in `keycloak-scim-client`.** An earlier version
  of the deactivation-entry search matched by shape alone (any `PUT`/`PATCH` carrying
  `active: false`), which the prior UPDATE step's own captured request can also satisfy --
  a genuinely failed or missing delete-time dispatch was silently masked by re-matching
  that stale entry, and the test still went green. Caught by cross-checking the Keycloak
  container's own logs against the test's claims, not by the test failing on its own.
  Fixed by snapshotting the capture count before triggering delete and requiring a
  strictly later match.

## What this harness does *not* cover

- Filter-query evaluation over a collection (`GET /Users?filter=...`): out of scope for
  `scimforge` itself (see `src/filter.rs`'s module doc) and not exercised by the plugin's
  event-driven push path, which is what this harness targets.
- Group sync: `keycloak-scim-client`'s `main` branch has no group-sync feature at all
  (Slice 1 only handles `ResourceType.USER` admin events) -- `/Groups` routes exist so
  this server isn't a 404 against `scimforge`'s own group support, but nothing in the live
  conformance test drives them, and there's no plugin-side config key to point at them yet.
- `HARD_DELETE`: the live conformance test only exercises `keycloak-scim-target`'s default
  `deletePolicy` (`SOFT_DELETE`), which deprovisions via PATCH/PUT deactivation, not a
  literal `DELETE` verb. `HARD_DELETE` is a real, separate code path
  (`ScimTargetClient.deleteUser`) not currently driven by live traffic here -- tracked as
  a follow-up, not silently assumed equivalent.
- Bulk operations (RFC 7644 §3.7): the plugin doesn't use them.
