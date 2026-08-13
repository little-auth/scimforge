# keycloak-it

A disposable example SCIM 2.0 consumer plus a real-Keycloak conformance test harness for
`scimitar` (GitHub issue #1: "Real-IdP conformance testing"). **Not a reference
implementation** -- no persistence, no concurrency control beyond a single mutex, a
single shared bearer token for auth, minimal error handling. It exists to give real
Keycloak provisioning traffic somewhere to land, in front of `scimitar`'s own parsing and
PATCH-application code, so this repo's RFC-literal conformance claims can be checked
against what a real, currently-maintained SCIM client actually sends -- not just against
the spec text.

## Why this plugin, and not another one

The direction needed is Keycloak acting as a SCIM *client*, pushing provisioning events
to an external service provider -- the same role Okta and Azure AD play against a real
SCIM SP. That's the opposite direction from Keycloak's own newer native "SCIM Realm API"
(experimental as of Keycloak 26.6, per the Keycloak project's own blog), which makes
Keycloak itself a SCIM *server*.

Chosen: [**mitodl/keycloak-scim**](https://github.com/mitodl/keycloak-scim) (Apache-2.0).
Checked directly against its source rather than assumed:

- Architecture: an Event Listener (provider id `scim`) turns Keycloak user/group changes
  into outbound SCIM calls; a User Storage Provider component (also id `scim`) holds the
  per-realm config (`endpoint`, `content-type`, `auth-mode`, `auth-pass`,
  `propagation-user`/`propagation-group`) -- see
  `src/main/java/sh/libre/scim/storage/ScimStorageProviderFactory.java`.
- Built on `de.captaingoldfish:scim-sdk-common`/`scim-sdk-client` 1.25.1, a spec-driven
  SCIM SDK -- requests are RFC-shaped by construction, not hand-rolled per call site.
- `build.gradle` on `main` compiles against `org.keycloak:keycloak-*:25.0.6`
  (`compileOnly`), which is why this harness's Dockerfile pins
  `quay.io/keycloak/keycloak:25.0.6` rather than a newer release -- a newer Keycloak risks
  Provider SPI drift the plugin's own build hasn't caught up to yet.
- Maintenance: commits (Renovate dependency bumps, verified) through 2026-04-01, i.e.
  actively maintained within the last several months of this harness being built
  (2026-08-13).

## The one accommodation this research produced

`UserAdapter.toPatchBuilder()` (pinned commit
[`eec8ecd14971886f0d00f3dc688b587c3002f252`](https://github.com/mitodl/keycloak-scim/blob/eec8ecd14971886f0d00f3dc688b587c3002f252/src/main/java/sh/libre/scim/core/UserAdapter.java))
builds the PATCH op for `active` as:

```java
patchBuilder.addOperation()
    .path("active")
    .op(PatchOp.REPLACE)
    .value(active.toString())
```

Java's `Boolean#toString()` is the string `"true"`/`"false"`, and the SDK's
`.value(String)` overload puts that literally into the wire `value` field --
`{"op":"replace","path":"active","value":"true"}`. RFC 7643 §2.3 declares `active` as
`type: boolean`; a strict RFC-literal PATCH engine that just merges JSON values in
untyped would silently store the *string* `"true"`, not the boolean `true`, corrupting
the resource's type shape (a later `serde_json::from_value::<User>` on that resource
would then fail, even though the SCIM server itself accepted the request).

`scimitar::patch::apply_patch_with_schema` (src/patch.rs in the crate root, not this
directory) now coerces a PATCH `value` that's a JSON string into the target attribute's
declared `boolean`/`integer`/`decimal` type, but *only* for an exact canonical string
form of that type -- `"true"`/`"false"` exactly (not `"True"`, not `"TRUE"`), a clean
integer parse that round-trips (not `"007"`, not `" 42"`), a clean finite decimal parse
(not `"Infinity"`/`"NaN"`). Anything else passes through unchanged. This only applies to
`apply_patch_with_schema` (the schema is what supplies the declared type to coerce
toward); `apply_patch` has no schema and keeps storing whatever JSON type it's given.

This was found by reading the plugin's source, not by capturing live traffic -- there was
no Docker daemon available in the sandbox this harness was originally built in. The live
Keycloak run (below) is what actually confirms it, or would surface anything this
source-reading approach missed.

**Important note discovered along the way, not itself an accommodation**: the plugin's
`UserAdapter.toSCIM()` also sets a client-side `id` value on the outbound resource
representation. `scimitar::common::ResourceId`'s only *public constructor* is `new()`
(documented as being for server-generated values only), but its derived
`#[serde(transparent)]` `Deserialize` impl doesn't route through that constructor --
deserializing a request body with a client-supplied `id` will populate `User.id` anyway.
`keycloak-it/src/users.rs::create()` deliberately overwrites `user.id` with a
server-generated UUID *after* deserializing, discarding whatever the client sent, exactly
matching the CVE-2025-41115 lesson this crate's README already calls out. This is
correct, deliberate caller-side handling, not a gap in `scimitar` -- the crate can't
distinguish "deserializing an untrusted client request" from "deserializing your own
already-validated stored resource" from inside a generic `Deserialize` impl; that context
is inherently the caller's to supply.

## Running the live conformance test

Requires Docker.

```sh
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

## What this harness does *not* cover

- Filter-query evaluation over a collection (`GET /Users?filter=...`): out of scope for
  `scimitar` itself (see `src/filter.rs`'s module doc) and not exercised by the plugin's
  event-driven push path, which is what this harness targets. The plugin's optional
  periodic full-import sync does use it, but that path isn't wired up here.
- Group propagation (`propagation-group`): the routes exist (`/Groups`), but the live
  conformance test only drives `propagation-user`.
- Bulk operations (RFC 7644 §3.7): the plugin doesn't use them.
