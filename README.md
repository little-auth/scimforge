# scimforge

A SCIM 2.0 server-side protocol implementation for Rust: RFC 7643 (schema) and RFC 7644
(protocol), including the two pieces that are actually hard, the filter-expression
grammar and PATCH semantics. Storage-agnostic: this crate parses, validates, and
serializes. You bring the database.

## Why this exists

I went looking for a Rust SCIM library and found one, `scim-server`. It has no filter
parser at all: `filter=userName eq "bjensen"` just gets string-matched, not parsed
against RFC 7644 §3.4.2.2's actual grammar. And its PATCH path validator rejects the
exact bracket-notation path (`emails[type eq "work"]`) that its own test suite asserts
should work. Filed as: not a bug I want to inherit.

Those two pieces, the filter grammar and PATCH semantics, are the actual protocol. Get
them wrong and a directory sync either can't find the record it's looking for, or finds
the wrong one. So I'm building them properly, against the RFC text, not against how
other implementations are commonly described.

## What "properly" means here

Every claim in this crate traces back to an RFC section, not to memory of how SCIM
usually works. And because a SCIM endpoint is, by definition, something an external
identity provider calls with a bearer token, the tests aren't just "does it parse the
happy path." I went and read real SCIM CVEs before writing the schema types:

- **CVE-2025-41115** (Grafana, CVSS 10.0): a SCIM client provisions a user with a numeric
  `externalId`, the server maps it onto its own internal user ID, and now the attacker's
  new account *is* an existing admin account. Root cause: conflating a client-supplied,
  opaque identifier with a server-assigned one. RFC 7643 is explicit that `id` is
  server-issued and `externalId` is client-issued and the two must never be treated as
  interchangeable, this crate's types make that conflation a compile error, not a
  discipline problem.
- The **scim-patch prototype-pollution class**: PATCH paths resolved without checking
  them against the resource's actual schema let an attacker touch fields they shouldn't
  reach. Rust has no prototype chain, so the exact bug can't happen here, but the root
  cause (unvalidated path resolution) can. PATCH here enforces RFC 7643 attribute
  mutability and refuses to touch `id`, `meta.*`, or `schemas`, whether you got there
  through an explicit path or the no-path whole-object replace form.

The filter parser also has a hard-capped recursion depth. The grammar is mutually
recursive with no inherent bound (`valuePath` can contain a filter that contains another
`valuePath`), and since the input is attacker-controlled, an uncapped recursive-descent
parser is just a stack-overflow DoS with extra steps.

One more spec detail worth calling out because it's easy to get backwards: RFC 7643
§2.2 says `caseExact` defaults to **false**, meaning case-*insensitive* comparison is
the spec's stated default, not case-sensitive. Filter matching (`eq`, `co`, `sw`, `ew`)
folds case unless told otherwise -- I found and fixed a real bug in an early build where
this was backwards. Schema-driven PATCH (`apply_patch_with_schema`) goes a step further:
PATCH's bracket-filter matching (e.g. `emails[type eq "work"]`) now consults the matched
sub-attribute's actual `caseExact` from the schema instead of always folding -- if a
resource type ever defines a `caseExact: true` sub-attribute of a multi-valued attribute,
filtering on it compares literally. `apply_patch` (no schema) still always folds, since
it has no schema to consult.

`id`, `externalId`, `meta.resourceType`, and `meta.version` are real RFC 7643 §3.1
`caseExact: true` examples (and `profileUrl` per §4.1) -- but none of them can themselves
appear inside a PATCH bracket filter (they're resource-level attributes, never
sub-attributes of a multi-valued one). Where they *do* matter is a search/list filter
(`GET /Users?filter=externalId eq "701984"`, the way a provisioning connector checks
whether an account already exists before creating one) -- evaluating a filter against a
whole collection is a storage-layer concern this crate deliberately doesn't implement
(see the filter grammar module's own doc comment), so it can't run that query for you.
What it can do is answer the RFC question underneath it:
[`discovery::is_case_exact`](https://docs.rs/scimforge/latest/scimforge/discovery/fn.is_case_exact.html)
is `pub` for exactly this -- resolve `caseExact` for any attribute path, including the
common ones no per-resource schema declares, so a caller writing their own filter
evaluator doesn't have to re-derive RFC 7643's rules by hand. (The link above will 404
until this crate ships to crates.io -- see Status below -- but it's the right link once
it does, so it stays.)

## Quickstart

This is real, compiled-and-tested code (`cargo test --doc` runs it, since this README is
also the crate's rustdoc front page). It's not the whole API -- see the module docs
(`cargo doc --open`) for bulk operations, discovery resources, and the rest.

```rust
use scimforge::discovery::is_case_exact;
use scimforge::filter;
use scimforge::patch::{apply_patch, PatchOp, PatchOperation};
use scimforge::user::{User, USER_SCHEMA_URI};
use serde_json::json;

// Parse an incoming SCIM User creation request the way a real IdP actually sends one --
// deserialized straight off the wire, not hand-built.
let user: User = serde_json::from_value(json!({
    "schemas": [USER_SCHEMA_URI],
    "userName": "bjensen@example.com",
    "name": {"givenName": "Barbara", "familyName": "Jensen"},
    "emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}],
    "active": true
}))
.unwrap();
assert_eq!(user.user_name, "bjensen@example.com");

// Parse a search filter against RFC 7644 §3.4.2.2's actual grammar, not a string match
// against the raw query parameter (see "Why this exists" above for what that costs you).
let parsed = filter::parse(r#"userName eq "bjensen@example.com" and active eq true"#).unwrap();
assert!(matches!(parsed, filter::Filter::And(_, _)));

// Apply a PATCH request (RFC 7644 §3.5.2) to the resource's own JSON representation.
let resource = serde_json::to_value(&user).unwrap();
let patched = apply_patch(
    &resource,
    &[PatchOperation {
        op: PatchOp::Replace,
        path: Some(r#"emails[type eq "work"].value"#.to_string()),
        value: Some(json!("bjensen+updated@example.com")),
    }],
)
.unwrap();
assert_eq!(patched["emails"][0]["value"], "bjensen+updated@example.com");

// id/externalId/meta.resourceType/meta.version are caseExact per RFC 7643 §3.1, even
// though no per-resource schema declares them -- is_case_exact resolves that for you.
assert!(is_case_exact(None, None, "externalId", None));
```

`apply_patch` only enforces the universal protections (`id`, `meta.*`, `schemas` are
never touchable). Pass a resource's schema to `apply_patch_with_schema` for full
per-attribute mutability -- `readOnly` attributes rejected outright, `immutable`
attributes only addable when they have no existing value yet -- using the exact same
`SchemaResource` that answers `/Schemas`, so the two can't drift out of sync with each
other:

```rust
use scimforge::patch::{apply_patch_with_schema, PatchError, PatchOp, PatchOperation};
use scimforge::user::user_schema;
use serde_json::json;

let schema = user_schema();
assert_eq!(
    serde_json::to_value(&schema).unwrap()["id"],
    "urn:ietf:params:scim:schemas:core:2.0:User"
);

// User.groups is readOnly (RFC 7643 §4.1.5): a client can't grant itself group
// membership through PATCH, only through the Group resource's own `members`.
// apply_patch (no schema) can't catch this; apply_patch_with_schema does.
let resource = json!({
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "bjensen"
});
let err = apply_patch_with_schema(
    &resource,
    &[PatchOperation {
        op: PatchOp::Replace,
        path: Some("groups".to_string()),
        value: Some(json!([{"value": "g-1", "display": "Admins"}])),
    }],
    &schema,
)
.unwrap_err();
assert_eq!(err, PatchError::ImmutableOrReadOnly("groups".to_string()));
```

Two longer, narrated walkthroughs live in `examples/`: `apply_patch.rs` (a full PATCH
request with both an accepted and a schema-rejected operation, turned into the RFC 7644
§3.12 Error response shape) and `filter_and_mutability.rs` (parsing a filter, resolving
`caseExact`, and the immutable-attribute add-if-absent exception on a Group). Run either
with `cargo run --example apply_patch`.

## What's here

RFC 7643's Core Schema (User, Group, the Enterprise User extension), RFC 7644's filter
grammar (§3.4.2.2), full PATCH semantics including schema-driven mutability enforcement
(§3.5.2), bulk operations with `bulkId` cross-referencing and dependency ordering
(§3.7), discovery resources (ServiceProviderConfig/ResourceType/Schema, §5-7),
ListResponse and pagination (§3.4.2), and the Error response shape with all ten
canonical `scimType` keywords (§3.12, Table 9). 117 tests.

## Status

Early. Not audited, not yet published to crates.io, and I'd tell you that even if it
hurt adoption, because it's true and you should know it before you trust it with a
production directory sync.

Real-IdP conformance testing (issue #1) now has a live consumer: `keycloak-it/` is a
disposable example SCIM server built on this crate's own types, exercised in CI against a
real Keycloak instance running [little-auth/keycloak-scim-client](https://github.com/little-auth/keycloak-scim-client)
(the in-house Keycloak SCIM client plugin -- Keycloak pushing provisioning events out, the
same direction Okta/Azure AD operate in; targets that plugin's `main` branch only, Slice 1
functionality). `apply_patch_with_schema` accommodates two real-world PATCH `value`
shapes (the schema is what supplies a declared type/cardinality to coerce toward --
`apply_patch` has none of this and stores whatever JSON shape it's given), neither
guessing beyond an exact, evidenced shape: a `value` that's an exact canonical string
form of a `boolean`/`integer`/`decimal` attribute's declared type (e.g. `"true"`, not
`"True"`) coerces to that native JSON type -- a defensive, generically-motivated
accommodation, not one this specific live traffic evidenced. A `value` arriving as a
one-element JSON array against a declared non-multi-valued attribute unwraps before that
same coercion runs -- this one *is* exactly what the live traffic proved: the real SCIM
SDK `little-auth/keycloak-scim-client` is built on wraps even a single-valued replace
value this way (see `keycloak-it/`'s README for the live-run details, and
`src/patch.rs`'s `coerce_to_attribute_type` doc comment for the full detail).

## License

Copyright (c) 2026 Mario Đanić

Licensed under either of
[Apache License, Version 2.0](https://github.com/little-auth/scimforge/blob/main/LICENSE-APACHE)
or [MIT license](https://github.com/little-auth/scimforge/blob/main/LICENSE-MIT) at your option.
