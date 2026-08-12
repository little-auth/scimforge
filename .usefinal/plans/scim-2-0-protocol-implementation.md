# Implementation: SCIM 2.0 server-side protocol library (scimitar)
**Scope:** Complete, adversarially-tested SCIM 2.0 server-side protocol library
(RFC 7643 Core Schema, RFC 7644 Protocol), storage-agnostic via a trait extension
point, no I/O in the crate itself. Built because the one prior Rust option
(`scim-server`) has no RFC 7644 §3.4.2.2 filter grammar and a PATCH-path validator
that contradicts its own test suite on bracket-notation paths. Standalone public
repo (github.com/mario/scimitar), potentially publishable to crates.io.
**Linked slice:** none
**Started:** 2026-08-12T10:32:41Z
**Status:** in-progress
**Iteration:** 0
**Consecutive clean:** 0

## Pre-mortem risks

- **High -- unbounded filter-parser recursion (DoS).** A deeply nested/parenthesized
  filter expression (`((((...))))`) could stack-overflow the parser -- reachable by any
  IdP that can send a filter query, i.e. attacker-reachable by definition since SCIM
  endpoints are called by external identity providers. `addressed`: explicit, tested,
  const-capped recursion depth in the filter parser; a fixture at exactly max-depth-plus-1
  must be a clean parse error, never a crash.
- **High -- ambiguous PATCH path resolution silently doing the wrong thing.** RFC 7644
  §3.5.2's `remove` with no filter on a multi-valued attribute must have one unambiguous
  meaning (remove all values), and any path this crate can't resolve unambiguously must be
  a hard parse/validation error, never a best-guess. `addressed`: PATCH path resolution
  returns a typed error for anything ambiguous rather than guessing; RFC-literal semantics
  for the unfiltered-multi-valued-remove case, tested explicitly.
- **Medium -- injection through filter attribute values reaching a caller's storage
  layer untyped.** Since this crate has no I/O, a caller who naively string-interpolates
  a parsed filter value into a query string would reintroduce injection risk one layer up.
  `addressed`: the parsed filter AST exposes typed, structured values (never a
  pre-assembled query-string fragment), and this is called out explicitly in the crate's
  top-level documentation as the caller's responsibility to bind as parameters, not
  string-concatenate.
- **Medium -- real IdP behavior diverging from strict RFC text (Okta/Azure AD
  quirks).** A strictly-conformant parser could reject requests real IdPs actually send.
  `accepted` for the initial build -- can't fabricate specific IdP quirks without an actual
  conformance run against real IdP traffic (out of scope for a from-scratch library with
  no live IdP to test against yet); tracked as a Follow-up to revisit once little-saas
  wires this against a real Okta/Azure AD test tenant.
- **Low -- Unicode/case-sensitivity mismatches per attribute.** RFC 7643 defines explicit
  per-attribute case-sensitivity (e.g. `userName` is case-insensitive per the spec's own
  schema definitions). `addressed`: case-sensitivity is a property carried on each schema
  attribute definition, not a single global assumption, and tested per-attribute.

## Progress log

## Discoveries and plan changes

## Known-vulnerability-informed adversarial test requirements

Per explicit user request ("a beast of tests, especially against known vulnerabilities in
SCIM servers"), researched real documented SCIM CVEs rather than guessing at threat
classes. Two are directly relevant to a protocol library (not just a specific server's
implementation bug) and become hard test requirements, not optional hardening:

- **CVE-2025-41115 (Grafana, CVSS 10.0, Nov 2025)**: a SCIM client provisions a user with
  a numeric `externalId` that the server incorrectly maps onto its own internal user ID,
  letting an attacker impersonate an existing account (including admin) with no prior
  authentication -- root cause is conflating the client-supplied, opaque `externalId`
  with the server-assigned internal `id`. Test requirement: `externalId` and `id` must be
  structurally distinct in this crate's types (never coercible into each other), and an
  adversarial test must prove that a resource whose `externalId` equals another existing
  resource's real `id` is never treated as an alias for it by any function this crate
  exposes.
- **scim-patch prototype pollution class** (JS-specific CVE, but the lesson generalizes
  to any language): PATCH paths resolved without validating against the resource's
  declared schema let an attacker target internal/protected fields. Rust has no prototype
  chain, so this can't manifest as literal prototype pollution, but the same root cause
  (unvalidated path resolution) can still let a PATCH silently touch server-controlled
  attributes. Test requirement: PATCH must enforce RFC 7643 attribute mutability
  (`readOnly`/`immutable`) and reject -- not silently ignore or silently apply -- any
  operation targeting `id`, `meta.*`, or `schemas`, whether reached via an explicit path
  or the no-path whole-object replace form (RFC 7644 §3.5.2.1).

## Follow-ups

- Real-IdP-conformance pass (Okta, Azure AD/Entra ID quirks vs. strict RFC 7644 text) --
  accepted as out of scope for the initial build since there's no live IdP to test
  against yet from a standalone library with no deployed caller; revisit once little-saas
  (or another consumer) wires this against a real test tenant.

## Progress log (continued)

- **055e701**: RFC 7644 §3.4.2.2 filter-expression grammar (`src/filter.rs`). Hand-written
  tokenizer + recursive-descent parser, no parser-combinator dependency (matches the
  crate's lean/auditable-dependency-tree design goal). Caught two real bugs via its own
  test suite before commit: (1) precedence was initially flat left-to-right chaining, not
  actual "not > and > or" per the spec text -- fixed with a proper precedence-climbing
  grammar (or-of-ands-of-unary-terms); (2) schema URN version segments like "2.0" in
  `urn:ietf:params:scim:schemas:core:2.0:User` tokenized as a Number, not an Ident,
  breaking schema-URI-prefixed attribute paths -- fixed by accepting either token kind
  for URI segments. 25 tests, including the pre-mortem's addressed high-risk item: a
  MAX_DEPTH=32 cap on both the paren/logExp recursion path and the value-path bracket
  path, proven via a programmatically-generated MAX_DEPTH+1 fixture.

## Council iterations

## Final summary
