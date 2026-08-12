# scimitar

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

## Status

Early. Not audited, not yet published to crates.io, and I'd tell you that even if it
hurt adoption, because it's true and you should know it before you trust it with a
production directory sync. What exists so far is real and well-tested: the filter
grammar (25 tests, including the depth-cap fixtures). The rest, schema types, PATCH
engine, discovery resources, is in progress. Check the commit history, not this README,
for the current honest state.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
