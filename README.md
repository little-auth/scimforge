# scimitar

SCIM 2.0 (RFC 7643, RFC 7644) server-side protocol implementation for Rust.

Storage-agnostic: this crate owns the schema types, the RFC 7644 §3.4.2.2 filter
grammar, and RFC 7644 §3.5.2 PATCH semantics; you provide resource storage.

## Status

Early development. Not yet published to crates.io.

## Why this exists

The Rust SCIM ecosystem is thin. The one existing crate at the time this project
started (`scim-server`) had no filter-expression parser (RFC 7644 §3.4.2.2 --
`eq`/`co`/`sw`/`ew`/`pr`/`gt`/`ge`/`lt`/`le`/`and`/`or`/`not`, complex attribute
filters) and a PATCH-path validator that contradicted its own test suite on
bracket-notation paths (`emails[type eq "work"]`). scimitar exists to be a
correct, adversarially-tested implementation of those two hard pieces plus the
rest of the protocol, built against the RFCs directly.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
