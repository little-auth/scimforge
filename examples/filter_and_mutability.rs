//! Minimal walkthrough: parse an RFC 7644 §3.4.2.2 filter, resolve RFC 7643 `caseExact`
//! for an attribute via `discovery::is_case_exact`, and see the RFC 7644 §3.5.2
//! immutable-attribute "add if absent" exception apply differently to two entries of the
//! same multi-valued attribute.
//!
//! Run with `cargo run --example filter_and_mutability`.

use scimforge::discovery::is_case_exact;
use scimforge::filter::{self, Filter};
use scimforge::group::group_schema;
use scimforge::patch::{PatchOp, PatchOperation, apply_patch_with_schema};
use serde_json::json;

fn main() {
    // A filter a provisioning connector might send to check whether an account already
    // exists before creating one (RFC 7644 §3.4.2.2's grammar; see the crate README's
    // discussion of why externalId matters here).
    let parsed = filter::parse(r#"externalId eq "701984""#).expect("valid filter syntax");
    let Filter::Compare(path, _, _) = &parsed else {
        unreachable!("this filter is a simple Compare");
    };
    println!(
        "parsed filter on '{}', caseExact = {}",
        path.attr_name,
        is_case_exact(None, None, &path.attr_name, path.sub_attr.as_deref())
    );

    // A PATCH path with a bracket filter parses through the same grammar, via
    // parse_patch_path instead of parse.
    let path = filter::parse_patch_path(r#"members[value eq "u-2"].display"#).unwrap();
    println!(
        "PATCH path targets attribute: '{}'",
        path.attr_path.attr_name
    );

    // Group.members[].display is immutable (RFC 7643 §4.2): settable once, then locked.
    // RFC 7644 §3.5.2's add-exception lets an `add` through only when that specific
    // matched entry has no existing value yet -- not just "the array has room somewhere."
    let group = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": "g-1",
        "displayName": "Admins",
        "members": [
            {"value": "u-1", "type": "User", "display": "Alice"},
            {"value": "u-2", "type": "User"}
        ]
    });
    let schema = group_schema();

    // u-2 has no display yet: this add is allowed.
    let allowed = apply_patch_with_schema(
        &group,
        &[PatchOperation {
            op: PatchOp::Add,
            path: Some(r#"members[value eq "u-2"].display"#.to_string()),
            value: Some(json!("Bob")),
        }],
        &schema,
    );
    println!("add on the absent entry succeeds: {}", allowed.is_ok());

    // u-1 already has display "Alice": the identical operation type (Add) on a
    // different, already-set entry is rejected.
    let rejected = apply_patch_with_schema(
        &group,
        &[PatchOperation {
            op: PatchOp::Add,
            path: Some(r#"members[value eq "u-1"].display"#.to_string()),
            value: Some(json!("Alicia")),
        }],
        &schema,
    );
    println!(
        "add on the already-set entry succeeds: {}",
        rejected.is_ok()
    );
}
