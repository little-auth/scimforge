//! Minimal walkthrough: apply an RFC 7644 §3.5.2 PATCH request to a User resource with
//! schema-driven mutability enforcement, then turn a rejected operation into the RFC
//! 7644 §3.12 Error response shape a real SCIM endpoint would send back over the wire.
//!
//! Run with `cargo run --example apply_patch`.

use little_auth_scim::error::ScimError;
use little_auth_scim::patch::{PatchOp, PatchOperation, apply_patch_with_schema};
use little_auth_scim::user::user_schema;
use serde_json::json;

fn main() {
    let resource = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": "2819c223-7f76-453a-919d-413861904646",
        "userName": "bjensen@example.com",
        "active": true,
        "emails": [
            {"value": "bjensen@example.com", "type": "work", "primary": true}
        ]
    });
    let schema = user_schema();

    // A legitimate request: deactivate the account and update the work email, in one
    // atomic PATCH -- RFC 7644 §3.5.2: "regardless of the number of operations... SHALL
    // be treated as atomic."
    let ops = [
        PatchOperation {
            op: PatchOp::Replace,
            path: Some("active".to_string()),
            value: Some(json!(false)),
        },
        PatchOperation {
            op: PatchOp::Replace,
            path: Some(r#"emails[type eq "work"].value"#.to_string()),
            value: Some(json!("bjensen+deactivated@example.com")),
        },
    ];
    let patched = apply_patch_with_schema(&resource, &ops, &schema).expect("both ops are valid");
    println!(
        "patched resource:\n{}\n",
        serde_json::to_string_pretty(&patched).unwrap()
    );

    // An illegitimate request: User.groups is readOnly (RFC 7643 §4.1.5) -- a client
    // can't grant itself group membership through PATCH, only through the Group
    // resource's own `members`. apply_patch_with_schema catches this; the plain
    // apply_patch (no schema) would not have.
    let bad_op = PatchOperation {
        op: PatchOp::Add,
        path: Some("groups".to_string()),
        value: Some(json!([{"value": "admins", "display": "Admins"}])),
    };
    match apply_patch_with_schema(&resource, &[bad_op], &schema) {
        Ok(_) => unreachable!("groups is readOnly, this must be rejected"),
        Err(err) => {
            // This is the shape a real endpoint sends back: RFC 7644 §3.12's Error
            // message, with the canonical scimType keyword for exactly this failure.
            let scim_error = ScimError::new(
                err.http_status(),
                Some(err.scim_type()),
                format!("PATCH rejected: {err:?}"),
            );
            println!(
                "rejected as expected:\n{}",
                serde_json::to_string_pretty(&scim_error).unwrap()
            );
        }
    }
}
