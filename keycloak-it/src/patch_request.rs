//! Parses RFC 7644 §3.5.2's PATCH request envelope
//! (`{"schemas": [...], "Operations": [...]}`) into [`scimforge::patch::PatchOperation`]s.
//! scimforge itself deliberately doesn't own this: `PatchOperation` isn't `Deserialize`
//! (see `src/patch.rs`'s module doc -- the crate does no I/O and expects a caller to
//! parse its own request envelope), so any real SCIM server built on it needs exactly
//! this. This is where a real IdP's exact `op` casing matters -- checked against
//! `de.captaingoldfish:scim-sdk-common`'s `PatchOp` enum (the SCIM SDK the Keycloak
//! plugin under test is built on): it serializes lowercase (`"add"`/`"replace"`/
//! `"remove"`) matching RFC 7644's own examples exactly, but its own parser
//! (`PatchOp.getByValue`) compares case-insensitively on the way in. Matching that
//! same "produce strict, accept loose" asymmetry here rather than assuming every real
//! sender's `op` casing matches the RFC's examples byte-for-byte.

use scimforge::patch::{PatchOp, PatchOperation};
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum PatchRequestError {
    MissingOperations,
    OperationsNotAnArray,
    MissingOp,
    UnknownOp(String),
}

pub fn parse_patch_operations(body: &Value) -> Result<Vec<PatchOperation>, PatchRequestError> {
    let operations = body
        .get("Operations")
        .ok_or(PatchRequestError::MissingOperations)?;
    let operations = operations
        .as_array()
        .ok_or(PatchRequestError::OperationsNotAnArray)?;
    operations.iter().map(parse_one).collect()
}

fn parse_one(raw: &Value) -> Result<PatchOperation, PatchRequestError> {
    let op_str = raw
        .get("op")
        .and_then(Value::as_str)
        .ok_or(PatchRequestError::MissingOp)?;
    let op = match op_str.to_ascii_lowercase().as_str() {
        "add" => PatchOp::Add,
        "remove" => PatchOp::Remove,
        "replace" => PatchOp::Replace,
        other => return Err(PatchRequestError::UnknownOp(other.to_string())),
    };
    let path = raw
        .get("path")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let value = raw.get("value").cloned();
    Ok(PatchOperation { op, path, value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_the_rfc_7644_worked_example_verbatim() {
        // RFC 7644 3.5.2's own example: add a member to a Group.
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "add",
                "path": "members",
                "value": [{"display": "Babs Jensen", "value": "2819c223-7f76-453a-919d-413861904646"}]
            }]
        });
        let ops = parse_patch_operations(&body).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, PatchOp::Add);
        assert_eq!(ops[0].path.as_deref(), Some("members"));
    }

    #[test]
    fn parses_the_exact_keycloak_plugin_shaped_active_replace_op() {
        // mitodl/keycloak-scim's UserAdapter.toPatchBuilder() shape -- value is the JSON
        // *string* "true", not a native boolean (see src/patch.rs's coercion doc comment
        // for the core-library side of this).
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "active", "value": "true"},
                {"op": "replace", "path": "userName", "value": "bjensen"},
                {"op": "replace", "path": "displayName", "value": "Babs Jensen"}
            ]
        });
        let ops = parse_patch_operations(&body).unwrap();
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].value, Some(json!("true")));
    }

    #[test]
    fn op_matching_is_case_insensitive_since_the_sdk_the_plugin_is_built_on_parses_that_way() {
        let body = json!({
            "Operations": [{"op": "REPLACE", "path": "active", "value": "true"}]
        });
        let ops = parse_patch_operations(&body).unwrap();
        assert_eq!(ops[0].op, PatchOp::Replace);
    }

    #[test]
    fn missing_operations_array_is_a_typed_error_not_a_panic() {
        let body = json!({"schemas": []});
        assert_eq!(
            parse_patch_operations(&body).unwrap_err(),
            PatchRequestError::MissingOperations
        );
    }

    #[test]
    fn an_unknown_op_value_is_a_typed_error_not_a_silent_skip() {
        let body = json!({"Operations": [{"op": "frobnicate", "path": "active"}]});
        assert_eq!(
            parse_patch_operations(&body).unwrap_err(),
            PatchRequestError::UnknownOp("frobnicate".to_string())
        );
    }
}
