//! RFC 7644 §3.7 Bulk Operations. Like [`crate::patch`], this crate has no I/O: a caller
//! executes each operation against its own storage in the order [`order_operations`]
//! returns, reporting each POST's assigned id back to a [`BulkIdResolver`] as it goes, so
//! later operations' `"bulkId:xxx"` references substitute to real ids before the caller
//! executes them.
//!
//! One real spec inconsistency worth documenting rather than silently picking a side of:
//! RFC 7644's own worked examples in §3.7.2 and §3.7.3 disagree with each other on the
//! response `status` field's shape -- one example renders `"status": { "code": "201" }`,
//! several others render `"status": "201"` (a bare string). The *prose* (not an example)
//! is unambiguous: "The status attribute MUST include the code attribute that holds the
//! HTTP response code" (§3.7.3). [`BulkStatus`] follows the prose for what this crate
//! serializes (the object form), and deserializes either shape leniently, since a real
//! IdP client parsing a bulk response might have been built against either example.

use std::collections::{HashMap, HashSet};

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const BULK_REQUEST_SCHEMA_URI: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
pub const BULK_RESPONSE_SCHEMA_URI: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkMethod {
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "DELETE")]
    Delete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkOperationRequest {
    pub method: BulkMethod,
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "failOnErrors", skip_serializing_if = "Option::is_none")]
    pub fail_on_errors: Option<u32>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationRequest>,
}

/// See the module doc: this crate always *serializes* the object form (`{"code": ...}`,
/// matching RFC 7644 §3.7.3's normative prose) but *deserializes* either that or a bare
/// string, since real clients/servers in the wild follow either of the RFC's own two
/// conflicting example shapes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BulkStatus {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl<'de> Deserialize<'de> for BulkStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(code) => Ok(BulkStatus {
                code,
                description: None,
            }),
            Value::Object(mut obj) => {
                let code = obj
                    .remove("code")
                    .and_then(|v| v.as_str().map(str::to_string))
                    .ok_or_else(|| DeError::custom("bulk status object missing 'code'"))?;
                let description = obj
                    .remove("description")
                    .and_then(|v| v.as_str().map(str::to_string));
                Ok(BulkStatus { code, description })
            }
            other => Err(DeError::custom(format!(
                "expected a status string or object, got {other:?}"
            ))),
        }
    }
}

impl BulkStatus {
    pub fn code(code: impl Into<String>) -> Self {
        BulkStatus {
            code: code.into(),
            description: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkOperationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub method: BulkMethod,
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub status: BulkStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResponse>,
}

impl BulkResponse {
    pub fn new(operations: Vec<BulkOperationResponse>) -> Self {
        BulkResponse {
            schemas: vec![BULK_RESPONSE_SCHEMA_URI.to_string()],
            operations,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum BulkError {
    /// RFC 7644 §3.7.2: `bulkId` "REQUIRED when 'method' is 'POST'".
    MissingBulkIdOnPost(usize),
    /// Two operations in the same request declared the same `bulkId` -- the spec
    /// requires it be "unique within a bulk request."
    DuplicateBulkId(String),
    /// A `"bulkId:xxx"` reference where `xxx` never appears as any operation's own
    /// `bulkId` in this request.
    UnresolvedBulkId(String),
    /// RFC 7644 §3.7.1: "the service provider... MAY stop after a failed attempt and
    /// instead return HTTP status code 409 (Conflict)." This implementation takes that
    /// option rather than attempting the two-phase create-then-patch resolution a true
    /// circular reference would require -- a deliberate, spec-permitted scope boundary.
    CircularReference,
    /// RFC 7644 §3.7.4: either `maxOperations` or `maxPayloadSize` was exceeded. Maps to
    /// HTTP 413 per the spec ("the service provider MUST return HTTP response code 413").
    TooLarge(String),
}

/// Validates §3.7.4's limits. `payload_size_bytes` is the caller's own measurement of
/// the raw request body (this crate never sees raw bytes, only the parsed structure).
pub fn check_limits(
    request: &BulkRequest,
    max_operations: u32,
    max_payload_size_bytes: u64,
    payload_size_bytes: u64,
) -> Result<(), BulkError> {
    if request.operations.len() as u64 > max_operations as u64 {
        return Err(BulkError::TooLarge(format!(
            "request has {} operations, exceeding the maximum of {max_operations}",
            request.operations.len()
        )));
    }
    if payload_size_bytes > max_payload_size_bytes {
        return Err(BulkError::TooLarge(format!(
            "request payload is {payload_size_bytes} bytes, exceeding the maximum of {max_payload_size_bytes}"
        )));
    }
    Ok(())
}

const BULK_ID_PREFIX: &str = "bulkId:";

/// Every `bulkId:xxx` reference reachable in `data`, found by walking the whole JSON
/// tree -- RFC 7644 §3.7.2's own example uses this inside `members[].value`, and §3.7.2's
/// closing paragraph explicitly generalizes it to extension attributes too ("Extensions
/// that include references to other resources MUST be handled in the same way"), so this
/// walks every string value rather than special-casing known field names.
fn find_bulk_id_refs(data: &Value, out: &mut HashSet<String>) {
    match data {
        Value::String(s) => {
            if let Some(id) = s.strip_prefix(BULK_ID_PREFIX) {
                out.insert(id.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                find_bulk_id_refs(item, out);
            }
        }
        Value::Object(obj) => {
            for v in obj.values() {
                find_bulk_id_refs(v, out);
            }
        }
        _ => {}
    }
}

/// Returns indices into `operations` in dependency order: an operation referencing
/// another operation's `bulkId` always comes after the operation that defines it.
/// Operations with no dependency relationship keep their original relative order
/// (stable topological sort) -- RFC 7644 §3.7's "MAY elect to optimize the sequence...
/// MUST ensure the client's intent is preserved" licenses reordering but not scrambling
/// unrelated operations for no reason.
pub fn order_operations(operations: &[BulkOperationRequest]) -> Result<Vec<usize>, BulkError> {
    let mut bulk_id_to_index: HashMap<&str, usize> = HashMap::new();
    for (i, op) in operations.iter().enumerate() {
        if op.method == BulkMethod::Post {
            let Some(bulk_id) = &op.bulk_id else {
                return Err(BulkError::MissingBulkIdOnPost(i));
            };
            if bulk_id_to_index.insert(bulk_id, i).is_some() {
                return Err(BulkError::DuplicateBulkId(bulk_id.clone()));
            }
        }
    }

    let mut deps: Vec<HashSet<usize>> = Vec::with_capacity(operations.len());
    for op in operations {
        let mut refs = HashSet::new();
        if let Some(data) = &op.data {
            find_bulk_id_refs(data, &mut refs);
        }
        let mut dep_indices = HashSet::new();
        for r in &refs {
            match bulk_id_to_index.get(r.as_str()) {
                Some(&idx) => {
                    dep_indices.insert(idx);
                }
                None => return Err(BulkError::UnresolvedBulkId(r.clone())),
            }
        }
        deps.push(dep_indices);
    }

    // Kahn's algorithm, seeded in original-index order so independent operations keep
    // their submitted relative order (stable).
    let n = operations.len();
    let mut in_degree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, dep_set) in deps.iter().enumerate() {
        // Self-reference (an operation whose own data references its own bulkId) can't
        // happen structurally -- a POST's data can't yet know its own not-yet-assigned
        // id -- so no special-casing needed here.
        for &dep in dep_set {
            dependents[dep].push(i);
            in_degree[i] += 1;
        }
    }

    let mut ready: Vec<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(pos) = ready
        .iter()
        .enumerate()
        .min_by_key(|&(_, &idx)| idx)
        .map(|(pos, _)| pos)
    {
        let i = ready.remove(pos);
        order.push(i);
        for &dependent in &dependents[i] {
            in_degree[dependent] -= 1;
            if in_degree[dependent] == 0 {
                ready.push(dependent);
            }
        }
    }

    if order.len() != n {
        return Err(BulkError::CircularReference);
    }
    Ok(order)
}

/// Tracks `bulkId -> real id` as a caller executes operations in [`order_operations`]'s
/// returned sequence, and substitutes `"bulkId:xxx"` references in an operation's `data`
/// once the id they point to is known.
#[derive(Debug, Clone, Default)]
pub struct BulkIdResolver {
    known: HashMap<String, String>,
}

impl BulkIdResolver {
    pub fn new() -> Self {
        BulkIdResolver::default()
    }

    /// Call after successfully executing the POST operation that declared `bulk_id`,
    /// passing the real id the caller's storage assigned.
    pub fn record(&mut self, bulk_id: impl Into<String>, real_id: impl Into<String>) {
        self.known.insert(bulk_id.into(), real_id.into());
    }

    /// Substitutes every `"bulkId:xxx"` string anywhere in `data`. Errors if any
    /// reference isn't yet known -- which, if the caller executes operations in
    /// [`order_operations`]'s order and calls [`Self::record`] after each POST, can only
    /// happen for a genuinely unresolved reference, not an ordering mistake.
    pub fn substitute(&self, data: &Value) -> Result<Value, BulkError> {
        match data {
            Value::String(s) => match s.strip_prefix(BULK_ID_PREFIX) {
                Some(id) => match self.known.get(id) {
                    Some(real) => Ok(Value::String(real.clone())),
                    None => Err(BulkError::UnresolvedBulkId(id.to_string())),
                },
                None => Ok(data.clone()),
            },
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.substitute(item)?);
                }
                Ok(Value::Array(out))
            }
            Value::Object(obj) => {
                let mut out = serde_json::Map::with_capacity(obj.len());
                for (k, v) in obj {
                    out.insert(k.clone(), self.substitute(v)?);
                }
                Ok(Value::Object(out))
            }
            other => Ok(other.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn post(bulk_id: &str, path: &str, data: Value) -> BulkOperationRequest {
        BulkOperationRequest {
            method: BulkMethod::Post,
            bulk_id: Some(bulk_id.to_string()),
            version: None,
            path: path.to_string(),
            data: Some(data),
        }
    }

    /// Round-trips RFC 7644 §3.7.2's own worked example verbatim.
    #[test]
    fn deserializes_the_alice_and_tour_guides_example_verbatim() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "bulkId": "qwerty",
                    "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": "Alice"
                    }
                },
                {
                    "method": "POST",
                    "path": "/Groups",
                    "bulkId": "ytrewq",
                    "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                        "displayName": "Tour Guides",
                        "members": [
                            {"type": "User", "value": "bulkId:qwerty"}
                        ]
                    }
                }
            ]
        }"#;
        let req: BulkRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operations.len(), 2);
        assert_eq!(req.operations[1].bulk_id.as_deref(), Some("ytrewq"));
    }

    #[test]
    fn bulk_status_deserializes_both_rfc_example_shapes() {
        let object_form: BulkStatus = serde_json::from_str(r#"{"code": "201"}"#).unwrap();
        assert_eq!(object_form.code, "201");

        let bare_string_form: BulkStatus = serde_json::from_str(r#""201""#).unwrap();
        assert_eq!(bare_string_form.code, "201");
    }

    #[test]
    fn bulk_status_always_serializes_the_object_form() {
        let status = BulkStatus::code("201");
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json, serde_json::json!({"code": "201"}));
    }

    #[test]
    fn order_operations_puts_the_referenced_user_before_the_referencing_group() {
        let ops = vec![
            post(
                "ytrewq",
                "/Groups",
                json!({"members": [{"value": "bulkId:qwerty"}]}),
            ),
            post("qwerty", "/Users", json!({"userName": "Alice"})),
        ];
        let order = order_operations(&ops).unwrap();
        // "qwerty" (index 1) must come before "ytrewq" (index 0) despite the client
        // submitting them in the opposite order.
        let pos_of = |target_idx: usize| order.iter().position(|&i| i == target_idx).unwrap();
        assert!(pos_of(1) < pos_of(0));
    }

    #[test]
    fn order_operations_preserves_relative_order_of_independent_operations() {
        let ops = vec![
            post("a", "/Users", json!({"userName": "a"})),
            post("b", "/Users", json!({"userName": "b"})),
            post("c", "/Users", json!({"userName": "c"})),
        ];
        assert_eq!(order_operations(&ops).unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn order_operations_finds_a_reference_in_an_extension_attribute_not_just_members() {
        // RFC 7644 §3.7.2's closing paragraph: "Extensions that include references to
        // other resources MUST be handled in the same way" (its own example uses the
        // enterprise extension's manager.value) -- generic tree-walking, not a
        // members[]-specific special case, is what makes this pass.
        let ops = vec![
            post(
                "ytrewq",
                "/Users",
                json!({
                    "userName": "Bob",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "manager": {"value": "bulkId:qwerty"}
                    }
                }),
            ),
            post("qwerty", "/Users", json!({"userName": "Alice"})),
        ];
        let order = order_operations(&ops).unwrap();
        let pos_of = |target_idx: usize| order.iter().position(|&i| i == target_idx).unwrap();
        assert!(pos_of(1) < pos_of(0));
    }

    /// The exact circular case from RFC 7644 §3.7.1's own example (Group A <-> Group B).
    #[test]
    fn order_operations_detects_the_rfc_7644_circular_reference_example() {
        let ops = vec![
            post(
                "qwerty",
                "/Groups",
                json!({"members": [{"type": "Group", "value": "bulkId:ytrewq"}]}),
            ),
            post(
                "ytrewq",
                "/Groups",
                json!({"members": [{"type": "Group", "value": "bulkId:qwerty"}]}),
            ),
        ];
        assert_eq!(order_operations(&ops), Err(BulkError::CircularReference));
    }

    #[test]
    fn rejects_a_post_operation_with_no_bulk_id() {
        let ops = vec![BulkOperationRequest {
            method: BulkMethod::Post,
            bulk_id: None,
            version: None,
            path: "/Users".to_string(),
            data: Some(json!({"userName": "Alice"})),
        }];
        assert_eq!(
            order_operations(&ops),
            Err(BulkError::MissingBulkIdOnPost(0))
        );
    }

    #[test]
    fn rejects_duplicate_bulk_ids_in_the_same_request() {
        let ops = vec![
            post("qwerty", "/Users", json!({"userName": "Alice"})),
            post("qwerty", "/Users", json!({"userName": "Bob"})),
        ];
        assert_eq!(
            order_operations(&ops),
            Err(BulkError::DuplicateBulkId("qwerty".to_string()))
        );
    }

    #[test]
    fn rejects_a_reference_to_a_bulk_id_that_was_never_defined() {
        let ops = vec![post(
            "ytrewq",
            "/Groups",
            json!({"members": [{"value": "bulkId:nonexistent"}]}),
        )];
        assert_eq!(
            order_operations(&ops),
            Err(BulkError::UnresolvedBulkId("nonexistent".to_string()))
        );
    }

    #[test]
    fn resolver_substitutes_a_reference_once_recorded() {
        let mut resolver = BulkIdResolver::new();
        resolver.record("qwerty", "92b725cd-9465-4e7d-8c16-01f8e146b87a");
        let data = json!({"members": [{"type": "User", "value": "bulkId:qwerty"}]});
        let substituted = resolver.substitute(&data).unwrap();
        assert_eq!(
            substituted["members"][0]["value"],
            "92b725cd-9465-4e7d-8c16-01f8e146b87a"
        );
    }

    #[test]
    fn resolver_errors_on_an_unrecorded_reference_rather_than_leaving_the_literal_string() {
        let resolver = BulkIdResolver::new();
        let data = json!({"value": "bulkId:never-recorded"});
        let err = resolver.substitute(&data).unwrap_err();
        assert_eq!(
            err,
            BulkError::UnresolvedBulkId("never-recorded".to_string())
        );
    }

    #[test]
    fn check_limits_rejects_too_many_operations() {
        let req = BulkRequest {
            schemas: vec![BULK_REQUEST_SCHEMA_URI.to_string()],
            fail_on_errors: None,
            operations: vec![
                post("a", "/Users", json!({})),
                post("b", "/Users", json!({})),
            ],
        };
        let err = check_limits(&req, 1, 1_000_000, 100).unwrap_err();
        assert!(matches!(err, BulkError::TooLarge(_)));
    }

    #[test]
    fn check_limits_rejects_oversized_payload() {
        let req = BulkRequest {
            schemas: vec![BULK_REQUEST_SCHEMA_URI.to_string()],
            fail_on_errors: None,
            operations: vec![post("a", "/Users", json!({}))],
        };
        let err = check_limits(&req, 1000, 1_048_576, 5_000_000_000).unwrap_err();
        assert!(matches!(err, BulkError::TooLarge(_)));
    }

    #[test]
    fn check_limits_accepts_a_request_within_both_limits() {
        let req = BulkRequest {
            schemas: vec![BULK_REQUEST_SCHEMA_URI.to_string()],
            fail_on_errors: None,
            operations: vec![post("a", "/Users", json!({}))],
        };
        assert!(check_limits(&req, 1000, 1_048_576, 200).is_ok());
    }
}
