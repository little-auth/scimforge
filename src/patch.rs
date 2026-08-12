//! RFC 7644 §3.5.2 PATCH operation semantics, applied to a resource's JSON
//! representation. This crate has no I/O: a caller reads its resource from storage,
//! deserializes to `serde_json::Value` (or serializes a typed resource from
//! [`crate::user`]/[`crate::group`] via `serde_json::to_value`), calls [`apply_patch`],
//! and persists the result -- the atomicity RFC 7644 requires ("regardless of the number
//! of operations, SHALL be treated as atomic... the original SCIM resource MUST be
//! restored" on any error) is achieved here by operating on a clone and only returning it
//! on full success; a caller's own persistence step must still be atomic on its side
//! (e.g. one DB transaction), which this crate can't provide since it does no I/O.
//!
//! Two hard requirements drove this module's design, both traced to real SCIM CVEs (see
//! the crate README):
//!
//! - **Protected common attributes are never touchable by PATCH.** `id`, every `meta.*`
//!   sub-attribute, and `schemas` are rejected outright by [`apply_patch`], regardless of
//!   whether the request reaches them via an explicit path or the no-path whole-resource
//!   form. This is the direct mitigation for the scim-patch-class bug (a PATCH library
//!   that resolved paths without checking them against protected fields, letting a
//!   client touch reserved attributes it should never reach).
//! - **Ambiguous paths are a hard parse/validation error, never a best guess.** A path
//!   this module can't resolve unambiguously against the actual JSON shape returns
//!   [`PatchError`], not a silent no-op or a silent partial match.
//!
//! Not yet covered (tracked as a real scope boundary, not silently skipped): full
//! per-resource-type schema-driven mutability (e.g. knowing that `User.groups` is
//! `readOnly` the way `id`/`meta`/`schemas` are universally protected here) requires a
//! schema-attribute registry this crate doesn't own yet -- only the universal common
//! attributes are protected in this version.

use serde_json::{Map, Value};

use crate::filter::{self, CompValue, CompareOp, Filter, FilterError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatchOperation {
    pub op: PatchOp,
    pub path: Option<String>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatchError {
    /// RFC 7644 §3.5.2: "If 'path' is unspecified, the operation fails with HTTP status
    /// code 400 and a 'scimType' error code of 'noTarget'" -- `remove` requires a path.
    NoTarget,
    /// The request targeted `id`, a `meta.*` sub-attribute, or `schemas` -- see the
    /// module doc's protected-attributes requirement.
    Protected(String),
    InvalidPath(FilterError),
    /// `replace`/`remove` with a value-filter path (e.g. `emails[type eq "work"]`) that
    /// matched no existing entry -- RFC 7644 §3.5.2: "the service provider SHALL treat
    /// this as an invalid PATCH request... scimType of 'noTarget'" for replace's filtered
    /// case with no match; the same "found nothing to act on" shape applies to remove.
    NoMatchingValue,
    /// The path targets a shape apply_patch can't resolve unambiguously against the
    /// actual JSON structure (e.g. a bracket filter against a non-array value).
    AmbiguousPath(String),
}

impl From<FilterError> for PatchError {
    fn from(e: FilterError) -> Self {
        PatchError::InvalidPath(e)
    }
}

const PROTECTED_TOP_LEVEL: &[&str] = &["id", "meta", "schemas"];

fn is_protected(attr_name: &str) -> bool {
    PROTECTED_TOP_LEVEL
        .iter()
        .any(|p| p.eq_ignore_ascii_case(attr_name))
}

/// Applies a sequence of PATCH operations to `resource` and returns the result, or the
/// first error encountered -- `resource` itself is never mutated in place (a clone is
/// modified internally), so a caller that discards the `Err` case still holds an
/// untouched original, satisfying RFC 7644's atomicity requirement for this crate's
/// slice of the problem.
pub fn apply_patch(resource: &Value, operations: &[PatchOperation]) -> Result<Value, PatchError> {
    let mut working = resource.clone();
    for operation in operations {
        apply_one(&mut working, operation)?;
    }
    Ok(working)
}

fn apply_one(resource: &mut Value, operation: &PatchOperation) -> Result<(), PatchError> {
    match operation.op {
        PatchOp::Remove => apply_remove(resource, operation),
        PatchOp::Add => apply_add_or_replace(resource, operation, false),
        PatchOp::Replace => apply_add_or_replace(resource, operation, true),
    }
}

fn apply_remove(resource: &mut Value, operation: &PatchOperation) -> Result<(), PatchError> {
    let Some(path_str) = &operation.path else {
        return Err(PatchError::NoTarget);
    };
    let path = filter::parse_patch_path(path_str)?;
    if is_protected(&path.attr_path.attr_name) {
        return Err(PatchError::Protected(path.attr_path.attr_name.clone()));
    }
    let root = resource.as_object_mut().ok_or_else(|| {
        PatchError::AmbiguousPath("resource root is not a JSON object".to_string())
    })?;

    match (&path.attr_path.sub_attr, &path.value_filter) {
        (Some(sub), None) => {
            // "name.familyName" with no bracket filter -- remove just that sub-attribute.
            if let Some(Value::Object(obj)) = root.get_mut(&path.attr_path.attr_name) {
                obj.remove(sub);
            }
            Ok(())
        }
        (None, None) => {
            // RFC 7644 3.5.2: multi-valued with no filter removes the whole attribute
            // (all values), single-valued removes the attribute and its value -- both
            // are "delete this top-level key," so one branch covers both cases.
            root.remove(&path.attr_path.attr_name);
            Ok(())
        }
        (_, Some(value_filter)) => {
            let array = root
                .get_mut(&path.attr_path.attr_name)
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    PatchError::AmbiguousPath(format!(
                        "'{}' is not a multi-valued attribute this resource has",
                        path.attr_path.attr_name
                    ))
                })?;
            let before = array.len();
            if let Some(sub) = &path.sub_attr_after_filter {
                // e.g. addresses[type eq "work"].streetAddress -- remove just that
                // sub-attribute from every matching entry, not the whole entry.
                let mut any_matched = false;
                for entry in array.iter_mut() {
                    if evaluate(value_filter, entry) {
                        any_matched = true;
                        if let Value::Object(obj) = entry {
                            obj.remove(sub);
                        }
                    }
                }
                if !any_matched {
                    return Err(PatchError::NoMatchingValue);
                }
            } else {
                array.retain(|entry| !evaluate(value_filter, entry));
                if array.len() == before {
                    return Err(PatchError::NoMatchingValue);
                }
            }
            Ok(())
        }
    }
}

fn apply_add_or_replace(
    resource: &mut Value,
    operation: &PatchOperation,
    is_replace: bool,
) -> Result<(), PatchError> {
    let value = operation.value.clone().unwrap_or(Value::Null);

    let Some(path_str) = &operation.path else {
        // No-path form: value is a set of attributes merged onto the resource root
        // (RFC 7644 3.5.2, both add and replace).
        let Value::Object(incoming) = &value else {
            return Err(PatchError::AmbiguousPath(
                "no-path add/replace requires an object value".to_string(),
            ));
        };
        for key in incoming.keys() {
            if is_protected(key) {
                return Err(PatchError::Protected(key.clone()));
            }
        }
        let root = resource.as_object_mut().ok_or_else(|| {
            PatchError::AmbiguousPath("resource root is not a JSON object".to_string())
        })?;
        for (k, v) in incoming {
            root.insert(k.clone(), v.clone());
        }
        return Ok(());
    };

    let path = filter::parse_patch_path(path_str)?;
    if is_protected(&path.attr_path.attr_name) {
        return Err(PatchError::Protected(path.attr_path.attr_name.clone()));
    }
    let root = resource.as_object_mut().ok_or_else(|| {
        PatchError::AmbiguousPath("resource root is not a JSON object".to_string())
    })?;

    match (&path.attr_path.sub_attr, &path.value_filter) {
        (Some(sub), None) => {
            let entry = root
                .entry(path.attr_path.attr_name.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            let obj = entry.as_object_mut().ok_or_else(|| {
                PatchError::AmbiguousPath(format!(
                    "'{}' is not a complex attribute",
                    path.attr_path.attr_name
                ))
            })?;
            obj.insert(sub.clone(), value);
            Ok(())
        }
        (None, None) => {
            match root.get_mut(&path.attr_path.attr_name) {
                Some(existing @ Value::Array(_)) if !is_replace => {
                    // add onto a multi-valued attribute appends rather than overwriting.
                    let arr = existing.as_array_mut().expect("matched Value::Array");
                    match value {
                        Value::Array(mut new_items) => arr.append(&mut new_items),
                        single => arr.push(single),
                    }
                }
                _ => {
                    root.insert(path.attr_path.attr_name.clone(), value);
                }
            }
            Ok(())
        }
        (_, Some(value_filter)) => {
            let array = root
                .get_mut(&path.attr_path.attr_name)
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    PatchError::AmbiguousPath(format!(
                        "'{}' is not a multi-valued attribute this resource has",
                        path.attr_path.attr_name
                    ))
                })?;
            let mut any_matched = false;
            for entry in array.iter_mut() {
                if evaluate(value_filter, entry) {
                    any_matched = true;
                    if let Some(sub) = &path.sub_attr_after_filter {
                        if let Value::Object(obj) = entry {
                            obj.insert(sub.clone(), value.clone());
                        }
                    } else {
                        *entry = value.clone();
                    }
                }
            }
            if !any_matched {
                return Err(PatchError::NoMatchingValue);
            }
            Ok(())
        }
    }
}

/// Evaluates a parsed [`Filter`] against one JSON value -- the piece [`crate::filter`]'s
/// module doc explicitly scopes out ("evaluation... is a storage-layer concern"), because
/// that scoping is about evaluating a filter as a *search/list query* over a whole
/// collection a caller's storage owns. This is different: PATCH's bracket-filter matching
/// operates on entries already in hand, inside one resource's own JSON, which is squarely
/// this crate's problem since PATCH application itself is.
fn evaluate(filter: &Filter, value: &Value) -> bool {
    match filter {
        Filter::Present(path) => resolve_scalar(path, value).is_some_and(|v| !is_empty(v)),
        Filter::Compare(path, op, comp) => {
            resolve_scalar(path, value).is_some_and(|v| compare(v, op, comp))
        }
        Filter::And(a, b) => evaluate(a, value) && evaluate(b, value),
        Filter::Or(a, b) => evaluate(a, value) || evaluate(b, value),
        Filter::Not(inner) => !evaluate(inner, value),
        // A nested valuePath inside a value-filter (filtering a sub-attribute that is
        // itself multi-valued) has no realistic case in this crate's scope yet -- treat
        // as non-matching rather than guessing.
        Filter::ValuePath(_, _) => false,
    }
}

fn is_empty(v: &Value) -> bool {
    matches!(v, Value::Null)
        || matches!(v, Value::String(s) if s.is_empty())
        || matches!(v, Value::Array(a) if a.is_empty())
}

fn resolve_scalar<'a>(path: &crate::filter::AttrPath, value: &'a Value) -> Option<&'a Value> {
    let base = value.get(&path.attr_name)?;
    match &path.sub_attr {
        Some(sub) => base.get(sub),
        None => Some(base),
    }
}

fn compare(actual: &Value, op: &CompareOp, expected: &CompValue) -> bool {
    match (actual, expected) {
        (Value::String(a), CompValue::String(b)) => match op {
            CompareOp::Eq => a == b,
            CompareOp::Ne => a != b,
            CompareOp::Co => a.contains(b.as_str()),
            CompareOp::Sw => a.starts_with(b.as_str()),
            CompareOp::Ew => a.ends_with(b.as_str()),
            CompareOp::Gt => a > b,
            CompareOp::Ge => a >= b,
            CompareOp::Lt => a < b,
            CompareOp::Le => a <= b,
        },
        (Value::Number(a), CompValue::Number(b, _)) => {
            let a = a.as_f64().unwrap_or(f64::NAN);
            match op {
                CompareOp::Eq => a == *b,
                CompareOp::Ne => a != *b,
                CompareOp::Gt => a > *b,
                CompareOp::Ge => a >= *b,
                CompareOp::Lt => a < *b,
                CompareOp::Le => a <= *b,
                // co/sw/ew are string-only per RFC 7644 -- not a match for numbers.
                CompareOp::Co | CompareOp::Sw | CompareOp::Ew => false,
            }
        }
        (Value::Bool(a), CompValue::True) => *op == CompareOp::Eq && *a,
        (Value::Bool(a), CompValue::False) => *op == CompareOp::Eq && !*a,
        (Value::Null, CompValue::Null) => *op == CompareOp::Eq,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user_with_emails() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "u-1",
            "userName": "bjensen",
            "active": true,
            "emails": [
                {"value": "old@example.com", "type": "work", "primary": true},
                {"value": "personal@example.com", "type": "home"}
            ]
        })
    }

    fn op(kind: PatchOp, path: Option<&str>, value: Option<Value>) -> PatchOperation {
        PatchOperation {
            op: kind,
            path: path.map(str::to_string),
            value,
        }
    }

    #[test]
    fn replace_simple_top_level_attribute() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!(false)))],
        )
        .unwrap();
        assert_eq!(result["active"], false);
    }

    #[test]
    fn add_to_a_non_existent_path_behaves_as_add_per_spec() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(PatchOp::Add, Some("nickName"), Some(json!("Babs")))],
        )
        .unwrap();
        assert_eq!(result["nickName"], "Babs");
    }

    #[test]
    fn remove_multi_valued_attribute_with_no_filter_removes_all_values() {
        let resource = user_with_emails();
        let result = apply_patch(&resource, &[op(PatchOp::Remove, Some("emails"), None)]).unwrap();
        assert!(result.get("emails").is_none());
    }

    #[test]
    fn remove_requires_a_path() {
        let resource = user_with_emails();
        let err = apply_patch(&resource, &[op(PatchOp::Remove, None, None)]).unwrap_err();
        assert_eq!(err, PatchError::NoTarget);
    }

    #[test]
    fn replace_with_bracket_filter_replaces_only_the_matching_entry() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"emails[type eq "work"].value"#),
                Some(json!("new@example.com")),
            )],
        )
        .unwrap();
        let emails = result["emails"].as_array().unwrap();
        assert_eq!(emails[0]["value"], "new@example.com");
        // The non-matching entry (home) is untouched.
        assert_eq!(emails[1]["value"], "personal@example.com");
    }

    #[test]
    fn remove_with_bracket_filter_removes_only_the_matching_entry() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(PatchOp::Remove, Some(r#"emails[type eq "home"]"#), None)],
        )
        .unwrap();
        let emails = result["emails"].as_array().unwrap();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0]["type"], "work");
    }

    #[test]
    fn replace_bracket_filter_with_no_match_is_an_error_not_a_silent_noop() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"emails[type eq "nonexistent"].value"#),
                Some(json!("x")),
            )],
        )
        .unwrap_err();
        assert_eq!(err, PatchError::NoMatchingValue);
    }

    #[test]
    fn no_path_add_merges_attributes_onto_the_resource_root() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(
                PatchOp::Add,
                None,
                Some(json!({"title": "Vice President", "active": false})),
            )],
        )
        .unwrap();
        assert_eq!(result["title"], "Vice President");
        assert_eq!(result["active"], false);
        // Untouched fields survive the merge.
        assert_eq!(result["userName"], "bjensen");
    }

    // --- Protected-attribute rejection: the direct CVE-informed requirement ---

    #[test]
    fn rejects_replace_targeting_id() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("id"),
                Some(json!("attacker-controlled")),
            )],
        )
        .unwrap_err();
        assert_eq!(err, PatchError::Protected("id".to_string()));
    }

    #[test]
    fn rejects_replace_targeting_a_meta_sub_attribute() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("meta.resourceType"),
                Some(json!("Group")),
            )],
        )
        .unwrap_err();
        assert_eq!(err, PatchError::Protected("meta".to_string()));
    }

    #[test]
    fn rejects_replace_targeting_schemas() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("schemas"),
                Some(json!(["urn:evil:injected:schema"])),
            )],
        )
        .unwrap_err();
        assert_eq!(err, PatchError::Protected("schemas".to_string()));
    }

    /// The exact shape the scim-patch prototype-pollution class generalizes to: a
    /// no-path (whole-object) add/replace that bundles a protected key alongside
    /// legitimate ones must be rejected in full, not silently accept the legitimate
    /// keys while dropping the protected one (a partial-apply here would itself be a
    /// spec violation of the atomicity requirement, on top of being a worse security
    /// posture than a clean reject).
    #[test]
    fn rejects_no_path_replace_that_smuggles_a_protected_key_alongside_legitimate_ones() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({"active": false, "id": "attacker-controlled"})),
            )],
        )
        .unwrap_err();
        assert_eq!(err, PatchError::Protected("id".to_string()));
        // And critically: verify this wasn't a partial apply against the *original*
        // resource passed in (apply_patch must not mutate its input).
        assert_eq!(resource["active"], true);
    }

    #[test]
    fn rejects_id_case_insensitively() {
        // RFC 7643 attribute names are case-insensitive; a client sending "ID" or "Id"
        // must not slip past a literal-string-match protection check.
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(PatchOp::Replace, Some("ID"), Some(json!("x")))],
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::Protected(_)));
    }

    #[test]
    fn apply_patch_never_mutates_its_input_even_on_success() {
        let resource = user_with_emails();
        let original = resource.clone();
        let _ = apply_patch(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!(false)))],
        )
        .unwrap();
        assert_eq!(resource, original);
    }

    #[test]
    fn a_mid_sequence_error_does_not_return_a_partially_patched_resource() {
        let resource = user_with_emails();
        let ops = vec![
            op(PatchOp::Replace, Some("active"), Some(json!(false))),
            op(PatchOp::Replace, Some("id"), Some(json!("nope"))), // fails here
        ];
        let err = apply_patch(&resource, &ops).unwrap_err();
        assert!(matches!(err, PatchError::Protected(_)));
        // The original is untouched -- apply_patch never returns the intermediate
        // (first-op-applied) state on a later failure.
        assert_eq!(resource["active"], true);
    }

    #[test]
    fn invalid_path_syntax_is_a_hard_error_not_a_best_guess() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("emails[type eq"),
                Some(json!("x")),
            )],
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::InvalidPath(_)));
    }
}
