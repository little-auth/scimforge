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
//! [`apply_patch_with_schema`] layers a third check on top of the two above: full
//! per-resource-type mutability, using the same [`crate::discovery::SchemaResource`] that
//! backs the `/Schemas` discovery endpoint as the single source of truth (see
//! [`crate::user::user_schema`]'s doc comment for why one document serves both purposes
//! rather than risking a hand-maintained mutability table drifting out of sync with it).
//! `readOnly` attributes (e.g. `User.groups`) are rejected outright; `immutable`
//! attributes (e.g. `Group.members[].display`) may be `add`ed only if they have no
//! existing value, matching RFC 7644 §3.5.2's exact text: "a client MUST NOT modify an
//! attribute that has mutability 'readOnly' or 'immutable'... [but] MAY 'add' a value to
//! an 'immutable' attribute if the attribute had no previous value." [`apply_patch`]
//! (no schema) still enforces the universal common-attribute protections unconditionally
//! -- schema-driven checking is additive, not a replacement for that backstop.

use serde_json::{Map, Value};

use crate::common::Mutability;
use crate::discovery::{self, SchemaResource};
use crate::error::ScimType;
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
    /// [`apply_patch_with_schema`] only: the path targets an attribute whose schema
    /// mutability is `readOnly`, or `immutable` with an existing value already present.
    ImmutableOrReadOnly(String),
}

impl From<FilterError> for PatchError {
    fn from(e: FilterError) -> Self {
        PatchError::InvalidPath(e)
    }
}

impl PatchError {
    /// RFC 7644 §3.12 Table 9's canonical `scimType` for this failure -- every variant
    /// maps to a 400 (Bad Request) per the table, since PATCH errors are all
    /// request-shape/semantics problems, never a different status class.
    pub fn scim_type(&self) -> ScimType {
        match self {
            PatchError::NoTarget => ScimType::NoTarget,
            PatchError::Protected(_) => ScimType::Mutability,
            PatchError::InvalidPath(_) => ScimType::InvalidPath,
            PatchError::NoMatchingValue => ScimType::NoTarget,
            PatchError::AmbiguousPath(_) => ScimType::InvalidPath,
            PatchError::ImmutableOrReadOnly(_) => ScimType::Mutability,
        }
    }

    pub fn http_status(&self) -> u16 {
        400
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
/// slice of the problem. Enforces only the universal common-attribute protections (`id`,
/// `meta.*`, `schemas`); for full per-resource-type mutability, use
/// [`apply_patch_with_schema`].
pub fn apply_patch(resource: &Value, operations: &[PatchOperation]) -> Result<Value, PatchError> {
    apply_patch_internal(resource, operations, None)
}

/// As [`apply_patch`], additionally enforcing `schema`'s per-attribute `readOnly`/
/// `immutable` mutability (see the module doc). Pass [`crate::user::user_schema`] or
/// [`crate::group::group_schema`] for the corresponding resource type.
pub fn apply_patch_with_schema(
    resource: &Value,
    operations: &[PatchOperation],
    schema: &SchemaResource,
) -> Result<Value, PatchError> {
    apply_patch_internal(resource, operations, Some(schema))
}

fn apply_patch_internal(
    resource: &Value,
    operations: &[PatchOperation],
    schema: Option<&SchemaResource>,
) -> Result<Value, PatchError> {
    let mut working = resource.clone();
    for operation in operations {
        apply_one(&mut working, operation, schema)?;
    }
    Ok(working)
}

fn apply_one(
    resource: &mut Value,
    operation: &PatchOperation,
    schema: Option<&SchemaResource>,
) -> Result<(), PatchError> {
    match operation.op {
        PatchOp::Remove => apply_remove(resource, operation, schema),
        PatchOp::Add => apply_add_or_replace(resource, operation, false, schema),
        PatchOp::Replace => apply_add_or_replace(resource, operation, true, schema),
    }
}

/// RFC 7644 §3.5.2: "a client MUST NOT modify an attribute that has mutability
/// 'readOnly' or 'immutable'... [but] MAY 'add' a value to an 'immutable' attribute if
/// the attribute had no previous value" -- quoted verbatim since the "add exception"
/// is easy to get subtly wrong (it's `add` specifically, not `add` or `replace`, and only
/// when no previous value exists).
///
/// Precision note for the sub-attribute case (e.g. `members[value eq "x"].display`):
/// "had no previous value" is checked against whether the *top-level* attribute
/// (`members`) has any entries at all, not whether the one specific array entry the
/// bracket filter matches already has that sub-attribute set. This makes the check
/// conservative (may reject an add RFC 7644 would technically permit) rather than
/// permissive (never allows one it shouldn't) -- `replace`/`remove` on an immutable
/// sub-attribute are rejected unconditionally either way, which is the higher-value,
/// unambiguous case this exists to catch.
fn check_mutability(
    schema: &SchemaResource,
    resource: &Value,
    attr_name: &str,
    sub_attr: Option<&str>,
    op: PatchOp,
) -> Result<(), PatchError> {
    let Some(attr_def) = discovery::find_attribute(schema, attr_name, sub_attr) else {
        // An attribute this schema doesn't know about (an unmodeled extension, say) --
        // not this function's job to reject what it can't classify.
        return Ok(());
    };
    let mutability =
        Mutability::from_rfc_str(&attr_def.mutability).unwrap_or(Mutability::ReadWrite);
    match mutability {
        Mutability::ReadOnly => Err(PatchError::ImmutableOrReadOnly(attr_name.to_string())),
        Mutability::Immutable => {
            let has_existing = op != PatchOp::Add
                || resource
                    .get(attr_name)
                    .is_some_and(|v| !matches!(v, Value::Null));
            if has_existing {
                Err(PatchError::ImmutableOrReadOnly(attr_name.to_string()))
            } else {
                Ok(())
            }
        }
        Mutability::ReadWrite | Mutability::WriteOnly => Ok(()),
    }
}

/// The sub-attribute a mutability check must resolve against, regardless of which of the
/// two grammatically distinct ways a `PatchPath` carries one: a plain dotted path's own
/// `attr_path.sub_attr` (`name.familyName`), or a bracket-filtered path's trailing
/// `sub_attr_after_filter` (`members[value eq "x"].display`). Mixing these up silently
/// resolves mutability against the *top-level* attribute instead of the sub-attribute --
/// exactly the bug this helper exists to make impossible to reintroduce at a call site.
fn effective_sub_attr(path: &filter::PatchPath) -> Option<&str> {
    path.attr_path
        .sub_attr
        .as_deref()
        .or(path.sub_attr_after_filter.as_deref())
}

fn apply_remove(
    resource: &mut Value,
    operation: &PatchOperation,
    schema: Option<&SchemaResource>,
) -> Result<(), PatchError> {
    let Some(path_str) = &operation.path else {
        return Err(PatchError::NoTarget);
    };
    let path = filter::parse_patch_path(path_str)?;
    if is_protected(&path.attr_path.attr_name) {
        return Err(PatchError::Protected(path.attr_path.attr_name.clone()));
    }
    if let Some(schema) = schema {
        check_mutability(
            schema,
            resource,
            &path.attr_path.attr_name,
            effective_sub_attr(&path),
            PatchOp::Remove,
        )?;
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
    schema: Option<&SchemaResource>,
) -> Result<(), PatchError> {
    let value = operation.value.clone().unwrap_or(Value::Null);
    let op_kind = if is_replace {
        PatchOp::Replace
    } else {
        PatchOp::Add
    };

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
            if let Some(schema) = schema {
                check_mutability(schema, resource, key, None, op_kind)?;
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
    if let Some(schema) = schema {
        check_mutability(
            schema,
            resource,
            &path.attr_path.attr_name,
            effective_sub_attr(&path),
            op_kind,
        )?;
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

/// RFC 7643 §2.2: `caseExact` "OPTIONAL... DEFAULT: false" -- case-*insensitive* is the
/// spec's stated default, not an implementation nicety, so string equality/substring
/// comparisons fold case unless the caller knows better. (A schema-aware caller wanting
/// per-attribute `caseExact` overrides isn't implemented yet -- this default just needs
/// to stop being wrong first; see the Follow-ups in the ticket for the schema-threaded
/// version.)
fn compare(actual: &Value, op: &CompareOp, expected: &CompValue) -> bool {
    match (actual, expected) {
        (Value::String(a), CompValue::String(b)) => {
            let (a, b) = (a.to_lowercase(), b.to_lowercase());
            match op {
                CompareOp::Eq => a == b,
                CompareOp::Ne => a != b,
                CompareOp::Co => a.contains(&b),
                CompareOp::Sw => a.starts_with(&b),
                CompareOp::Ew => a.ends_with(&b),
                CompareOp::Gt => a > b,
                CompareOp::Ge => a >= b,
                CompareOp::Lt => a < b,
                CompareOp::Le => a <= b,
            }
        }
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

    // --- Schema-driven mutability (apply_patch_with_schema) ---

    #[test]
    fn schema_rejects_replace_targeting_a_readonly_attribute() {
        // User.groups is readOnly per RFC 7643 4.1.5 -- not one of the three universally
        // protected common attributes, only catchable via the schema-driven check.
        let resource = user_with_emails();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("groups"),
                Some(json!([{"value": "g-1", "display": "Admins"}])),
            )],
            &crate::user::user_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("groups".to_string()));
    }

    #[test]
    fn schema_allows_replace_on_readwrite_attributes_same_as_the_unscoped_check() {
        let resource = user_with_emails();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!(false)))],
            &crate::user::user_schema(),
        )
        .unwrap();
        assert_eq!(result["active"], false);
    }

    #[test]
    fn schema_allows_adding_a_fresh_readwrite_attribute_group_members_itself_is_readwrite() {
        // Group.members is readWrite (only its sub-attributes value/$ref/display are
        // immutable) -- confirms the schema check doesn't over-reject a plain readWrite
        // top-level add.
        let resource = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins"
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some("members"),
                Some(json!([{"value": "u-1", "type": "User"}])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        assert_eq!(result["members"][0]["value"], "u-1");
    }

    #[test]
    fn schema_rejects_replace_on_an_immutable_sub_attribute_that_already_has_a_value() {
        let resource = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins",
            "members": [{"value": "u-1", "type": "User", "display": "Alice"}]
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[value eq "u-1"].display"#),
                Some(json!("Alicia")),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("members".to_string()));
    }

    #[test]
    fn schema_rejects_no_path_add_that_smuggles_a_readonly_attribute() {
        let resource = user_with_emails();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                None,
                Some(json!({"active": false, "groups": [{"value": "g-1"}]})),
            )],
            &crate::user::user_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("groups".to_string()));
    }

    #[test]
    fn apply_patch_without_schema_still_allows_what_schema_would_reject() {
        // Documents the deliberate difference: apply_patch (no schema) only enforces the
        // universal common-attribute protections, not User.groups' readOnly status --
        // apply_patch_with_schema is what adds that.
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("groups"),
                Some(json!([{"value": "g-1"}])),
            )],
        )
        .unwrap();
        assert_eq!(result["groups"][0]["value"], "g-1");
    }

    #[test]
    fn patch_error_maps_to_the_rfc_7644_table_9_scim_type() {
        assert_eq!(PatchError::NoTarget.scim_type(), ScimType::NoTarget);
        assert_eq!(
            PatchError::Protected("id".to_string()).scim_type(),
            ScimType::Mutability
        );
        assert_eq!(
            PatchError::ImmutableOrReadOnly("groups".to_string()).scim_type(),
            ScimType::Mutability
        );
        assert_eq!(PatchError::NoMatchingValue.scim_type(), ScimType::NoTarget);
    }

    #[test]
    fn bracket_filter_matching_is_case_insensitive_by_default() {
        // RFC 7643 2.2: caseExact "DEFAULT: false" -- a filter value's case must not
        // matter unless the crate is told the attribute is caseExact.
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"emails[type eq "WORK"].value"#),
                Some(json!("new@example.com")),
            )],
        )
        .unwrap();
        assert_eq!(result["emails"][0]["value"], "new@example.com");
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
