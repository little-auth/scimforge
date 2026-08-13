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
//! attribute that has mutability 'readOnly' or 'immutable'... \[but\] MAY 'add' a value to
//! an 'immutable' attribute if the attribute had no previous value." [`apply_patch`]
//! (no schema) still enforces the universal common-attribute protections unconditionally
//! -- schema-driven checking is additive, not a replacement for that backstop.
//!
//! [`apply_patch_with_schema`] also coerces a PATCH `value` that's a JSON string into the
//! attribute's declared scalar type (`boolean`/`integer`/`decimal`), but only for exact
//! canonical string forms of that type (e.g. `"true"`, not `"True"`) -- real IdP traffic
//! (GitHub issue #1: a real, actively-maintained Keycloak SCIM client plugin sends
//! `boolean`-typed PATCH values as JSON strings via Java's `Boolean#toString()`), not a
//! general lenient-type parser. [`apply_patch`] has no declared type to coerce to and
//! never does this.

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
///
/// Takes exactly one schema: for a resource with an active extension (e.g. a User with
/// the Enterprise User extension), extension-only attributes like `manager.displayName`
/// won't be covered by mutability enforcement unless the caller merges the extension's
/// attributes into the schema passed here (`user_schema().attributes.into_iter().chain(
/// crate::user::enterprise_user_schema().attributes)`) -- this crate doesn't merge them
/// automatically, since it has no way to know which extensions are actually active for
/// a given resource without the caller telling it.
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
/// 'readOnly' or 'immutable'... \[but\] MAY 'add' a value to an 'immutable' attribute if
/// the attribute had no previous value" -- quoted verbatim since the "add exception"
/// is easy to get subtly wrong (it's `add` specifically, not `add` or `replace`, and only
/// when no previous value exists). `replace`/`remove` on an immutable attribute are
/// rejected unconditionally regardless of `value_filter`, so `has_existing` below is only
/// ever actually evaluated for `op == PatchOp::Add`.
fn check_mutability(
    schema: &SchemaResource,
    resource: &Value,
    attr_name: &str,
    sub_attr: Option<&str>,
    value_filter: Option<&Filter>,
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
                || attribute_has_existing_value(
                    resource,
                    attr_name,
                    sub_attr,
                    value_filter,
                    schema,
                );
            if has_existing {
                Err(PatchError::ImmutableOrReadOnly(attr_name.to_string()))
            } else {
                Ok(())
            }
        }
        Mutability::ReadWrite | Mutability::WriteOnly => Ok(()),
    }
}

/// Whether `attr_name`(.`sub_attr`) already has a value on `resource`, precisely --
/// consulting the specific bracket-filter-matched array entry when `value_filter` is
/// `Some` (e.g. `members[value eq "x"].display`), and the specific sub-attribute of a
/// plain dotted path otherwise (e.g. `profile.level`), rather than only whether the
/// top-level attribute is present at all. That coarser check is [`check_mutability`]'s
/// only source of imprecision in the immutable "had no previous value" add-exception --
/// `replace`/`remove` reject unconditionally regardless, so this is never consulted for
/// them.
fn attribute_has_existing_value(
    resource: &Value,
    attr_name: &str,
    sub_attr: Option<&str>,
    value_filter: Option<&Filter>,
    schema: &SchemaResource,
) -> bool {
    match (
        value_filter,
        resource.get(attr_name).and_then(Value::as_array),
    ) {
        (Some(filter), Some(array)) => array
            .iter()
            .filter(|entry| evaluate(filter, entry, attr_name, Some(schema)))
            .any(|entry| match sub_attr {
                Some(sub) => entry.get(sub).is_some_and(|v| !matches!(v, Value::Null)),
                // A matched entry existing at all is itself "a previous value" when the
                // path targets no sub-attribute (e.g. a whole-entry replace target).
                None => true,
            }),
        _ => match sub_attr {
            Some(sub) => resource
                .get(attr_name)
                .and_then(|v| v.get(sub))
                .is_some_and(|v| !matches!(v, Value::Null)),
            None => resource
                .get(attr_name)
                .is_some_and(|v| !matches!(v, Value::Null)),
        },
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
            path.value_filter.as_ref(),
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
                    if evaluate(value_filter, entry, &path.attr_path.attr_name, schema) {
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
                array.retain(|entry| {
                    !evaluate(value_filter, entry, &path.attr_path.attr_name, schema)
                });
                if array.len() == before {
                    return Err(PatchError::NoMatchingValue);
                }
            }
            Ok(())
        }
    }
}

/// Coerces `value` to the JSON-native form of `attr_def`'s declared scalar type when
/// `value` is a JSON string that is an exact canonical textual representation of that
/// type -- accommodating real SCIM clients that send PATCH `value`s for boolean/integer/
/// decimal attributes as JSON strings rather than RFC 7643's native JSON types for them.
/// Concrete evidence, not a hypothetical: mitodl/keycloak-scim (an actively-maintained
/// Keycloak SCIM client plugin, see the crate README's real-IdP-conformance section)
/// builds `active`'s PATCH replace op as `.value(active.toString())` -- Java
/// `Boolean#toString()` is the JSON string `"true"`/`"false"`, not a native boolean.
/// Anything that isn't an exact canonical form (wrong case, leading zeros, whitespace,
/// non-finite) is left untouched rather than guessed at -- this accommodates one
/// evidenced real sender, it isn't a general lenient-type parser. Only reachable from
/// `apply_patch_with_schema`: `apply_patch` has no schema, so it has no declared type to
/// coerce to, and keeps storing whatever JSON type it's given, unchanged.
fn coerce_to_attribute_type(value: Value, attr_def: &discovery::AttributeDefinition) -> Value {
    let Value::String(s) = &value else {
        return value;
    };
    let coerced = match attr_def.type_.as_str() {
        "boolean" if s == "true" => Some(Value::Bool(true)),
        "boolean" if s == "false" => Some(Value::Bool(false)),
        "integer" => s
            .parse::<i64>()
            .ok()
            .filter(|n| n.to_string() == *s)
            .map(|n| Value::Number(n.into())),
        "decimal" => s
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite())
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number),
        _ => None,
    };
    coerced.unwrap_or(value)
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
                check_mutability(schema, resource, key, None, None, op_kind)?;
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
            path.value_filter.as_ref(),
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
            let value = match schema
                .and_then(|s| discovery::find_attribute(s, &path.attr_path.attr_name, Some(sub)))
            {
                Some(attr_def) => coerce_to_attribute_type(value, attr_def),
                None => value,
            };
            obj.insert(sub.clone(), value);
            Ok(())
        }
        (None, None) => {
            let value = match schema
                .and_then(|s| discovery::find_attribute(s, &path.attr_path.attr_name, None))
            {
                Some(attr_def) => coerce_to_attribute_type(value, attr_def),
                None => value,
            };
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
                if evaluate(value_filter, entry, &path.attr_path.attr_name, schema) {
                    any_matched = true;
                    if let Some(sub) = &path.sub_attr_after_filter {
                        if let Value::Object(obj) = entry {
                            let coerced = match schema.and_then(|s| {
                                discovery::find_attribute(s, &path.attr_path.attr_name, Some(sub))
                            }) {
                                Some(attr_def) => coerce_to_attribute_type(value.clone(), attr_def),
                                None => value.clone(),
                            };
                            obj.insert(sub.clone(), coerced);
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
///
/// `parent_attr` is the multi-valued attribute `value` is one entry of (e.g. `"emails"`
/// for a `type eq "work"` filter inside `emails[type eq "work"]`) -- passed to
/// [`discovery::is_case_exact`] alongside `schema` so it can resolve the filter's own
/// attribute (e.g. `"type"`) as that parent's sub-attribute for `caseExact` lookup,
/// since [`discovery::find_attribute`] alone has no way to know `"type"` isn't a
/// top-level schema attribute.
fn evaluate(
    filter: &Filter,
    value: &Value,
    parent_attr: &str,
    schema: Option<&SchemaResource>,
) -> bool {
    match filter {
        Filter::Present(path) => resolve_scalar(path, value).is_some_and(|v| !is_empty(v)),
        Filter::Compare(path, op, comp) => resolve_scalar(path, value).is_some_and(|v| {
            let case_exact = discovery::is_case_exact(
                schema,
                Some(parent_attr),
                &path.attr_name,
                path.sub_attr.as_deref(),
            );
            compare(v, op, comp, case_exact)
        }),
        Filter::And(a, b) => {
            evaluate(a, value, parent_attr, schema) && evaluate(b, value, parent_attr, schema)
        }
        Filter::Or(a, b) => {
            evaluate(a, value, parent_attr, schema) || evaluate(b, value, parent_attr, schema)
        }
        Filter::Not(inner) => !evaluate(inner, value, parent_attr, schema),
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
/// comparisons fold case unless `case_exact` says otherwise (resolved per-attribute by
/// [`discovery::is_case_exact`] when a schema is available; always `false` -- fold --
/// via [`apply_patch`], which has no schema to consult).
fn compare(actual: &Value, op: &CompareOp, expected: &CompValue, case_exact: bool) -> bool {
    match (actual, expected) {
        (Value::String(a), CompValue::String(b)) => {
            let (a, b) = if case_exact {
                (a.clone(), b.clone())
            } else {
                (a.to_lowercase(), b.to_lowercase())
            };
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

    // --- Schema-aware caseExact filter evaluation (issue #4) ---

    /// A synthetic schema with a multi-valued `widgets` attribute whose `code`
    /// sub-attribute is `caseExact: true` and whose `label` sub-attribute is the
    /// default `caseExact: false` -- neither `user_schema()` nor `group_schema()`
    /// currently has a real caseExact:true sub-attribute of a multi-valued attribute,
    /// so this is the only way to exercise bracket-filter matching against one.
    fn widget_schema() -> SchemaResource {
        SchemaResource {
            schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Widget".to_string(),
            name: Some("Widget".to_string()),
            description: None,
            attributes: vec![crate::discovery::AttributeDefinition {
                multi_valued: true,
                sub_attributes: vec![
                    crate::discovery::AttributeDefinition {
                        case_exact: true,
                        ..crate::discovery::AttributeDefinition::simple(
                            "code",
                            "string",
                            "Case-sensitive widget code.",
                            "readWrite",
                        )
                    },
                    crate::discovery::AttributeDefinition::simple(
                        "label",
                        "string",
                        "Case-insensitive widget label.",
                        "readWrite",
                    ),
                ],
                ..crate::discovery::AttributeDefinition::simple(
                    "widgets",
                    "complex",
                    "A list of widgets.",
                    "readWrite",
                )
            }],
        }
    }

    fn resource_with_widgets() -> Value {
        json!({
            "schemas": ["urn:test:Widget"],
            "id": "w-1",
            "widgets": [
                {"code": "ABC", "label": "Sprocket"}
            ]
        })
    }

    #[test]
    fn schema_aware_bracket_filter_is_case_exact_for_a_caseexact_true_sub_attribute() {
        // "code" is caseExact:true -- a filter value differing only in case must NOT
        // match, unlike the always-fold behavior of the unscoped apply_patch.
        let resource = resource_with_widgets();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[code eq "abc"].label"#),
                Some(json!("Renamed")),
            )],
            &widget_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::NoMatchingValue);

        // The exact-case value still matches.
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[code eq "ABC"].label"#),
                Some(json!("Renamed")),
            )],
            &widget_schema(),
        )
        .unwrap();
        assert_eq!(result["widgets"][0]["label"], "Renamed");
    }

    #[test]
    fn schema_aware_bracket_filter_still_folds_case_for_a_caseexact_false_sub_attribute() {
        // "label" is the default caseExact:false -- case must still not matter, even
        // with a schema present, since the RFC default is fold-not-compare.
        let resource = resource_with_widgets();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[label eq "SPROCKET"].code"#),
                Some(json!("XYZ")),
            )],
            &widget_schema(),
        )
        .unwrap();
        assert_eq!(result["widgets"][0]["code"], "XYZ");
    }

    #[test]
    fn schema_aware_bracket_filter_folds_case_for_an_unresolvable_sub_attribute() {
        // A sub-attribute the schema doesn't model at all must still fall back to
        // fold (the RFC default), never accidentally default to caseExact -- an
        // unknown-attribute case must never be *more* restrictive than a known one.
        let resource = json!({
            "schemas": ["urn:test:Widget"],
            "id": "w-1",
            "widgets": [{"unmodeled": "ABC", "label": "Sprocket"}]
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[unmodeled eq "abc"].label"#),
                Some(json!("Renamed")),
            )],
            &widget_schema(),
        )
        .unwrap();
        assert_eq!(result["widgets"][0]["label"], "Renamed");
    }

    #[test]
    fn apply_patch_without_schema_still_always_folds_case_for_bracket_filters() {
        // Documents that the no-schema apply_patch keeps today's behavior even when
        // the schema-aware apply_patch_with_schema would now compare "code" literally.
        let resource = resource_with_widgets();
        let result = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[code eq "abc"].label"#),
                Some(json!("Renamed")),
            )],
        )
        .unwrap();
        assert_eq!(result["widgets"][0]["label"], "Renamed");
    }

    #[test]
    fn schema_aware_compound_filter_resolves_case_exact_independently_per_clause() {
        // Adversarial: an AND-combined filter mixes a caseExact:true clause ("code") with
        // a caseExact:false clause ("label") against the same entry -- Filter::And's
        // recursion must thread parent_attr/schema into *both* sides independently, not
        // drop it after the first recursive call.
        let resource = resource_with_widgets();

        // Wrong-case "code" (case-exact) must fail to match even though "label" matches
        // case-insensitively -- proves the AND's left branch is truly case-exact.
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[code eq "abc" and label eq "SPROCKET"].label"#),
                Some(json!("Renamed")),
            )],
            &widget_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::NoMatchingValue);

        // Exact-case "code" plus wrong-case "label" (case-insensitive) must still match --
        // proves the AND's right branch still folds.
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[code eq "ABC" and label eq "SPROCKET"].label"#),
                Some(json!("Renamed")),
            )],
            &widget_schema(),
        )
        .unwrap();
        assert_eq!(result["widgets"][0]["label"], "Renamed");
    }

    // --- Precise bracket-filtered immutable add-when-absent (issue #2) ---

    fn group_with_two_members() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins",
            "members": [
                {"value": "u-1", "type": "User", "display": "Alice"},
                {"value": "u-2", "type": "User"}
            ]
        })
    }

    #[test]
    fn schema_allows_add_on_an_immutable_sub_attribute_when_the_matched_entry_has_no_prior_value() {
        // u-2 has no `display` set yet -- RFC 7644 3.5.2's add-exception should allow it,
        // even though the top-level `members` array has other entries (u-1) that do have
        // `display` set. The old conservative check rejected this.
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some(r#"members[value eq "u-2"].display"#),
                Some(json!("Bob")),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        let members = result["members"].as_array().unwrap();
        assert_eq!(members[1]["display"], "Bob");
        // u-1's existing display is untouched.
        assert_eq!(members[0]["display"], "Alice");
    }

    #[test]
    fn schema_rejects_add_on_an_immutable_sub_attribute_when_the_matched_entry_already_has_a_value()
    {
        // u-1 already has `display` set -- the add-exception does not apply to it
        // specifically, even though a different entry (u-2) in the same array doesn't.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some(r#"members[value eq "u-1"].display"#),
                Some(json!("Alicia")),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("members".to_string()));
    }

    #[test]
    fn schema_reports_no_matching_value_not_immutable_for_an_add_whose_filter_matches_nothing() {
        // A filter matching zero entries has, vacuously, no previous value to protect --
        // the real problem is "no target," which the existing array-matching loop already
        // reports as NoMatchingValue once check_mutability lets the request through.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some(r#"members[value eq "nonexistent"].display"#),
                Some(json!("Nobody")),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::NoMatchingValue);
    }

    #[test]
    fn schema_allows_add_on_immutable_sub_attribute_matched_by_a_compound_filter() {
        // Adversarial: attribute_has_existing_value's evaluate() call must handle a
        // compound (AND) value_filter identically to the real mutation loop's, not just
        // a bare Filter::Compare -- otherwise the mutability gate and the actual write
        // could resolve a different matched entry for anything beyond a single clause.
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some(r#"members[value eq "u-2" and type eq "User"].display"#),
                Some(json!("Bob")),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        assert_eq!(result["members"][1]["display"], "Bob");
    }

    /// A synthetic schema exercising an immutable sub-attribute under a *single-valued*
    /// complex attribute (no real schema in this crate has one: `user_schema()`'s `name.*`
    /// are all readWrite; only `group.members[].*` are immutable, and those are reached
    /// via a bracket filter, not a plain dotted path). Proves `check_mutability`'s
    /// "had no previous value" check is precise for the dotted-path case too, not just
    /// the bracket-filtered one.
    fn badge_schema() -> SchemaResource {
        SchemaResource {
            schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Badge".to_string(),
            name: Some("Badge".to_string()),
            description: None,
            attributes: vec![crate::discovery::AttributeDefinition {
                sub_attributes: vec![
                    crate::discovery::AttributeDefinition::simple(
                        "level",
                        "string",
                        "Immutable badge level.",
                        "immutable",
                    ),
                    crate::discovery::AttributeDefinition::simple(
                        "note",
                        "string",
                        "Freely editable note.",
                        "readWrite",
                    ),
                ],
                ..crate::discovery::AttributeDefinition::simple(
                    "profile",
                    "complex",
                    "The user's profile.",
                    "readWrite",
                )
            }],
        }
    }

    #[test]
    fn schema_allows_add_on_a_dotted_immutable_sub_attribute_absent_from_an_existing_parent_object()
    {
        // `profile` already exists (with `note` set) but `profile.level` specifically does
        // not -- the add-exception must key off `level`'s own presence, not `profile`'s.
        let resource = json!({
            "schemas": ["urn:test:Badge"],
            "id": "b-1",
            "profile": {"note": "hello"}
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Add, Some("profile.level"), Some(json!("gold")))],
            &badge_schema(),
        )
        .unwrap();
        assert_eq!(result["profile"]["level"], "gold");
        assert_eq!(result["profile"]["note"], "hello");
    }

    #[test]
    fn schema_rejects_add_on_a_dotted_immutable_sub_attribute_that_already_has_a_value() {
        let resource = json!({
            "schemas": ["urn:test:Badge"],
            "id": "b-1",
            "profile": {"level": "silver"}
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Add, Some("profile.level"), Some(json!("gold")))],
            &badge_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("profile".to_string()));
    }

    // --- Adversarial malformed-input safety (security-audit control test) ---

    #[test]
    fn immutable_add_check_never_panics_on_a_non_object_array_entry() {
        // A malformed/adversarial resource where a "members" entry is a bare string
        // instead of an object -- attribute_has_existing_value's entry.get(sub) and
        // evaluate()'s resolve_scalar() must degrade to "no match"/"absent", never index
        // or unwrap into a shape that isn't there. Asserting Result (not a panic) is the
        // actual security property: a PATCH-processing library panicking on attacker
        // input can take down the caller's whole request-handling thread.
        let resource = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins",
            "members": ["not-an-object", 42, null, {"value": "u-1"}]
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some(r#"members[value eq "u-1"].display"#),
                Some(json!("Bob")),
            )],
            &crate::group::group_schema(),
        );
        // Whatever the outcome, it must be a typed Result, not a panic -- reaching this
        // assertion at all is the control test passing.
        assert!(result.is_ok() || result.is_err());
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

    // --- Schema-typed PATCH value coercion (real-IdP conformance, GitHub issue #1) ---
    //
    // mitodl/keycloak-scim (Apache-2.0, actively maintained -- see PR description for the
    // full evaluation) builds its PATCH `active` op as
    // `.path("active").op(PatchOp.REPLACE).value(active.toString())`
    // (`UserAdapter.toPatchBuilder()`, pinned commit
    // eec8ecd14971886f0d00f3dc688b587c3002f252) -- Java `Boolean#toString()` is the JSON
    // *string* `"true"`/`"false"`, not RFC 7643's native JSON boolean for a
    // `boolean`-typed attribute. A strict RFC-literal apply_patch_with_schema would store
    // that string verbatim, silently corrupting the resource's type shape (a later
    // `serde_json::from_value::<User>` would then fail on a field the SCIM server itself
    // accepted). Coercion is deliberately narrow: only `apply_patch_with_schema` (which
    // has a declared type to coerce *to*) does this, only for exact canonical string
    // forms of the target type, and only boolean/integer/decimal -- anything else (wrong
    // case, leading zeros, whitespace, non-numeric) passes through unchanged rather than
    // being guessed at.

    fn numeric_schema() -> SchemaResource {
        SchemaResource {
            schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Numeric".to_string(),
            name: Some("Numeric".to_string()),
            description: None,
            attributes: vec![
                crate::discovery::AttributeDefinition::simple(
                    "loginCount",
                    "integer",
                    "Number of logins.",
                    "readWrite",
                ),
                crate::discovery::AttributeDefinition::simple(
                    "score",
                    "decimal",
                    "A decimal score.",
                    "readWrite",
                ),
            ],
        }
    }

    fn numeric_resource() -> Value {
        json!({
            "schemas": ["urn:test:Numeric"],
            "id": "n-1",
            "loginCount": 3,
            "score": 1.5
        })
    }

    #[test]
    fn schema_coerces_a_string_true_to_boolean_for_a_boolean_typed_attribute() {
        let resource = user_with_emails();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!("true")))],
            &crate::user::user_schema(),
        )
        .unwrap();
        assert_eq!(result["active"], json!(true));
    }

    #[test]
    fn schema_coerces_a_string_false_to_boolean_for_a_boolean_typed_attribute() {
        let resource = user_with_emails();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!("false")))],
            &crate::user::user_schema(),
        )
        .unwrap();
        assert_eq!(result["active"], json!(false));
    }

    #[test]
    fn unscoped_apply_patch_never_coerces_since_it_has_no_schema_type_to_consult() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!("true")))],
        )
        .unwrap();
        // Stored verbatim as the string it was given -- apply_patch documents (module
        // doc, src/patch.rs) that schema-driven behavior is additive, never assumed.
        assert_eq!(result["active"], json!("true"));
    }

    #[test]
    fn schema_coercion_rejects_a_wrong_case_boolean_string_as_a_near_miss() {
        // "True" is not the canonical lowercase JSON/Java Boolean#toString() form --
        // coercing it would be guessing, not accommodating an evidenced real sender.
        let resource = user_with_emails();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!("True")))],
            &crate::user::user_schema(),
        )
        .unwrap();
        assert_eq!(result["active"], json!("True"));
    }

    #[test]
    fn schema_coerces_a_clean_integer_string_for_an_integer_typed_attribute() {
        let resource = numeric_resource();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("loginCount"), Some(json!("42")))],
            &numeric_schema(),
        )
        .unwrap();
        assert_eq!(result["loginCount"], json!(42));
    }

    #[test]
    fn schema_coercion_rejects_a_leading_zero_integer_string_as_a_near_miss() {
        // "007" round-trips through i64::parse but isn't canonical JSON integer text --
        // coercing it would silently normalize a value the sender may not have intended
        // as a number at all (e.g. a zero-padded code).
        let resource = numeric_resource();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("loginCount"), Some(json!("007")))],
            &numeric_schema(),
        )
        .unwrap();
        assert_eq!(result["loginCount"], json!("007"));
    }

    #[test]
    fn schema_coercion_rejects_a_whitespace_padded_integer_string_as_a_near_miss() {
        let resource = numeric_resource();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("loginCount"), Some(json!(" 42")))],
            &numeric_schema(),
        )
        .unwrap();
        assert_eq!(result["loginCount"], json!(" 42"));
    }

    #[test]
    fn schema_coerces_a_clean_decimal_string_for_a_decimal_typed_attribute() {
        let resource = numeric_resource();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("score"), Some(json!("2.5")))],
            &numeric_schema(),
        )
        .unwrap();
        assert_eq!(result["score"], json!(2.5));
    }

    #[test]
    fn schema_coercion_rejects_a_non_finite_decimal_string_as_a_near_miss() {
        // "Infinity"/"NaN" parse via f64::from_str but aren't representable in JSON
        // (RFC 8259 4) -- must never be coerced into a Number.
        let resource = numeric_resource();
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Replace, Some("score"), Some(json!("Infinity")))],
            &numeric_schema(),
        )
        .unwrap();
        assert_eq!(result["score"], json!("Infinity"));
    }

    #[test]
    fn schema_coercion_leaves_non_numeric_strings_on_string_typed_attributes_untouched() {
        let resource = user_with_emails();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("displayName"),
                Some(json!("Babs")),
            )],
            &crate::user::user_schema(),
        )
        .unwrap();
        assert_eq!(result["displayName"], json!("Babs"));
    }

    #[test]
    fn schema_coerces_a_bracket_filtered_sub_attribute_value_too() {
        // The same coercion applies wherever apply_add_or_replace resolves an attribute
        // definition via schema, not just the plain top-level-path case -- exercised here
        // against Group.members[].value's bracket-filter-matched-entry replace path (using
        // a locally-declared boolean sub-attribute added onto the Group fixture schema
        // rather than a real RFC 7643 one, since Group has no multi-valued boolean
        // sub-attribute of its own).
        let mut schema = crate::group::group_schema();
        let members = schema
            .attributes
            .iter_mut()
            .find(|a| a.name == "members")
            .unwrap();
        members
            .sub_attributes
            .push(crate::discovery::AttributeDefinition::simple(
                "primary",
                "boolean",
                "Whether this is the primary membership record.",
                "readWrite",
            ));
        let resource = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins",
            "members": [{"value": "u-1", "type": "User", "primary": false}]
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[value eq "u-1"].primary"#),
                Some(json!("true")),
            )],
            &schema,
        )
        .unwrap();
        assert_eq!(result["members"][0]["primary"], json!(true));
    }
}
