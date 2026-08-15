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
    /// The `path` carried a full schema URN prefix (RFC 7644 §3.5.2's `attrPath = [URI
    /// ":"] ATTRNAME`, e.g. `urn:ietf:params:scim:schemas:extension:enterprise:2.0:
    /// User:employeeNumber`). Every mutation and mutability check in this module
    /// resolves a path via `attr_path.attr_name` against the *top level* of the
    /// resource object -- but an extension attribute reached through a schema-qualified
    /// path actually lives nested under a key equal to the full schema URN, not
    /// `resource["employeeNumber"]`. Resolving that correctly is real routing logic
    /// this module does not implement, so a schema-qualified path is rejected outright
    /// before any mutation happens.
    SchemaQualifiedPath(String),
    /// [`apply_patch_with_schema`] only: the path targets an attribute whose schema
    /// mutability is `readOnly`, or `immutable` with an existing value already present.
    ImmutableOrReadOnly(String),
    /// [`apply_patch_with_schema`] only: `attr_def.mutability` on the schema passed in
    /// is not one of RFC 7643 §2.2's four canonical tokens (`readOnly`, `readWrite`,
    /// `immutable`, `writeOnly`) -- a typo'd, mis-cased, or whitespace-padded value in a
    /// hand-authored or hand-edited schema document. This is a malformed schema, not a
    /// malformed request, but it is surfaced as a hard error rather than silently
    /// treated as the most permissive `readWrite`.
    InvalidSchemaMutability {
        attr_name: String,
        mutability: String,
    },
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
            PatchError::SchemaQualifiedPath(_) => ScimType::InvalidPath,
            PatchError::ImmutableOrReadOnly(_) => ScimType::Mutability,
            PatchError::InvalidSchemaMutability { .. } => ScimType::InvalidValue,
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
    // Snapshotted once, before any operation runs, and threaded through every
    // mutability check below as the sole source of "does this attribute currently
    // have a value" (RFC 7644 3.5.2's immutable add-exception). Without this, an
    // earlier op in the *same* multi-op request could Remove an immutable value and a
    // later op could then Add it back with different content: each op's mutability
    // check only ever consulted the live, already-partially-mutated `working` value,
    // so the re-add looked like a genuine first-time addition (no previous value) --
    // completely defeating "immutable" via an ordinary two-operation PATCH body,
    // instead of requiring a whole separate PATCH request per RFC 7644's own atomic
    // per-request semantics.
    let original = resource.clone();
    let mut working = resource.clone();
    for operation in operations {
        apply_one(&mut working, &original, operation, schema)?;
    }
    Ok(working)
}

fn apply_one(
    resource: &mut Value,
    original: &Value,
    operation: &PatchOperation,
    schema: Option<&SchemaResource>,
) -> Result<(), PatchError> {
    match operation.op {
        PatchOp::Remove => apply_remove(resource, original, operation, schema),
        PatchOp::Add => apply_add_or_replace(resource, original, operation, false, schema),
        PatchOp::Replace => apply_add_or_replace(resource, original, operation, true, schema),
    }
}

/// Ranks RFC 7643 §2.2 mutability tokens by how much they restrict a PATCH write:
/// `ReadOnly` is strictest (never writable), `Immutable` next (writable exactly once, via
/// `add`, only while unset), and `ReadWrite`/`WriteOnly` are the least strict -- there's no
/// meaningful ordering between those last two since [`check_mutability`]'s own match on
/// [`Mutability`] treats them identically (`Ok(())` unconditionally regardless of which).
fn mutability_rank(m: Mutability) -> u8 {
    match m {
        Mutability::ReadOnly => 2,
        Mutability::Immutable => 1,
        Mutability::ReadWrite | Mutability::WriteOnly => 0,
    }
}

/// Whether `a` is at least as strict as `b`, by [`mutability_rank`] -- i.e. whether `a`
/// is the side that "wins" when both apply to the same write. [`stricter`] returns the
/// resulting [`Mutability`]; this returns *which side* that came from, since
/// [`check_mutability`] needs both: which attribute (a sub-attribute or its parent) is
/// actually the reason a write is protected also decides which attribute's existing
/// value the immutable add-exception must consult (see [`check_mutability`]'s own doc
/// comment on `existing_value_sub_attr`).
fn at_least_as_strict(a: Mutability, b: Mutability) -> bool {
    mutability_rank(a) >= mutability_rank(b)
}

/// The effective mutability when two apply to the same write: the stricter of the two,
/// by [`mutability_rank`]. Used by [`check_mutability`] to combine a sub-attribute's own
/// mutability with its parent's, so a readOnly/immutable parent's protection is a floor a
/// looser sub-attribute can never lower -- never a ceiling that loosens an
/// explicitly-stricter sub-attribute down to a looser parent's (see GitHub issue #12).
fn stricter(a: Mutability, b: Mutability) -> Mutability {
    if at_least_as_strict(a, b) { a } else { b }
}

/// RFC 7644 §3.5.2: "a client MUST NOT modify an attribute that has mutability
/// 'readOnly' or 'immutable'... \[but\] MAY 'add' a value to an 'immutable' attribute if
/// the attribute had no previous value" -- quoted verbatim since the "add exception"
/// is easy to get subtly wrong (it's `add` specifically, not `add` or `replace`, and only
/// when no previous value exists). `replace`/`remove` on an immutable attribute are
/// rejected unconditionally regardless of `value_filter`, so `has_existing` below is only
/// ever actually evaluated for `op == PatchOp::Add`.
///
/// For a sub-attribute path (`sub_attr: Some`), the mutability actually enforced is the
/// stricter (via [`stricter`]) of the sub-attribute's own and its parent complex/
/// multi-valued attribute's own -- [`discovery::find_attribute`] alone only ever returns
/// the sub-attribute's own definition, so without this, a readOnly/immutable parent (e.g.
/// `User.groups`) gave no protection at all to a sub-attribute the schema left unmarked
/// (defaulting to readWrite per RFC 7643 §2.2), regardless of the parent's own mutability.
/// This crate's own shipped schemas don't have a live gap here (every readOnly/immutable
/// complex attribute they declare has every sub-attribute hand-annotated to match), but
/// [`apply_patch_with_schema`]'s own doc comment explicitly invites a caller to
/// hand-assemble/merge a schema (e.g. for an extension), and nothing stopped a future
/// schema -- shipped or caller-supplied -- from reopening this exact gap. See GitHub
/// issue #12.
///
/// Cascading *which* mutability applies isn't sufficient on its own: the immutable
/// add-exception's "had no previous value" check (below, via
/// [`attribute_has_existing_value`]) must also be scoped to whichever attribute is
/// actually doing the protecting. `existing_value_sub_attr` is `sub_attr` unchanged when
/// the sub-attribute's own mutability is at least as strict as its parent's (preserving
/// this crate's established per-sub-attribute precision, e.g. `Group.members[].display`
/// -- an entry that already exists but never had `display` set may still receive it), or
/// `None` (the parent as a whole) when the parent's mutability is what cascaded in.
/// Getting this wrong doesn't just misclassify severity: cascading `Immutable` from the
/// parent while still asking whether *this never-before-set sub-attribute* has a
/// previous value let an attacker add previously-unset fields to an already-existing
/// immutable complex value one field at a time, forever, since each individual field
/// really was unset in isolation -- the parent's own existing value never entered the
/// check at all (found by this fix's own adversarial confirmation pass; see this
/// module's tests for the `_when_the_entry_already_exists` and
/// `_when_the_parent_already_has_a_value` regression cases).
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
    let mutability = Mutability::from_rfc_str(&attr_def.mutability).ok_or_else(|| {
        PatchError::InvalidSchemaMutability {
            attr_name: attr_name.to_string(),
            mutability: attr_def.mutability.clone(),
        }
    })?;
    let (mutability, existing_value_sub_attr) = match sub_attr {
        None => (mutability, sub_attr),
        Some(_) => match discovery::find_attribute(schema, attr_name, None) {
            // Structurally always `Some` here: `find_attribute` only ever resolves a
            // sub-attribute by first resolving its parent by `attr_name` (see its own
            // doc), so `attr_def` having resolved above already implies this does too.
            // Falling back to the sub-attribute's own mutability/scope rather than a
            // `panic!`/`.expect` keeps this function total even if that invariant is
            // ever violated.
            Some(parent_def) => {
                let parent_mutability = Mutability::from_rfc_str(&parent_def.mutability)
                    .ok_or_else(|| PatchError::InvalidSchemaMutability {
                        attr_name: attr_name.to_string(),
                        mutability: parent_def.mutability.clone(),
                    })?;
                let existing_value_sub_attr = if at_least_as_strict(parent_mutability, mutability) {
                    None
                } else {
                    sub_attr
                };
                (
                    stricter(parent_mutability, mutability),
                    existing_value_sub_attr,
                )
            }
            None => (mutability, sub_attr),
        },
    };
    match mutability {
        Mutability::ReadOnly => Err(PatchError::ImmutableOrReadOnly(attr_name.to_string())),
        Mutability::Immutable => {
            let has_existing = op != PatchOp::Add
                || attribute_has_existing_value(
                    resource,
                    attr_name,
                    existing_value_sub_attr,
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

/// Rejects a schema-qualified `path` (see [`PatchError::SchemaQualifiedPath`]'s doc for
/// why) before any mutation or mutability check runs.
fn reject_schema_qualified_path(path: &filter::PatchPath) -> Result<(), PatchError> {
    if let Some(uri) = &path.attr_path.schema_uri {
        return Err(PatchError::SchemaQualifiedPath(format!(
            "{uri}:{}",
            path.attr_path.attr_name
        )));
    }
    Ok(())
}

fn apply_remove(
    resource: &mut Value,
    original: &Value,
    operation: &PatchOperation,
    schema: Option<&SchemaResource>,
) -> Result<(), PatchError> {
    let Some(path_str) = &operation.path else {
        return Err(PatchError::NoTarget);
    };
    let path = filter::parse_patch_path(path_str)?;
    reject_schema_qualified_path(&path)?;
    if is_protected(&path.attr_path.attr_name) {
        return Err(PatchError::Protected(path.attr_path.attr_name.clone()));
    }
    if let Some(schema) = schema {
        check_mutability(
            schema,
            original,
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

/// Guards a single entry of a multi-valued complex attribute (e.g. `Group`'s `members`,
/// whose `value`/`$ref`/`display` sub-attributes are `immutable` per RFC 7643 §4.2 while
/// `members` itself is `readWrite`) against silently overwriting an existing entry's
/// immutable/readOnly sub-attribute values. `check_mutability` called with `sub_attr:
/// None` only validates the top-level attribute's own mutability and never consults
/// `attr_def.sub_attributes`, so a whole-entry write sailed straight past every
/// sub-attribute's own mutability and overwrote it verbatim.
///
/// Shared by every call site that can replace/append a whole entry of a multi-valued
/// complex attribute -- a bracket-filtered `path` matching one entry, or a no-path/
/// top-level `path` array-replace/append matching zero or more entries by `value` (see
/// [`check_multivalued_complex_replace_mutability`]) -- so none of them can be the one
/// call site that forgets the check.
fn check_entry_immutable_sub_attrs(
    attr_name: &str,
    attr_def: &discovery::AttributeDefinition,
    existing_entry: &Value,
    new_entry: &Value,
) -> Result<(), PatchError> {
    let Some(new_obj) = new_entry.as_object() else {
        return Ok(());
    };
    // Iterate the *schema's* immutable/readOnly sub-attributes, not new_entry's keys --
    // every call site here whole-replaces the matched entry object rather than merging
    // it, so a replacement that simply omits an immutable/readOnly sub-attribute (rather
    // than supplying an explicit conflicting value) would otherwise sail past a
    // keys-of-new_entry loop uncaught and silently erase that value on write.
    for sub_def in &attr_def.sub_attributes {
        let Some(mutability) = Mutability::from_rfc_str(&sub_def.mutability) else {
            continue;
        };
        if !matches!(mutability, Mutability::Immutable | Mutability::ReadOnly) {
            continue;
        }
        let existing_sub_value = existing_entry.get(&sub_def.name);
        let has_existing_value = existing_sub_value.is_some_and(|v| !matches!(v, Value::Null));
        if !has_existing_value {
            continue;
        }
        // Every key in the attacker-supplied entry that case-insensitively matches this
        // sub-attribute's name must agree with the existing value -- not just whichever
        // one a `.find()` happens to pick first. JSON permits multiple keys that differ
        // only by case to coexist in the same object (serde_json's Map, backed by a
        // BTreeMap here since this crate doesn't enable the preserve_order feature,
        // never merges them), and this whole-entry write copies every key verbatim into
        // the stored resource. Picking just one case-variant to check let an attacker
        // pair a decoy key holding a value equal to the existing one (so the check
        // passes) with the real, canonical-case key holding a forged value (which is
        // what a typed downstream consumer's case-sensitive serde deserialization, or
        // any other code path that resolves the canonical key, would actually read) --
        // completely defeating immutable/readOnly enforcement in a single PATCH op. An
        // entry that doesn't unambiguously agree on this value across every case-variant
        // key present is itself adversarial-shaped input, not something safe to resolve
        // with a single arbitrary tie-break.
        let matching_values: Vec<&Value> = new_obj
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(&sub_def.name))
            .map(|(_, v)| v)
            .collect();
        let all_candidates_agree = !matching_values.is_empty()
            && matching_values
                .iter()
                .all(|v| Some(*v) == existing_sub_value);
        if !all_candidates_agree {
            return Err(PatchError::ImmutableOrReadOnly(format!(
                "{attr_name}[].{}",
                sub_def.name
            )));
        }
    }
    Ok(())
}

/// Whether `attr_def`'s `value` sub-attribute is declared `caseExact` (RFC 7643 §2.2's
/// default is `false`). Shared by every place in this file that must correlate an entry
/// of a multi-valued complex attribute to its counterpart in a different array snapshot
/// by their `value` sub-attribute -- this crate's own shipped schemas (e.g. Group.
/// members[].value) leave it at the default, so an exact case-sensitive comparison would
/// treat a case-varied `value` (e.g. "U-1" vs stored "u-1") as an unrelated entry.
fn value_sub_attr_is_case_exact(attr_def: &discovery::AttributeDefinition) -> bool {
    attr_def
        .sub_attributes
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case("value"))
        .is_some_and(|s| s.case_exact)
}

/// Finds the entry in `entries` whose `value` sub-attribute matches `key`, per
/// `attr_def`'s declared `caseExact` for that sub-attribute (see
/// [`value_sub_attr_is_case_exact`]) when both sides are strings, or exact `Value`
/// equality otherwise. Centralizes this file's one identity convention for
/// multi-valued complex attribute entries so every caller correlates entries the same
/// way, rather than each re-implementing its own match.
///
/// `key` is the raw `Value`, not a pre-extracted `&str`: an earlier version of this
/// function only matched when BOTH sides' `value` sub-attribute were JSON strings
/// (`.and_then(Value::as_str)`), so a `value` written as a number, bool, or `null` --
/// this crate never validates the sub-attribute's declared `type` for a whole-entry
/// array write, unlike scalar attributes via `coerce_to_attribute_type` -- could never
/// be correlated to itself again, on this or any future request. Since correlation
/// failure means "treat as a genuine new entry, no immutability check runs at all" (RFC
/// 7644 3.5.2's add-exception), that silently and *permanently* exempted such an entry
/// from all immutable/readOnly protection: an attacker could plant a
/// `{"value": 42, ...}` entry once, then freely rewrite its other sub-attributes
/// forever, since `42` (a `Value::Number`) never matched via `.as_str()` on either side.
/// Comparing the raw `Value` directly closes this for every JSON type uniformly.
fn find_entry_by_value<'a>(
    entries: &'a [Value],
    attr_def: &discovery::AttributeDefinition,
    key: &Value,
) -> Option<&'a Value> {
    let case_exact = value_sub_attr_is_case_exact(attr_def);
    entries.iter().find(|e| {
        let Some(existing_key) = e.get("value") else {
            return false;
        };
        match (existing_key, key) {
            (Value::String(a), Value::String(b)) => {
                if case_exact {
                    a == b
                } else {
                    a.eq_ignore_ascii_case(b)
                }
            }
            (a, b) => a == b,
        }
    })
}

/// Guards a whole-attribute replace/add of a complex attribute (single-valued or
/// multi-valued) against silently overwriting an existing value's immutable/readOnly
/// sub-attribute values (see [`check_entry_immutable_sub_attrs`] for why this check
/// exists at all).
///
/// Scoped to only the case that matters: `attr_def.sub_attributes` non-empty (a complex
/// attribute). Scalar/simple attributes return `Ok` immediately.
///
/// A single-valued complex attribute (e.g. `manager`) has exactly one existing value to
/// check the new one against -- there's no array to correlate entries within, and no
/// [`find_entry_by_value`] lookup by `value` sub-attribute makes sense (a bare JSON
/// object has no per-entry identity to match on). Checking `attr_def.multi_valued`
/// rather than merely whether `existing` happens to already be an array matters: an
/// absent-or-null existing value for a multi-valued attribute must still go through the
/// array-correlation branch below (there's simply nothing to match, so every new entry
/// is a genuine addition), not be misrouted into the single-valued branch.
///
/// For a multi-valued attribute, an existing entry is matched to a new one by their
/// `value` sub-attribute (see [`find_entry_by_value`]). A new entry with no matching
/// existing entry is a genuine addition, covered by RFC 7644 §3.5.2's add-exception, not
/// this check.
fn check_multivalued_complex_replace_mutability(
    attr_name: &str,
    attr_def: &discovery::AttributeDefinition,
    existing: Option<&Value>,
    new_value: &Value,
) -> Result<(), PatchError> {
    if attr_def.sub_attributes.is_empty() {
        return Ok(());
    }
    if !attr_def.multi_valued {
        // Single-valued complex attribute: check_entry_immutable_sub_attrs already
        // handles "no existing value" (has_existing_value is false per sub-attribute)
        // and "new_value isn't an object" (returns Ok) correctly on its own, so this
        // branch can call it unconditionally rather than needing its own early-outs.
        let existing_entry = existing.unwrap_or(&Value::Null);
        return check_entry_immutable_sub_attrs(attr_name, attr_def, existing_entry, new_value);
    }
    // Mirrors apply_add_or_replace's own handling of a merged/appended value
    // (Value::Array(items) => append each item, single => push it as one new entry): a
    // bare (non-array) object is a valid single-entry Add there, so it must go through
    // the same immutable-collision check as a one-element array, not silently bypass it
    // via `new_value.as_array()` returning None.
    let new_entries: Vec<&Value> = match new_value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let existing_entries = existing.and_then(Value::as_array);

    for new_entry in new_entries {
        let Some(new_obj) = new_entry.as_object() else {
            continue;
        };
        // The correlation key is resolved case-insensitively, matching every other
        // place this module resolves an attribute/sub-attribute name (RFC 7643 2.2:
        // names are case-insensitive) -- an exact-case-only `new_obj.get("value")`
        // let an attacker spell the key as e.g. "Value", missing this lookup entirely
        // and skipping check_entry_immutable_sub_attrs for that entry altogether,
        // silently forging any of its immutable/readOnly sub-attributes (display,
        // $ref, type) unchecked. Every case-variant "value"-named key present is
        // tried against find_entry_by_value: if ANY of them correlates to an existing
        // entry, the immutability check runs against that baseline.
        let Some(existing_entry) = existing_entries.and_then(|entries| {
            new_obj
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("value"))
                .find_map(|(_, new_key)| find_entry_by_value(entries, attr_def, new_key))
        }) else {
            continue;
        };
        check_entry_immutable_sub_attrs(attr_name, attr_def, existing_entry, new_entry)?;
    }
    Ok(())
}

fn apply_add_or_replace(
    resource: &mut Value,
    original: &Value,
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
        for (key, new_val) in incoming {
            if is_protected(key) {
                return Err(PatchError::Protected(key.clone()));
            }
            if let Some(schema) = schema {
                check_mutability(schema, original, key, None, None, op_kind)?;
                if let Some(attr_def) = discovery::find_attribute(schema, key, None) {
                    check_multivalued_complex_replace_mutability(
                        key,
                        attr_def,
                        original.get(key),
                        new_val,
                    )?;
                }
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
    reject_schema_qualified_path(&path)?;
    if is_protected(&path.attr_path.attr_name) {
        return Err(PatchError::Protected(path.attr_path.attr_name.clone()));
    }
    if let Some(schema) = schema {
        check_mutability(
            schema,
            original,
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
            let attr_def =
                schema.and_then(|s| discovery::find_attribute(s, &path.attr_path.attr_name, None));
            let value = match attr_def {
                Some(attr_def) => coerce_to_attribute_type(value, attr_def),
                None => value,
            };
            // Checked once, ahead of both the append and whole-replace branches below --
            // both can silently overwrite/duplicate an existing entry's immutable/readOnly
            // sub-attribute values (RFC 7644 3.5.2's add-exception only excuses a genuine
            // new entry, not one whose `value` collides with an entry that already exists).
            if let Some(attr_def) = attr_def {
                check_multivalued_complex_replace_mutability(
                    &path.attr_path.attr_name,
                    attr_def,
                    original.get(&path.attr_path.attr_name),
                    &value,
                )?;
            }
            let appends_onto_existing_array =
                !is_replace && matches!(root.get(&path.attr_path.attr_name), Some(Value::Array(_)));
            if appends_onto_existing_array {
                let arr = root
                    .get_mut(&path.attr_path.attr_name)
                    .and_then(Value::as_array_mut)
                    .expect("matched Value::Array above");
                match value {
                    Value::Array(mut new_items) => arr.append(&mut new_items),
                    single => arr.push(single),
                }
            } else {
                root.insert(path.attr_path.attr_name.clone(), value);
            }
            Ok(())
        }
        (_, Some(value_filter)) => {
            let attr_def =
                schema.and_then(|s| discovery::find_attribute(s, &path.attr_path.attr_name, None));
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
                        if let Some(attr_def) = attr_def {
                            // Consult the pre-request snapshot's matching entry, not the
                            // live (possibly already mutated by an earlier op in this
                            // same request) one -- for consistency with every other
                            // mutability check in this function, all of which consult
                            // `original` for exactly this reason. Correlated by identity
                            // (this entry's own `value`, via find_entry_by_value), NOT
                            // by re-running `value_filter` against `original` -- a
                            // non-unique filter (e.g. `type eq "User"`) can match more
                            // than one live entry in this same loop, and re-running the
                            // filter would return the *same first* original match for
                            // every one of them, validating every entry after the first
                            // against an unrelated entry's baseline. Falls back to the
                            // live `entry` only if no corresponding entry exists in the
                            // snapshot at all (e.g. this entry was added earlier in the
                            // same request), matching the add-exception's "no previous
                            // value" case.
                            let original_match = entry.get("value").and_then(|key| {
                                original
                                    .get(&path.attr_path.attr_name)
                                    .and_then(Value::as_array)
                                    .and_then(|arr| find_entry_by_value(arr, attr_def, key))
                            });
                            check_entry_immutable_sub_attrs(
                                &path.attr_path.attr_name,
                                attr_def,
                                original_match.unwrap_or(entry),
                                &value,
                            )?;
                        }
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
    fn stricter_prefers_readonly_over_immutable_regardless_of_argument_order() {
        assert_eq!(
            stricter(Mutability::ReadOnly, Mutability::Immutable),
            Mutability::ReadOnly
        );
        assert_eq!(
            stricter(Mutability::Immutable, Mutability::ReadOnly),
            Mutability::ReadOnly
        );
    }

    #[test]
    fn stricter_prefers_immutable_over_readwrite_and_writeonly_regardless_of_argument_order() {
        assert_eq!(
            stricter(Mutability::Immutable, Mutability::ReadWrite),
            Mutability::Immutable
        );
        assert_eq!(
            stricter(Mutability::ReadWrite, Mutability::Immutable),
            Mutability::Immutable
        );
        assert_eq!(
            stricter(Mutability::Immutable, Mutability::WriteOnly),
            Mutability::Immutable
        );
        assert_eq!(
            stricter(Mutability::WriteOnly, Mutability::Immutable),
            Mutability::Immutable
        );
    }

    #[test]
    fn stricter_treats_readwrite_and_writeonly_as_equally_unrestrictive() {
        // Neither is stricter than the other (check_mutability's own match on Mutability
        // treats both identically), so `stricter` just returns whichever argument came
        // first when ranks tie -- verified both ways so a future rank change that breaks
        // this tie-break symmetry doesn't sneak past silently.
        assert_eq!(
            stricter(Mutability::ReadWrite, Mutability::WriteOnly),
            Mutability::ReadWrite
        );
        assert_eq!(
            stricter(Mutability::WriteOnly, Mutability::ReadWrite),
            Mutability::WriteOnly
        );
    }

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
    fn schema_rejects_replace_targeting_the_groups_type_sub_attribute() {
        // Regression: groups[].type used to be unmodeled in user_schema()'s sub_attributes,
        // so find_attribute returned None and check_mutability's unmodeled-attribute
        // fallback silently allowed the write despite groups being readOnly.
        let mut resource = user_with_emails();
        resource["groups"] = json!([{"value": "g-1", "display": "Admins", "type": "direct"}]);
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"groups[value eq "g-1"].type"#),
                Some(json!("indirect")),
            )],
            &crate::user::user_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn schema_rejects_replace_targeting_the_groups_ref_sub_attribute() {
        // Same class of gap as the groups.type regression above: groups[].$ref was
        // unmodeled in user_schema()'s sub_attributes, so it fell through
        // check_mutability's unmodeled-attribute fallback despite groups being readOnly.
        let mut resource = user_with_emails();
        resource["groups"] = json!([{
            "value": "g-1",
            "display": "Admins",
            "$ref": "https://example.com/v2/Groups/g-1",
        }]);
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"groups[value eq "g-1"].$ref"#),
                Some(json!("https://example.com/v2/Groups/evil")),
            )],
            &crate::user::user_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    /// A synthetic schema exercising the cascade gap GitHub issue #12 describes, which
    /// none of this crate's own shipped schemas (user/group/enterprise-user) actually
    /// have: every readOnly/immutable complex attribute they declare has all of its
    /// sub-attributes hand-annotated readOnly/immutable too, so there's no live example
    /// of a sub-attribute *left at the readWrite default* under a stricter parent. This
    /// is exactly the shape `apply_patch_with_schema`'s own doc comment invites a caller
    /// to hand-assemble (e.g. merging in an extension schema), so it's the realistic
    /// stand-in for "future schema that reopens the cascade bug."
    fn schema_with_unmarked_sub_attrs_under_stricter_parents() -> SchemaResource {
        SchemaResource {
            schemas: vec![discovery::SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:params:scim:schemas:extension:cascade:2.0:Widget".to_string(),
            name: Some("Widget".to_string()),
            description: None,
            attributes: vec![
                discovery::AttributeDefinition {
                    // Single-valued complex, readOnly at the top level; `level` is left
                    // at the readWrite default -- the shape a schema author forgets to
                    // annotate.
                    sub_attributes: vec![discovery::AttributeDefinition::simple(
                        "level",
                        "string",
                        "Left unmarked (readWrite) despite profile being readOnly.",
                        "readWrite",
                    )],
                    ..discovery::AttributeDefinition::simple(
                        "profile",
                        "complex",
                        "A readOnly single-valued complex attribute.",
                        "readOnly",
                    )
                },
                discovery::AttributeDefinition {
                    // Multi-valued complex, immutable at the top level; `label` is left
                    // at the readWrite default the same way.
                    multi_valued: true,
                    sub_attributes: vec![
                        discovery::AttributeDefinition::simple(
                            "value",
                            "string",
                            "Correlates entries.",
                            "readWrite",
                        ),
                        discovery::AttributeDefinition::simple(
                            "label",
                            "string",
                            "Left unmarked (readWrite) despite widgets being immutable.",
                            "readWrite",
                        ),
                    ],
                    ..discovery::AttributeDefinition::simple(
                        "widgets",
                        "complex",
                        "An immutable multi-valued complex attribute.",
                        "immutable",
                    )
                },
                discovery::AttributeDefinition {
                    // Single-valued complex, ordinary readWrite parent -- the baseline
                    // "nothing to cascade" case, must stay allowed.
                    sub_attributes: vec![discovery::AttributeDefinition::simple(
                        "note",
                        "string",
                        "An ordinary readWrite sub-attribute of a readWrite parent.",
                        "readWrite",
                    )],
                    ..discovery::AttributeDefinition::simple(
                        "settings",
                        "complex",
                        "An ordinary readWrite single-valued complex attribute.",
                        "readWrite",
                    )
                },
                discovery::AttributeDefinition {
                    // Malformed mutability string on the *parent*, well-formed on the
                    // child -- previously never inspected on a sub-attribute path.
                    sub_attributes: vec![discovery::AttributeDefinition::simple(
                        "detail",
                        "string",
                        "A well-formed sub-attribute under a malformed parent.",
                        "readWrite",
                    )],
                    ..discovery::AttributeDefinition::simple(
                        "broken",
                        "complex",
                        "A single-valued complex attribute with a typo'd mutability.",
                        "ReadOnly", // wrong case -- RFC 7643 tokens are exact-case.
                    )
                },
                discovery::AttributeDefinition {
                    // Single-valued complex, immutable at the top level; `nickname` is
                    // left at the readWrite default -- reached via a plain dotted path
                    // (unlike `widgets`, which is only reachable via a bracket filter,
                    // and whose matched entry -- by construction of how a bracket-filter
                    // `add` resolves -- always already exists). This is what exercises
                    // the immutable add-exception's "had no previous value" precision on
                    // a path where a genuinely brand-new value is actually reachable.
                    sub_attributes: vec![discovery::AttributeDefinition::simple(
                        "nickname",
                        "string",
                        "Left unmarked (readWrite) despite badge being immutable.",
                        "readWrite",
                    )],
                    ..discovery::AttributeDefinition::simple(
                        "badge",
                        "complex",
                        "An immutable single-valued complex attribute.",
                        "immutable",
                    )
                },
            ],
        }
    }

    #[test]
    fn check_mutability_cascades_a_readonly_parent_to_an_unmarked_sub_attribute() {
        // The core regression this ticket exists for: `profile` is readOnly at the top
        // level, but `profile.level` was left at the readWrite default. Before the fix,
        // find_attribute(schema, "profile", Some("level")) resolved only `level`'s own
        // (readWrite) mutability, so this replace sailed straight through.
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
            "profile": {"level": "user"},
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("profile.level"),
                Some(json!("admin")),
            )],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("profile".to_string()));
    }

    #[test]
    fn check_mutability_cascades_an_immutable_parent_to_an_unmarked_sub_attribute_on_replace() {
        // Same gap via a multi-valued complex attribute and a bracket-filtered path:
        // `widgets` is immutable, `widgets[].label` was left at the readWrite default.
        // `replace` on an immutable attribute is rejected unconditionally regardless of
        // whether a previous value exists (see check_mutability's own doc comment).
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
            "widgets": [{"value": "w-1", "label": "old"}],
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"widgets[value eq "w-1"].label"#),
                Some(json!("new")),
            )],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("widgets".to_string()));
    }

    #[test]
    fn check_mutability_rejects_add_to_a_cascaded_immutable_sub_attribute_when_the_entry_already_exists()
     {
        // Confirmation-pass regression (GitHub issue #12): cascading `widgets`'s
        // immutable mutability down to unmarked `label` isn't enough on its own -- the
        // immutable add-exception's "had no previous value" check must also be scoped to
        // whichever attribute is actually being protected. The `w-1` entry already
        // exists (that's *why* this path resolves to an existing entry at all -- a
        // bracket-filtered add can only ever match an existing entry, see
        // apply_add_or_replace's NoMatchingValue handling), so per the cascaded
        // Immutable protection, `widgets` already has a previous value here and no
        // further field of this entry may be added, even one -- like `label` -- that was
        // itself never set. Before this was fixed, `attribute_has_existing_value` was
        // still asked about `label`'s own (unset) value, not `widgets`'s, and let this
        // through.
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
            "widgets": [{"value": "w-1"}],
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some(r#"widgets[value eq "w-1"].label"#),
                Some(json!("new")),
            )],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("widgets".to_string()));
    }

    #[test]
    fn check_mutability_still_allows_add_to_a_cascaded_immutable_sub_attribute_when_the_parent_is_genuinely_absent()
     {
        // The cascade must still preserve immutable's own add-exception (RFC 7644
        // 3.5.2: "MAY 'add' a value to an 'immutable' attribute if the attribute had no
        // previous value") for a genuinely first-time set -- it should compute an
        // effective mutability of Immutable, not over-tighten to ReadOnly, for an
        // unmarked sub-attribute under an immutable parent. `badge` (reached via a plain
        // dotted path, not a bracket filter) is entirely absent from the resource, so
        // there is no previous value for `badge` -- the parent whose mutability actually
        // governs this write, once cascaded -- to protect.
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Add, Some("badge.nickname"), Some(json!("Ace")))],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap();
        assert_eq!(result["badge"]["nickname"], "Ace");
    }

    #[test]
    fn check_mutability_rejects_add_to_a_cascaded_immutable_sub_attribute_when_the_parent_already_has_a_value()
     {
        // Same confirmation-pass regression as the widgets case above, via the dotted-path
        // shape: `badge` already exists (with no `nickname` set yet), so per the cascaded
        // Immutable protection `badge` already has a previous value and `nickname` -- even
        // though it was itself never set -- may not be added.
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
            "badge": {},
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(PatchOp::Add, Some("badge.nickname"), Some(json!("Ace")))],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("badge".to_string()));
    }

    #[test]
    fn check_mutability_does_not_cascade_when_parent_and_sub_attribute_are_both_readwrite() {
        // Baseline: nothing stricter anywhere in the chain, nothing should be rejected.
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
            "settings": {"note": "old"},
        });
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("settings.note"),
                Some(json!("new")),
            )],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap();
        assert_eq!(result["settings"]["note"], "new");
    }

    #[test]
    fn check_mutability_does_not_cascade_a_stricter_sub_attribute_down_to_a_looser_parent() {
        // The inverse direction must NOT happen: `members[].display` (readWrite parent,
        // immutable sub-attribute per RFC 7643 4.2) must stay immutable -- the cascade
        // is a floor (parent's strictness protects the child), never a ceiling that
        // loosens an explicitly-stricter sub-attribute down to its parent's mutability.
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
                Some(json!("Mallory")),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert_eq!(err, PatchError::ImmutableOrReadOnly("members".to_string()));
    }

    #[test]
    fn check_mutability_surfaces_a_malformed_parent_mutability_on_a_sub_attribute_path() {
        // Previously, a sub-attribute path never even looked at the parent's own
        // mutability string, so a typo there (wrong case, here) went uninspected as long
        // as the sub-attribute's own string parsed fine. The cascade fix means this is
        // now surfaced -- a schema-authoring bug becomes a visible InvalidSchemaMutability
        // error rather than staying silently uninspected.
        let resource = json!({
            "schemas": ["urn:test:params:scim:schemas:extension:cascade:2.0:Widget"],
            "id": "w-1",
            "broken": {"detail": "old"},
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("broken.detail"),
                Some(json!("new")),
            )],
            &schema_with_unmarked_sub_attrs_under_stricter_parents(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::InvalidSchemaMutability { .. }));
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

    fn merged_user_and_enterprise_schema() -> SchemaResource {
        let mut schema = crate::user::user_schema();
        schema
            .attributes
            .extend(crate::user::enterprise_user_schema().attributes);
        schema
    }

    fn user_with_manager() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "u-1",
            "userName": "bjensen",
            "manager": {
                "value": "u-boss",
                "$ref": "https://example.com/v2/Users/u-boss",
                "displayName": "Real Boss"
            }
        })
    }

    #[test]
    fn schema_rejects_a_whole_attribute_replace_that_forges_managers_readonly_displayname() {
        // Regression: check_multivalued_complex_replace_mutability's correlation logic
        // assumed a multi-valued attribute (existing.as_array()), so a single-valued
        // complex attribute's existing object was silently treated as "no existing
        // entries" and check_entry_immutable_sub_attrs never ran -- letting a
        // whole-attribute replace overwrite manager.displayName (readOnly) despite the
        // equivalent dotted-path replace (manager.displayName) correctly rejecting it.
        let resource = user_with_manager();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("manager"),
                Some(json!({
                    "value": "u-boss",
                    "$ref": "https://example.com/v2/Users/u-boss",
                    "displayName": "FORGED BOSS"
                })),
            )],
            &merged_user_and_enterprise_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn schema_rejects_a_no_path_replace_that_forges_managers_readonly_displayname() {
        // Same gap as above, reached via the no-path merge form instead of an explicit
        // "manager" path.
        let resource = user_with_manager();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "manager": {
                        "value": "u-boss",
                        "$ref": "https://example.com/v2/Users/u-boss",
                        "displayName": "FORGED BOSS 2"
                    }
                })),
            )],
            &merged_user_and_enterprise_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn schema_allows_replacing_managers_readwrite_value_and_ref_without_touching_displayname() {
        // A legitimate manager reassignment (value/$ref are readWrite) must still work --
        // the fix above must not over-reject a replace that leaves displayName untouched
        // in the request but equal to the existing stored value.
        let resource = user_with_manager();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("manager"),
                Some(json!({
                    "value": "u-new-boss",
                    "$ref": "https://example.com/v2/Users/u-new-boss",
                    "displayName": "Real Boss"
                })),
            )],
            &merged_user_and_enterprise_schema(),
        )
        .unwrap();
        assert_eq!(result["manager"]["value"], "u-new-boss");
    }

    #[test]
    fn schema_rejects_a_whole_array_replace_correlating_via_a_decoy_cased_value_key() {
        // Regression: check_multivalued_complex_replace_mutability correlated a
        // replacement entry to its existing counterpart via an exact-case-only
        // `new_obj.get("value")`. SCIM attribute names are case-insensitive (RFC 7643
        // 2.2), and every other lookup in this file already accounts for that -- but
        // this one didn't: spelling the correlation key "Value" instead of "value"
        // missed the lookup entirely, so the entry was silently treated as a brand-new
        // addition and check_entry_immutable_sub_attrs never ran for it, letting an
        // attacker forge any immutable sub-attribute (here, display) of an existing
        // entry just by capitalizing the one key this correlation step read.
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
                Some("members"),
                Some(json!([{"Value": "u-1", "type": "User", "display": "MALLORY"}])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            PatchError::ImmutableOrReadOnly("members[].display".to_string())
        );
    }

    #[test]
    fn schema_rejects_replace_targeting_the_members_type_sub_attribute() {
        // Regression: members[].type was unmodeled in group_schema()'s sub_attributes,
        // so find_attribute returned None and check_mutability's unmodeled-attribute
        // fallback silently allowed flipping an existing member's type after creation.
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
                Some(r#"members[value eq "u-1"].type"#),
                Some(json!("Group")),
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

    #[test]
    fn rejects_schema_qualified_path_on_replace_rather_than_writing_a_bogus_top_level_key() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"),
                Some(json!("12345")),
            )],
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::SchemaQualifiedPath(_)));
        assert!(
            resource
                .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber")
                .is_none()
        );
    }

    #[test]
    fn rejects_schema_qualified_path_on_remove() {
        let resource = user_with_emails();
        let err = apply_patch(
            &resource,
            &[op(
                PatchOp::Remove,
                Some("urn:ietf:params:scim:schemas:core:2.0:User:userName"),
                None,
            )],
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::SchemaQualifiedPath(_)));
    }

    #[test]
    fn rejects_schema_qualified_path_with_schema_present_too() {
        let resource = user_with_emails();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("urn:ietf:params:scim:schemas:core:2.0:User:active"),
                Some(json!(false)),
            )],
            &crate::user::user_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::SchemaQualifiedPath(_)));
    }

    #[test]
    fn schema_qualified_path_error_maps_to_invalid_path_scim_type() {
        assert_eq!(
            PatchError::SchemaQualifiedPath("x".to_string()).scim_type(),
            ScimType::InvalidPath
        );
    }

    #[test]
    fn unqualified_path_to_a_core_attribute_is_unaffected_by_the_new_rejection() {
        let resource = user_with_emails();
        let result = apply_patch(
            &resource,
            &[op(PatchOp::Replace, Some("active"), Some(json!(false)))],
        )
        .unwrap();
        assert_eq!(result["active"], false);
    }

    #[test]
    fn schema_rejects_a_malformed_mutability_string_instead_of_treating_it_as_readwrite() {
        let schema = crate::discovery::SchemaResource {
            schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Typo".to_string(),
            name: Some("Typo".to_string()),
            description: None,
            attributes: vec![crate::discovery::AttributeDefinition::simple(
                "secretField",
                "string",
                "Should be locked down, but the schema has a typo.",
                "immutible",
            )],
        };
        let resource = json!({"schemas": ["urn:test:Typo"], "secretField": "original"});
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("secretField"),
                Some(json!("attacker-controlled")),
            )],
            &schema,
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::InvalidSchemaMutability { .. }));
        if let PatchError::InvalidSchemaMutability {
            attr_name,
            mutability,
        } = err
        {
            assert_eq!(attr_name, "secretField");
            assert_eq!(mutability, "immutible");
        }
    }

    #[test]
    fn schema_accepts_the_four_exact_rfc_mutability_tokens() {
        for token in ["readOnly", "readWrite", "immutable", "writeOnly"] {
            let schema = crate::discovery::SchemaResource {
                schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
                id: "urn:test:Tokens".to_string(),
                name: Some("Tokens".to_string()),
                description: None,
                attributes: vec![crate::discovery::AttributeDefinition::simple(
                    "field", "string", "test", token,
                )],
            };
            let resource = json!({"schemas": ["urn:test:Tokens"], "field": "original"});
            let result = apply_patch_with_schema(
                &resource,
                &[op(PatchOp::Replace, Some("field"), Some(json!("new")))],
                &schema,
            );
            if let Err(err) = result {
                assert!(
                    !matches!(err, PatchError::InvalidSchemaMutability { .. }),
                    "token {token:?} should parse cleanly, got {err:?}"
                );
            }
        }
    }

    // --- Whole-array replace of a multi-valued complex attribute must still enforce
    // per-sub-attribute immutability (no-path merge and explicit top-level-path forms) ---

    #[test]
    fn no_path_replace_rejects_a_whole_members_array_that_changes_an_immutable_sub_attribute() {
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "members": [
                        {"value": "u-1", "type": "User", "display": "NOT-ALICE"},
                        {"value": "u-2", "type": "User"}
                    ]
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn no_path_replace_allows_a_whole_members_array_that_only_adds_a_new_member() {
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "members": [
                        {"value": "u-1", "type": "User", "display": "Alice"},
                        {"value": "u-2", "type": "User"},
                        {"value": "u-3", "type": "User", "display": "Carol"}
                    ]
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        let members = result["members"].as_array().unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[2]["value"], "u-3");
    }

    #[test]
    fn no_path_replace_allows_resubmitting_identical_sub_attribute_values() {
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "members": [
                        {"value": "u-1", "type": "User", "display": "Alice"},
                        {"value": "u-2", "type": "User"}
                    ]
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        assert_eq!(result["members"][0]["display"], "Alice");
    }

    #[test]
    fn no_path_replace_rejects_a_whole_members_array_that_silently_omits_an_immutable_sub_attribute()
     {
        // Regression: check_entry_immutable_sub_attrs used to only inspect sub-attribute
        // keys present in the *new* entry, never the schema's own list of
        // immutable/readOnly sub-attributes -- so a replacement entry that simply
        // omitted "display" (rather than supplying a conflicting value for it) was never
        // compared against anything and sailed through, silently erasing the immutable
        // value on write since every call site here whole-replaces the matched entry.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "members": [
                        {"value": "u-1", "type": "User"},
                        {"value": "u-2", "type": "User"}
                    ]
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn explicit_top_level_path_replace_rejects_a_members_array_that_silently_omits_an_immutable_sub_attribute()
     {
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("members"),
                Some(json!([
                    {"value": "u-1", "type": "User"},
                    {"value": "u-2", "type": "User"}
                ])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn bracket_filter_replace_with_no_trailing_sub_attr_rejects_silently_omitting_an_immutable_sub_attribute()
     {
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[value eq "u-1"]"#),
                Some(json!({"value": "u-1", "type": "User"})),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn explicit_top_level_path_replace_rejects_changing_an_existing_members_immutable_value() {
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("members"),
                Some(json!([
                    {"value": "u-1", "type": "User", "display": "Mallory"},
                    {"value": "u-2", "type": "User"}
                ])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn explicit_top_level_path_add_onto_an_existing_array_still_only_appends() {
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some("members"),
                Some(json!([{"value": "u-3", "type": "User", "display": "Carol"}])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        let members = result["members"].as_array().unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0]["display"], "Alice");
    }

    #[test]
    fn explicit_top_level_path_add_rejects_a_duplicate_value_with_forged_immutable_fields() {
        // Regression: an Add (not Replace) onto an existing array took the "append"
        // branch unconditionally and never ran check_multivalued_complex_replace_mutability
        // -- unlike the sibling whole-replace branch. A client could "add" a new members
        // entry whose `value` collides with an existing member's, carrying attacker-chosen
        // immutable sub-attributes (display/$ref/type), and it sailed straight through.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some("members"),
                Some(json!([
                    {"value": "u-1", "type": "User", "display": "MALLORY", "$ref": "https://evil.example/Users/attacker"}
                ])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn explicit_top_level_path_add_rejects_a_bare_object_duplicate_value_with_forged_immutable_fields()
     {
        // Regression: check_multivalued_complex_replace_mutability bailed out silently
        // (`new_value.as_array()` returning None) for a bare (non-array) object value,
        // even though apply_add_or_replace's own append logic explicitly accepts a bare
        // object as a valid single-entry Add (`single => arr.push(single)`). Sending
        // the same forged-fields payload as this suite's array-wrapped sibling test,
        // but without the array brackets, used to skip the immutable check entirely.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Add,
                Some("members"),
                Some(json!(
                    {"value": "u-1", "type": "User", "display": "MALLORY", "$ref": "https://evil.example/Users/attacker"}
                )),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn explicit_top_level_path_replace_rejects_a_case_varied_value_with_forged_immutable_fields() {
        // Regression: matching a new entry to its existing counterpart by the `value`
        // sub-attribute used exact case-sensitive `==`, never consulting the schema's
        // declared caseExact for that sub-attribute (RFC 7643 2.2's default is false,
        // and Group.members[].value is left at that default). A case-varied `value`
        // (e.g. "U-1" for stored "u-1") was treated as an unrelated new entry rather
        // than the same member, so the immutable-field check never ran for it.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("members"),
                Some(json!([
                    {"value": "U-1", "type": "User", "display": "MALLORY"},
                    {"value": "u-2", "type": "User"}
                ])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
    }

    #[test]
    fn a_remove_then_readd_within_one_patch_request_cannot_smuggle_forged_immutable_fields() {
        // Regression, the deepest one found this session: every mutability check's
        // "does this attribute currently have a value" question was answered by
        // consulting the *live, already-partially-mutated* working resource threaded
        // through apply_patch_internal's op loop -- not the resource as it stood
        // before this PATCH request began. That let an earlier op in the SAME
        // multi-op request Remove an immutable member entry, then a later op in the
        // same request Add it back with forged content: since the entry no longer
        // existed in the (live, already-mutated) state the check consulted, it looked
        // exactly like a genuine first-time addition, RFC 7644 3.5.2's own stated
        // exception -- completely defeating "immutable" via an ordinary two-operation
        // PATCH body, not even a whole separate request.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[
                op(PatchOp::Remove, Some(r#"members[value eq "u-1"]"#), None),
                op(
                    PatchOp::Add,
                    Some("members"),
                    Some(json!([{"value": "u-1", "type": "User", "display": "MALLORY"}])),
                ),
            ],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        // The original resource passed in must remain completely untouched: apply_patch
        // never mutates its input, so the caller's own copy is unaffected either way,
        // but this also confirms the rejection happened before either op's effects
        // could be observed by re-inspecting the (unrelated, still-original) input.
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn a_genuine_no_path_readd_after_removal_in_a_separate_request_still_succeeds() {
        // Confirms the fix is scoped correctly: RFC 7644 3.5.2's add-exception must
        // still work across *separate* PATCH requests/calls -- only a resurrection
        // within the *same* request's op sequence is rejected. Two independent
        // apply_patch_with_schema calls, feeding the first's output into the second.
        let resource = group_with_two_members();
        let after_remove = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Remove,
                Some(r#"members[value eq "u-1"]"#),
                None,
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        let after_readd = apply_patch_with_schema(
            &after_remove,
            &[op(
                PatchOp::Add,
                Some("members"),
                Some(json!([{"value": "u-1", "type": "User", "display": "Bob"}])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        let members = after_readd["members"].as_array().unwrap();
        assert!(
            members
                .iter()
                .any(|m| m["value"] == "u-1" && m["display"] == "Bob")
        );
    }

    #[test]
    fn no_path_replace_rejects_a_decoy_cased_key_hiding_a_forged_immutable_value() {
        // Regression, the most severe found this session: check_entry_immutable_sub_attrs
        // resolved the attacker-supplied replacement value with `.find()` over the new
        // entry's own keys matched case-insensitively -- returning only the FIRST
        // case-insensitive match. serde_json::Map (BTreeMap-backed here, no
        // preserve_order feature) never merges keys that differ only by case, and JSON
        // permits both to coexist in the same object. An attacker could pair a decoy
        // "Display" holding a value equal to the existing one (so the immutability check
        // passes) with the real, canonical-case "display" holding a forged value --
        // since the whole entry is written verbatim, both keys land in the stored
        // resource, and any downstream consumer resolving the canonical key (a typed
        // struct's case-sensitive serde deserialization, for one) reads the forged value.
        // This defeated immutable/readOnly enforcement entirely, in a single PATCH op.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "members": [
                        {"value": "u-1", "type": "User", "Display": "Alice", "display": "MALLORY"},
                        {"value": "u-2", "type": "User"}
                    ]
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn no_path_replace_allows_a_genuinely_duplicated_case_variant_key_with_agreeing_values() {
        // The fix must not reject a harmless case: multiple case-variant keys are
        // present but all of them (and the existing value) genuinely agree -- not an
        // attempted change, just redundant duplication.
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({
                    "members": [
                        {"value": "u-1", "type": "User", "Display": "Alice", "display": "Alice"},
                        {"value": "u-2", "type": "User"}
                    ]
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        assert_eq!(result["members"][0]["display"], "Alice");
    }

    #[test]
    fn bracket_filter_replace_rejects_a_decoy_cased_key_hiding_a_forged_immutable_value() {
        // Same regression as the no-path case above, reproduced via the bracket-filter
        // whole-entry-replace call site (a distinct code path calling the same helper).
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[value eq "u-1"]"#),
                Some(json!({
                    "value": "u-1",
                    "type": "User",
                    "Display": "Alice",
                    "display": "MALLORY"
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn bracket_filter_replace_matching_multiple_entries_checks_each_against_its_own_baseline() {
        // Regression, the deepest found this session: when a value-filter matches more
        // than one live array entry (e.g. `type eq "User"`), the immutable-check's
        // baseline for "the matching entry in the original snapshot" was found by
        // *re-running the same filter* against `original` -- which returns the SAME
        // first match every loop iteration, regardless of which live entry is
        // currently being validated. Here the filter matches both u-1 (no `display`
        // set) and u-2 (`display: "Alice"`). The attacker's single replacement payload
        // trivially passes when checked against u-1's baseline (no prior value to
        // conflict with), so the old code -- always consulting u-1's baseline -- let
        // that same payload silently overwrite u-2's real, immutable `display` too,
        // with zero validation against u-2's own true prior value. Correlating each
        // live entry to its own counterpart by identity (its `value`) instead of by
        // re-filtering closes this: u-2 must now be checked against its own baseline.
        let resource = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins",
            "members": [
                {"value": "u-1", "type": "User"},
                {"value": "u-2", "type": "User", "display": "Alice"}
            ]
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[type eq "User"]"#),
                Some(json!({"value": "u-1", "type": "User", "display": "MALLORY"})),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][1]["display"], "Alice");
    }

    #[test]
    fn explicit_top_level_path_replace_rejects_forging_an_entry_whose_value_is_not_a_string() {
        // Regression: find_entry_by_value used to correlate entries by
        // `.get("value").and_then(Value::as_str)` on BOTH sides -- this crate never
        // validates a multi-valued complex attribute's `value` sub-attribute type on a
        // whole-entry write (unlike scalar attributes via coerce_to_attribute_type), so
        // a `value` written as a JSON number (or bool/null) could never be correlated
        // to itself again, on this or any FUTURE request: correlation failure means
        // "genuine new entry, no immutability check runs at all" (RFC 7644 3.5.2's
        // add-exception), silently and permanently exempting that entry from all
        // immutable/readOnly protection. Comparing the raw Value (not just strings)
        // closes this for every JSON type uniformly.
        let resource = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "g-1",
            "displayName": "Admins",
            "members": [{"value": 42, "type": "User", "display": "Alice"}]
        });
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some("members"),
                Some(json!([{"value": 42, "type": "User", "display": "MALLORY"}])),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn bracket_filter_replace_with_no_trailing_sub_attr_rejects_changing_an_immutable_value() {
        // Regression: a bracket-filtered path matching a whole entry with no trailing
        // sub-attribute (e.g. `members[value eq "u-1"]`, as opposed to
        // `members[value eq "u-1"].display`) replaced the matched entry wholesale via
        // `*entry = value.clone()`, never consulting check_entry_immutable_sub_attrs --
        // the same op-type check_multivalued_complex_replace_mutability was written to
        // enforce for the no-path/top-level-path forms, just a call site that got missed.
        let resource = group_with_two_members();
        let err = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[value eq "u-1"]"#),
                Some(json!({
                    "value": "u-1",
                    "type": "User",
                    "display": "MALLORY",
                    "$ref": "https://evil.example/Users/attacker"
                })),
            )],
            &crate::group::group_schema(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ImmutableOrReadOnly(_)));
        assert_eq!(resource["members"][0]["display"], "Alice");
    }

    #[test]
    fn bracket_filter_replace_with_no_trailing_sub_attr_still_allows_a_matching_display_name() {
        // The fix must not reject a legitimate resubmission of the same immutable values
        // (RFC 7644's "no actual change" case), only a genuine attempted change.
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                Some(r#"members[value eq "u-1"]"#),
                Some(json!({"value": "u-1", "type": "User", "display": "Alice"})),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        assert_eq!(result["members"][0]["display"], "Alice");
    }

    #[test]
    fn scalar_attributes_are_unaffected_by_the_new_multivalued_check() {
        let resource = group_with_two_members();
        let result = apply_patch_with_schema(
            &resource,
            &[op(
                PatchOp::Replace,
                None,
                Some(json!({"displayName": "New Name"})),
            )],
            &crate::group::group_schema(),
        )
        .unwrap();
        assert_eq!(result["displayName"], "New Name");
    }
}
