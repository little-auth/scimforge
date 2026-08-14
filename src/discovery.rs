//! RFC 7643 §5-7 discovery resources: ServiceProviderConfig, ResourceType, Schema. All
//! three are server-authored capability descriptions, not client-writable resources.

use serde::{Deserialize, Serialize};
use std::cell::Cell;

pub const SERVICE_PROVIDER_CONFIG_SCHEMA_URI: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const RESOURCE_TYPE_SCHEMA_URI: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA_URI: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Supported {
    pub supported: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkConfig {
    pub supported: bool,
    #[serde(rename = "maxOperations")]
    pub max_operations: u32,
    #[serde(rename = "maxPayloadSize")]
    pub max_payload_size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterConfig {
    pub supported: bool,
    #[serde(rename = "maxResults")]
    pub max_results: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationScheme {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "specUri", skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(rename = "documentationUri", skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// RFC 7643 §5. Every sub-attribute here is `readOnly`: a service provider authors this
/// once to describe its own actual capabilities (this crate parses/represents it, but
/// deciding what's actually true -- whether PATCH really is supported, real limits --
/// is the caller's job, not something this type infers).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceProviderConfig {
    pub schemas: Vec<String>,
    #[serde(rename = "documentationUri", skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
    pub patch: Supported,
    pub bulk: BulkConfig,
    pub filter: FilterConfig,
    #[serde(rename = "changePassword")]
    pub change_password: Supported,
    pub sort: Supported,
    pub etag: Supported,
    #[serde(rename = "authenticationSchemes")]
    pub authentication_schemes: Vec<AuthenticationScheme>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaExtension {
    pub schema: String,
    pub required: bool,
}

/// RFC 7643 §6.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceType {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub endpoint: String,
    pub schema: String,
    #[serde(
        rename = "schemaExtensions",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub schema_extensions: Vec<SchemaExtension>,
}

/// Bounds AttributeDefinition's subAttributes recursion during deserialization, the
/// same DoS class filter::MAX_DEPTH guards against for filter-expression nesting.
/// Unlike filter's hand-rolled recursive-descent parser, AttributeDefinition's
/// Deserialize is #[derive]d, so there's no intermediate Value tree to depth-check
/// after the fact: the recursion happens DURING parsing.
pub const MAX_DEPTH: usize = 32;

thread_local! {
    /// JSON deserialization is synchronous (no `.await` point inside a
    /// `from_str`/`from_value` call), so a thread-local counter is sound even when
    /// the surrounding request handler is async. If an async-streaming deserializer
    /// that can suspend mid-parse across threads is ever introduced, this would need
    /// to become a passed-through depth parameter or a task-local instead.
    static SUB_ATTRIBUTES_DEPTH: Cell<usize> = const { Cell::new(0) };
}

struct SubAttributesDepthGuard;

impl Drop for SubAttributesDepthGuard {
    fn drop(&mut self) {
        SUB_ATTRIBUTES_DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

fn deserialize_sub_attributes<'de, D>(
    deserializer: D,
) -> Result<Vec<AttributeDefinition>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let depth = SUB_ATTRIBUTES_DEPTH.with(|depth| {
        let next = depth.get() + 1;
        depth.set(next);
        next
    });
    let _guard = SubAttributesDepthGuard;

    if depth > MAX_DEPTH {
        return Err(D::Error::custom(format!(
            "subAttributes nesting exceeds the maximum depth of {MAX_DEPTH}"
        )));
    }

    Vec::<AttributeDefinition>::deserialize(deserializer)
}

/// RFC 7643 §7 attribute definition, recursive via `subAttributes` for `type: "complex"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributeDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "multiValued")]
    pub multi_valued: bool,
    pub description: String,
    pub required: bool,
    #[serde(
        rename = "canonicalValues",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub canonical_values: Vec<String>,
    #[serde(rename = "caseExact")]
    pub case_exact: bool,
    pub mutability: String,
    pub returned: String,
    pub uniqueness: String,
    #[serde(
        rename = "subAttributes",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_sub_attributes"
    )]
    pub sub_attributes: Vec<AttributeDefinition>,
    #[serde(
        rename = "referenceTypes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub reference_types: Vec<String>,
}

impl AttributeDefinition {
    /// The common case: a non-multi-valued, non-required, case-insensitive,
    /// no-uniqueness, default-returned attribute -- which covers most of RFC 7643's
    /// §4.1/§4.2 attribute table. Override specific fields via struct-update syntax
    /// (`AttributeDefinition { required: true, ..AttributeDefinition::simple(...) }`)
    /// for the attributes that differ.
    pub fn simple(name: &str, type_: &str, description: &str, mutability: &str) -> Self {
        AttributeDefinition {
            name: name.to_string(),
            type_: type_.to_string(),
            multi_valued: false,
            description: description.to_string(),
            required: false,
            canonical_values: vec![],
            case_exact: false,
            mutability: mutability.to_string(),
            returned: "default".to_string(),
            uniqueness: "none".to_string(),
            sub_attributes: vec![],
            reference_types: vec![],
        }
    }
}

/// Looks up an attribute (optionally a sub-attribute) by name, case-insensitively per
/// RFC 7643 attribute-naming rules -- used by [`crate::patch`]'s schema-driven mutability
/// enforcement.
pub fn find_attribute<'a>(
    schema: &'a SchemaResource,
    attr_name: &str,
    sub_attr: Option<&str>,
) -> Option<&'a AttributeDefinition> {
    let top = schema
        .attributes
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(attr_name))?;
    match sub_attr {
        Some(sub) => top
            .sub_attributes
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(sub)),
        None => Some(top),
    }
}

/// Resolves whether `attr_name`(.`sub_attr`) is `caseExact` per RFC 7643, consulting
/// `schema`'s per-resource attribute table first (via [`find_attribute`]), then this
/// crate's internal RFC 7643 §3.1 common-attributes table for the common attributes
/// every resource type shares but no schema document redeclares (`id`, `externalId`,
/// `meta.*`). `parent_attr` distinguishes the two shapes an
/// attribute path can take: `None` resolves `attr_name`(.`sub_attr`) as a top-level
/// path (e.g. `userName`, or `meta.resourceType`, the shape a search-filter's own
/// `attrPath` takes -- RFC 7644 §3.4.2.2's `filter=externalId eq "x"`); `Some(parent)`
/// resolves `attr_name` as `parent`'s sub-attribute instead (e.g. `"type"` inside a
/// value-path bracket filter like `emails[type eq "work"]`, where `parent_attr` is
/// `"emails"` and `attr_name` is `"type"` -- `attr_name` alone isn't a top-level schema
/// attribute, so the parent context is required to resolve it correctly).
///
/// Anything this can't resolve folds case, matching RFC 7643 §2.2's stated default
/// (`caseExact` `DEFAULT: false`) -- never the reverse, since defaulting to `caseExact`
/// would silently break case-insensitive matching for everything this can't classify,
/// to fix the much narrower set of attributes that are actually `caseExact`.
///
/// [`crate::patch`]'s schema-driven PATCH bracket-filter matching uses this internally
/// (always with `parent_attr: Some(..)`, since it only ever compares one array entry's
/// sub-attributes). It's `pub` here for a caller implementing their own search/list
/// filter evaluation (`GET /Users?filter=...` against a whole collection) -- a
/// storage-layer concern this crate deliberately doesn't implement (see
/// [`crate::filter`]'s module doc) -- so they can resolve RFC 7643 `caseExact` for a
/// parsed [`crate::filter::AttrPath`]'s `attr_name`/`sub_attr` (pass `parent_attr: None`
/// for a top-level filter attribute, or the enclosing `valuePath`'s attribute name for
/// one nested inside a value-path bracket filter) without re-deriving the RFC's rules,
/// including the common attributes a per-resource `SchemaResource` alone can't answer.
///
/// ```
/// use scimitar::discovery::is_case_exact;
///
/// // No schema, not a common attribute: folds, per RFC 7643 2.2's stated default.
/// assert!(!is_case_exact(None, None, "userName", None));
///
/// // id/externalId/meta.resourceType/meta.version are RFC 7643 3.1 common attributes,
/// // resolved even with no SchemaResource to consult (they're never in one).
/// assert!(is_case_exact(None, None, "externalId", None));
/// assert!(is_case_exact(None, None, "meta", Some("resourceType")));
/// ```
pub fn is_case_exact(
    schema: Option<&SchemaResource>,
    parent_attr: Option<&str>,
    attr_name: &str,
    sub_attr: Option<&str>,
) -> bool {
    let (top, sub) = match parent_attr {
        Some(parent) => (parent, Some(attr_name)),
        None => (attr_name, sub_attr),
    };
    // RFC 7643 3.1's four common attributes with caseExact: true (id, externalId,
    // meta.resourceType, meta.version) are a fixed characteristic of those common
    // attributes, not a per-resource-schema opinion -- unlike every other attribute,
    // where the schema is the more specific, authoritative source (checked below). A
    // real /Schemas/User document wouldn't redeclare these (see
    // common_attribute_case_exact's doc comment), but nothing stops a caller from
    // feeding in a schema that does -- e.g. schema data imported from a less-trusted or
    // federated source -- so these four are resolved before consulting the schema,
    // rather than letting an unusual schema fold case for what RFC 7643 treats as an
    // always-case-exact identity/version field.
    if let Some(true) = common_attribute_case_exact(top, sub) {
        return true;
    }
    if let Some(schema) = schema
        && let Some(attr_def) = find_attribute(schema, top, sub)
    {
        return attr_def.case_exact;
    }
    common_attribute_case_exact(top, sub).unwrap_or(false)
}

/// RFC 7643 §3.1 "Common Attributes" -- defined once for every resource type, not part
/// of a specific resource's attribute table, so [`crate::user::user_schema`]/
/// [`crate::group::group_schema`] don't redeclare them (matching how a real
/// `/Schemas/User` document wouldn't either), meaning [`find_attribute`] alone always
/// reports "not found" for these. Verified directly against the RFC 7643 §3.1
/// characteristics text, not assumed: `id`, `externalId`, `meta.resourceType`, and
/// `meta.version` are explicitly `caseExact: true`; `meta.created`, `meta.lastModified`,
/// and `meta.location` have no `caseExact` stated, so they take §2.2's default (`false`).
fn common_attribute_case_exact(attr_name: &str, sub_attr: Option<&str>) -> Option<bool> {
    if attr_name.eq_ignore_ascii_case("id") && sub_attr.is_none() {
        return Some(true);
    }
    if attr_name.eq_ignore_ascii_case("externalId") && sub_attr.is_none() {
        return Some(true);
    }
    if attr_name.eq_ignore_ascii_case("meta")
        && let Some(sub) = sub_attr
    {
        return match sub.to_ascii_lowercase().as_str() {
            "resourcetype" | "version" => Some(true),
            "created" | "lastmodified" | "location" => Some(false),
            _ => None,
        };
    }
    None
}

/// RFC 7643 §7. "Schema resources are read-only."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaResource {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub attributes: Vec<AttributeDefinition>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips the RFC 7643 §8.5 example verbatim -- proves this crate's field
    /// names/nesting/types match the spec's own worked example, not just a plausible
    /// guess at the shape.
    #[test]
    fn deserializes_the_rfc_7643_section_8_5_example_verbatim() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "http://example.com/help/scim.html",
            "patch": { "supported": true },
            "bulk": {
                "supported": true,
                "maxOperations": 1000,
                "maxPayloadSize": 1048576
            },
            "filter": {
                "supported": true,
                "maxResults": 200
            },
            "changePassword": { "supported": true },
            "sort": { "supported": true },
            "etag": { "supported": true },
            "authenticationSchemes": [
                {
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using the OAuth Bearer Token Standard",
                    "specUri": "http://www.rfc-editor.org/info/rfc6750",
                    "documentationUri": "http://example.com/help/oauth.html",
                    "type": "oauthbearertoken",
                    "primary": true
                },
                {
                    "name": "HTTP Basic",
                    "description": "Authentication scheme using the HTTP Basic Standard",
                    "specUri": "http://www.rfc-editor.org/info/rfc2617",
                    "documentationUri": "http://example.com/help/httpBasic.html",
                    "type": "httpbasic"
                }
            ]
        }"#;
        let config: ServiceProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.bulk.max_operations, 1000);
        assert_eq!(config.bulk.max_payload_size, 1_048_576);
        assert_eq!(config.filter.max_results, 200);
        assert_eq!(config.authentication_schemes.len(), 2);
        assert_eq!(config.authentication_schemes[0].primary, Some(true));
        assert_eq!(config.authentication_schemes[1].primary, None);

        let round_tripped: ServiceProviderConfig =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert_eq!(round_tripped, config);
    }

    #[test]
    fn resource_type_round_trips_with_schema_extensions() {
        let rt = ResourceType {
            schemas: vec![RESOURCE_TYPE_SCHEMA_URI.to_string()],
            id: Some("User".to_string()),
            name: "User".to_string(),
            description: Some("User Account".to_string()),
            endpoint: "/Users".to_string(),
            schema: crate::user::USER_SCHEMA_URI.to_string(),
            schema_extensions: vec![SchemaExtension {
                schema: crate::user::ENTERPRISE_USER_SCHEMA_URI.to_string(),
                required: false,
            }],
        };
        let json = serde_json::to_value(&rt).unwrap();
        assert_eq!(json["schemaExtensions"][0]["required"], false);
        let round_tripped: ResourceType = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped, rt);
    }

    #[test]
    fn schema_attribute_definition_nests_sub_attributes_for_complex_types() {
        let name_attr = AttributeDefinition {
            name: "name".to_string(),
            type_: "complex".to_string(),
            multi_valued: false,
            description: "The components of the user's name.".to_string(),
            required: false,
            canonical_values: vec![],
            case_exact: false,
            mutability: "readWrite".to_string(),
            returned: "default".to_string(),
            uniqueness: "none".to_string(),
            sub_attributes: vec![AttributeDefinition {
                name: "familyName".to_string(),
                type_: "string".to_string(),
                multi_valued: false,
                description: "The family name.".to_string(),
                required: false,
                canonical_values: vec![],
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
                uniqueness: "none".to_string(),
                sub_attributes: vec![],
                reference_types: vec![],
            }],
            reference_types: vec![],
        };
        let json = serde_json::to_value(&name_attr).unwrap();
        assert_eq!(json["subAttributes"][0]["name"], "familyName");
    }

    // --- is_case_exact / common_attribute_case_exact ---

    fn widget_schema() -> SchemaResource {
        SchemaResource {
            schemas: vec![SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Widget".to_string(),
            name: Some("Widget".to_string()),
            description: None,
            attributes: vec![
                AttributeDefinition {
                    case_exact: true,
                    ..AttributeDefinition::simple(
                        "serialNumber",
                        "string",
                        "Case-sensitive top-level attribute.",
                        "readWrite",
                    )
                },
                AttributeDefinition {
                    multi_valued: true,
                    sub_attributes: vec![
                        AttributeDefinition {
                            case_exact: true,
                            ..AttributeDefinition::simple(
                                "code",
                                "string",
                                "Case-sensitive sub-attribute.",
                                "readWrite",
                            )
                        },
                        AttributeDefinition::simple(
                            "label",
                            "string",
                            "Case-insensitive sub-attribute.",
                            "readWrite",
                        ),
                    ],
                    ..AttributeDefinition::simple(
                        "parts",
                        "complex",
                        "A list of parts.",
                        "readWrite",
                    )
                },
            ],
        }
    }

    #[test]
    fn is_case_exact_resolves_a_top_level_schema_attribute() {
        // No parent_attr: attr_name/sub_attr are resolved as a top-level AttrPath, the
        // shape a search-filter caller (e.g. `filter=serialNumber eq "X"`) would use.
        let schema = widget_schema();
        assert!(is_case_exact(Some(&schema), None, "serialNumber", None));
        assert!(!is_case_exact(Some(&schema), None, "parts", None));
    }

    #[test]
    fn is_case_exact_resolves_a_sub_attribute_of_a_multi_valued_parent() {
        // parent_attr: Some -- the shape a value-path bracket filter's inner comparison
        // uses (e.g. `parts[code eq "X"]`), resolving against the parent's sub-attribute
        // table rather than treating "code" as a top-level attribute.
        let schema = widget_schema();
        assert!(is_case_exact(Some(&schema), Some("parts"), "code", None));
        assert!(!is_case_exact(Some(&schema), Some("parts"), "label", None));
    }

    #[test]
    fn is_case_exact_resolves_rfc_7643_section_3_1_common_attributes_with_no_schema_match() {
        // id/externalId/meta.* are RFC 7643 3.1 common attributes, defined once for every
        // resource type and never redeclared in a per-resource SchemaResource -- verified
        // directly against the RFC 7643 3.1 characteristics text, not assumed: id,
        // externalId, meta.resourceType, and meta.version are caseExact true; meta.created,
        // meta.lastModified, and meta.location have no caseExact stated (default false).
        assert!(is_case_exact(None, None, "id", None));
        assert!(is_case_exact(None, None, "externalId", None));
        assert!(is_case_exact(None, None, "meta", Some("resourceType")));
        assert!(is_case_exact(None, None, "meta", Some("version")));
        assert!(!is_case_exact(None, None, "meta", Some("created")));
        assert!(!is_case_exact(None, None, "meta", Some("lastModified")));
        assert!(!is_case_exact(None, None, "meta", Some("location")));
    }

    #[test]
    fn is_case_exact_prefers_the_schema_over_the_common_attributes_table() {
        // A schema that resolves the attribute wins over the common-attributes fallback
        // for an ordinary attribute name -- schema is the more specific, authoritative
        // source when it has an opinion. Uses "userName", not a common attribute, since
        // the four RFC-mandated-true common attributes are a fixed exception (see the
        // next test) rather than something a schema is entitled to override.
        let schema = SchemaResource {
            schemas: vec![SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Override".to_string(),
            name: None,
            description: None,
            attributes: vec![AttributeDefinition {
                case_exact: true,
                ..AttributeDefinition::simple(
                    "userName",
                    "string",
                    "A schema that opts an ordinary attribute into case-exactness.",
                    "readWrite",
                )
            }],
        };
        assert!(is_case_exact(Some(&schema), None, "userName", None));
    }

    #[test]
    fn is_case_exact_does_not_let_a_schema_override_the_four_rfc_mandated_common_attributes() {
        // Regression: is_case_exact() used to check the schema first for every
        // attribute name, including id/externalId/meta.resourceType/meta.version --
        // RFC 7643 3.1's common attributes, whose caseExact:true is a fixed
        // characteristic, not a per-resource-schema opinion. That let a schema which
        // (unusually, but validly per the AttributeDefinition type) redeclared one of
        // these names with caseExact:false silently fold case for what should be an
        // exact-match identity/version field -- e.g. externalId, commonly used as a
        // cross-system identity join key, being matched case-insensitively.
        let schema = SchemaResource {
            schemas: vec![SCHEMA_SCHEMA_URI.to_string()],
            id: "urn:test:Override".to_string(),
            name: None,
            description: None,
            attributes: vec![AttributeDefinition {
                case_exact: false,
                ..AttributeDefinition::simple(
                    "externalId",
                    "string",
                    "A schema that (unusually) redeclares externalId.",
                    "readWrite",
                )
            }],
        };
        assert!(is_case_exact(Some(&schema), None, "externalId", None));
        assert!(is_case_exact(Some(&schema), None, "id", None));
        assert!(is_case_exact(Some(&schema), None, "meta", Some("resourceType")));
        assert!(is_case_exact(Some(&schema), None, "meta", Some("version")));
    }

    #[test]
    fn is_case_exact_folds_case_for_anything_it_cannot_resolve() {
        // No schema, not a common attribute -- must fold (RFC 7643 2.2's stated default),
        // never default to caseExact for an attribute this can't classify.
        assert!(!is_case_exact(None, None, "userName", None));
        let schema = widget_schema();
        assert!(!is_case_exact(
            Some(&schema),
            Some("parts"),
            "unmodeled",
            None
        ));
    }

    fn nested_attribute_json(depth: usize) -> serde_json::Value {
        let mut attr = serde_json::json!({
            "name": "level",
            "type": "complex",
            "multiValued": false,
            "description": "A recursively nested attribute.",
            "required": false,
            "caseExact": false,
            "mutability": "readWrite",
            "returned": "default",
            "uniqueness": "none"
        });
        if depth > 0 {
            attr["subAttributes"] = serde_json::Value::Array(vec![nested_attribute_json(depth - 1)]);
        }
        attr
    }

    /// Pinned at the exact boundary rather than "comfortably past it," matching
    /// `filter.rs`'s own boundary-test convention for the identical unbounded-nesting
    /// DoS class.
    #[test]
    fn accepts_sub_attributes_nested_exactly_at_max_depth() {
        let json = nested_attribute_json(MAX_DEPTH);
        let result: Result<AttributeDefinition, _> = serde_json::from_value(json);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_sub_attributes_nested_one_past_max_depth() {
        let json = nested_attribute_json(MAX_DEPTH + 1);
        let result: Result<AttributeDefinition, _> = serde_json::from_value(json);
        let err = result.expect_err("nesting one past MAX_DEPTH must be rejected");
        assert!(
            err.to_string().contains("subAttributes nesting exceeds"),
            "unexpected error: {err}"
        );
    }

    /// The realistic entry point for a third-party provider's `/Schemas` response,
    /// not just a bare `AttributeDefinition` -- proving the bound holds regardless of
    /// where deserialization is kicked off from.
    #[test]
    fn rejects_deeply_nested_sub_attributes_via_schema_resource() {
        let json = serde_json::json!({
            "schemas": [SCHEMA_SCHEMA_URI],
            "id": "urn:test:DeepAttack",
            "attributes": [nested_attribute_json(MAX_DEPTH + 1)]
        });
        let result: Result<SchemaResource, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    /// Two independent complex attributes, each nested to exactly MAX_DEPTH, as
    /// siblings within one SchemaResource deserialize call. If the depth counter
    /// were wrongly cumulative across siblings instead of correctly reset by RAII
    /// Drop between them, the second sibling would spuriously fail even though
    /// neither individually exceeds MAX_DEPTH.
    #[test]
    fn sibling_attributes_each_independently_reach_max_depth_within_one_call() {
        let json = serde_json::json!({
            "schemas": [SCHEMA_SCHEMA_URI],
            "id": "urn:test:Siblings",
            "attributes": [
                nested_attribute_json(MAX_DEPTH),
                nested_attribute_json(MAX_DEPTH)
            ]
        });
        let result: Result<SchemaResource, _> = serde_json::from_value(json);
        assert!(result.is_ok(), "sibling nesting wrongly accumulated: {result:?}");
    }

    /// Proves the thread-local depth counter is fully restored after a rejected deep
    /// parse (via `SubAttributesDepthGuard`'s `Drop` firing on every unwind step, not
    /// just on success) -- otherwise a rejected attack payload on a reused thread
    /// (e.g. a thread-pooled server) would permanently poison every later,
    /// legitimate deserialization on that thread.
    #[test]
    fn depth_counter_does_not_leak_across_deserialize_calls() {
        let too_deep = nested_attribute_json(MAX_DEPTH + 1);
        let rejected: Result<AttributeDefinition, _> = serde_json::from_value(too_deep);
        assert!(rejected.is_err());

        let shallow = nested_attribute_json(1);
        let accepted: Result<AttributeDefinition, _> = serde_json::from_value(shallow);
        assert!(accepted.is_ok());
    }
}
