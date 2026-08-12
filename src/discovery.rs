//! RFC 7643 §5-7 discovery resources: ServiceProviderConfig, ResourceType, Schema. All
//! three are server-authored capability descriptions, not client-writable resources.

use serde::{Deserialize, Serialize};

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
        skip_serializing_if = "Vec::is_empty"
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
}
