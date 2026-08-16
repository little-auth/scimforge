//! Hand-authored discovery documents describing exactly what this disposable server
//! actually implements -- not a maximal/aspirational capability list. The Keycloak plugin
//! under test (`little-auth/keycloak-scim-client`) fetches `/ServiceProviderConfig` on
//! every `ScimTargetClient` construction to seed its PATCH-capability detection
//! (`ScimTargetClient::fetchPatchSupport`), so that endpoint in particular has to be
//! reachable and accurate for the plugin's PATCH-vs-PUT fallback logic to behave
//! correctly; `/Schemas` and `/ResourceTypes` exist for completeness rather than because
//! the plugin's own event-driven push flow calls them today.

use scimforge::discovery::{
    AuthenticationScheme, BulkConfig, FilterConfig, RESOURCE_TYPE_SCHEMA_URI, ResourceType,
    SERVICE_PROVIDER_CONFIG_SCHEMA_URI, SchemaResource, ServiceProviderConfig, Supported,
};
use scimforge::group::{GROUP_SCHEMA_URI, group_schema};
use scimforge::user::{USER_SCHEMA_URI, enterprise_user_schema, user_schema};

pub fn service_provider_config() -> ServiceProviderConfig {
    ServiceProviderConfig {
        schemas: vec![SERVICE_PROVIDER_CONFIG_SCHEMA_URI.to_string()],
        documentation_uri: Some(
            "https://github.com/little-auth/scimforge/tree/main/keycloak-it".to_string(),
        ),
        patch: Supported { supported: true },
        bulk: BulkConfig {
            supported: false,
            max_operations: 0,
            max_payload_size: 0,
        },
        filter: FilterConfig {
            supported: false,
            max_results: 0,
        },
        change_password: Supported { supported: false },
        sort: Supported { supported: false },
        etag: Supported { supported: false },
        authentication_schemes: vec![AuthenticationScheme {
            type_: "oauthbearertoken".to_string(),
            name: "Bearer Token".to_string(),
            description: "A single shared bearer token, fixed per server process -- test fixture, not a real auth scheme.".to_string(),
            spec_uri: None,
            documentation_uri: None,
            primary: Some(true),
        }],
    }
}

pub fn resource_types() -> Vec<ResourceType> {
    vec![
        ResourceType {
            schemas: vec![RESOURCE_TYPE_SCHEMA_URI.to_string()],
            id: Some("User".to_string()),
            name: "User".to_string(),
            description: Some("User Account".to_string()),
            endpoint: "/Users".to_string(),
            schema: USER_SCHEMA_URI.to_string(),
            schema_extensions: vec![],
        },
        ResourceType {
            schemas: vec![RESOURCE_TYPE_SCHEMA_URI.to_string()],
            id: Some("Group".to_string()),
            name: "Group".to_string(),
            description: Some("Group".to_string()),
            endpoint: "/Groups".to_string(),
            schema: GROUP_SCHEMA_URI.to_string(),
            schema_extensions: vec![],
        },
    ]
}

pub fn schemas() -> Vec<SchemaResource> {
    vec![user_schema(), enterprise_user_schema(), group_schema()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_types_point_at_endpoints_this_server_actually_serves() {
        let types = resource_types();
        assert!(types.iter().any(|t| t.endpoint == "/Users"));
        assert!(types.iter().any(|t| t.endpoint == "/Groups"));
    }

    #[test]
    fn service_provider_config_advertises_patch_support_since_patch_is_implemented() {
        assert!(service_provider_config().patch.supported);
    }
}
