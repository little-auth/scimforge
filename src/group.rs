//! RFC 7643 §4.2 Group resource schema.

use serde::{Deserialize, Serialize};

use crate::common::{ExternalId, Meta, ResourceId};
use crate::discovery::{AttributeDefinition, SchemaResource};

pub const GROUP_SCHEMA_URI: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// RFC 7643 §4.2 `members` sub-attributes. `display` is `immutable` per the spec (may be
/// set when a member is added, must not change after) -- this crate doesn't enforce
/// mutability at the type level for sub-attributes (that's the PATCH engine's job, since
/// it requires knowing the *previous* value to detect a change); this struct only owns
/// shape and serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub value: ResourceId,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// `"User"` or `"Group"` per RFC 7643 §4.2's canonicalValues -- groups can nest.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// RFC 7643 §4.2 Group resource. `id`/`externalId`/`meta` are `Option` for the same
/// reason as [`crate::user::User`]: absent on a client's create request, present on the
/// server's response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ResourceId>,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<ExternalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Member>,
}

/// RFC 7643 §4.2's full attribute table -- see [`crate::user::user_schema`]'s doc for why
/// this is the single source of truth shared with `/Schemas` discovery and
/// [`crate::patch`]'s mutability enforcement.
pub fn group_schema() -> SchemaResource {
    SchemaResource {
        schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
        id: GROUP_SCHEMA_URI.to_string(),
        name: Some("Group".to_string()),
        description: Some("Group".to_string()),
        attributes: vec![
            AttributeDefinition {
                required: true,
                ..AttributeDefinition::simple(
                    "displayName",
                    "string",
                    "A human-readable name for the Group.",
                    "readWrite",
                )
            },
            AttributeDefinition {
                multi_valued: true,
                sub_attributes: vec![
                    AttributeDefinition::simple(
                        "value",
                        "string",
                        "Identifier of the member of this Group.",
                        "immutable",
                    ),
                    AttributeDefinition::simple(
                        "$ref",
                        "reference",
                        "The URI of the member resource.",
                        "immutable",
                    ),
                    // "display" is immutable per RFC 7643 4.2: settable when a member is
                    // added, must not change afterward without removing and re-adding.
                    AttributeDefinition::simple(
                        "display",
                        "string",
                        "A human-readable name for the group member.",
                        "immutable",
                    ),
                    // "type" (canonicalValues "User"/"Group") is immutable per RFC 7643
                    // 4.2/8.7.1, same as value/$ref/display -- without this entry the
                    // PATCH engine's schema-driven mutability check can't see this
                    // sub-attribute at all (find_attribute returns None, which
                    // check_mutability treats permissively), letting a client silently
                    // flip an existing member's type after creation.
                    AttributeDefinition::simple(
                        "type",
                        "string",
                        "A label indicating the type of resource, e.g. 'User' or 'Group'.",
                        "immutable",
                    ),
                ],
                ..AttributeDefinition::simple(
                    "members",
                    "complex",
                    "A list of members of the Group.",
                    "readWrite",
                )
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::find_attribute;

    #[test]
    fn group_schema_matches_rfc_7643_section_4_2_characteristics() {
        let schema = group_schema();

        let display_name = find_attribute(&schema, "displayName", None).unwrap();
        assert!(display_name.required, "displayName is REQUIRED per 4.2");

        let members = find_attribute(&schema, "members", None).unwrap();
        assert!(members.multi_valued);
        assert_eq!(
            members.mutability, "readWrite",
            "members itself is readWrite -- only its sub-attributes are immutable"
        );

        for immutable_sub in ["value", "$ref", "display", "type"] {
            let sub = find_attribute(&schema, "members", Some(immutable_sub))
                .unwrap_or_else(|| panic!("members.{immutable_sub} must be resolvable"));
            assert_eq!(
                sub.mutability, "immutable",
                "members.{immutable_sub} is immutable per 4.2"
            );
        }
    }

    #[test]
    fn deserializes_a_realistic_group_payload_with_nested_group_member() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Tour Guides",
            "members": [
                {"value": "u-1", "type": "User", "display": "Babs Jensen"},
                {"value": "g-2", "type": "Group", "display": "Docents"}
            ]
        }"#;
        let group: Group = serde_json::from_str(json).unwrap();
        assert_eq!(group.display_name, "Tour Guides");
        assert_eq!(group.members.len(), 2);
        assert_eq!(group.members[1].type_.as_deref(), Some("Group"));
    }

    #[test]
    fn omits_empty_members_rather_than_serializing_an_empty_array() {
        let group = Group {
            schemas: vec![GROUP_SCHEMA_URI.to_string()],
            id: None,
            external_id: None,
            meta: None,
            display_name: "Empty Group".to_string(),
            members: vec![],
        };
        let json = serde_json::to_value(&group).unwrap();
        assert!(json.get("members").is_none());
    }

    #[test]
    fn member_value_is_a_resource_id_not_an_external_id() {
        // A Group's members[].value references another resource's server-assigned id
        // (RFC 7643 4.2), never a client-supplied externalId -- same CVE-2025-41115-class
        // reasoning as User.groups[].value in user.rs, enforced by using ResourceId here
        // rather than a bare String or ExternalId.
        let member = Member {
            value: ResourceId::new("u-1"),
            ref_: None,
            display: None,
            type_: Some("User".to_string()),
        };
        assert_eq!(member.value.as_str(), "u-1");
    }
}
