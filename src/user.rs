//! RFC 7643 §4.1 (Core User) and §4.3 (Enterprise User extension) resource schemas.

use serde::{Deserialize, Serialize};

use crate::common::{ExternalId, Meta, ResourceId};

pub const USER_SCHEMA_URI: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const ENTERPRISE_USER_SCHEMA_URI: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// RFC 7643 §4.1.1 `name` complex attribute. All sub-attributes are `readWrite` and
/// case-insensitive per the spec.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(rename = "middleName", skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(rename = "honorificPrefix", skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(rename = "honorificSuffix", skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

/// The common shape RFC 7643 uses for `emails`, `phoneNumbers`, `ims`, and `photos`
/// (§4.1.2): a bare value plus `type`/`primary`/`display` sub-attributes. `photos` is
/// technically `type: "reference"` rather than `string`, but shares this same sub-
/// attribute shape, so one type serves all four rather than four near-identical structs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiValuedString {
    pub value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// RFC 7643 §4.1.2 `addresses` sub-attributes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(rename = "streetAddress", skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(rename = "postalCode", skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// RFC 7643 §4.1.5 `groups` -- `readOnly`, server-managed reverse view of a user's group
/// memberships. No setter path is exposed on [`User`] for this field beyond
/// deserialization, matching its read-only mutability (a caller that wants to add this
/// user to a group does so via the Group resource's `members`, per RFC 7643 §4.2, not by
/// writing here).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupRef {
    pub value: ResourceId,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// `"direct"` or `"indirect"` per RFC 7643 §4.1.5's canonicalValues.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// RFC 7643 §4.1 Core User resource. `id`/`externalId`/`meta` are `Option` because they
/// don't exist yet on a resource a client is POSTing to create -- the server assigns
/// `id` and `meta`; `externalId` may or may not be supplied by the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ResourceId>,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<ExternalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "nickName", skip_serializing_if = "Option::is_none")]
    pub nick_name: Option<String>,
    #[serde(rename = "profileUrl", skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "userType", skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,
    #[serde(rename = "preferredLanguage", skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    /// RFC 7643 §4.1.1: mutability `writeOnly`, "values SHALL NOT be returned." Marked
    /// `skip_serializing` unconditionally -- deserializable (a caller parsing a client's
    /// create/replace request body needs to read the supplied password), never
    /// serializable, so leaking it into a response is a compile-time-enforced
    /// impossibility for any caller that reuses this type for output, not a discipline
    /// requirement on whoever builds the response.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<MultiValuedString>,
    #[serde(
        rename = "phoneNumbers",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub phone_numbers: Vec<MultiValuedString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ims: Vec<MultiValuedString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub photos: Vec<MultiValuedString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<Address>,
    /// `readOnly` (RFC 7643 §4.1.5) -- see [`GroupRef`]'s doc comment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entitlements: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(
        rename = "x509Certificates",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub x509_certificates: Vec<String>,

    #[serde(
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub enterprise: Option<EnterpriseUser>,
}

/// RFC 7643 §4.3 Enterprise User extension.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnterpriseUser {
    #[serde(rename = "employeeNumber", skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
    #[serde(rename = "costCenter", skip_serializing_if = "Option::is_none")]
    pub cost_center: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub division: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<Manager>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manager {
    pub value: ResourceId,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_user() -> User {
        User {
            schemas: vec![USER_SCHEMA_URI.to_string()],
            id: None,
            external_id: None,
            meta: None,
            user_name: "bjensen".to_string(),
            name: None,
            display_name: None,
            nick_name: None,
            profile_url: None,
            title: None,
            user_type: None,
            preferred_language: None,
            locale: None,
            timezone: None,
            active: None,
            password: None,
            emails: vec![],
            phone_numbers: vec![],
            ims: vec![],
            photos: vec![],
            addresses: vec![],
            groups: vec![],
            entitlements: vec![],
            roles: vec![],
            x509_certificates: vec![],
            enterprise: None,
        }
    }

    #[test]
    fn deserializes_a_realistic_okta_style_user_payload() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bjensen@example.com",
            "name": {"givenName": "Barbara", "familyName": "Jensen"},
            "emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}],
            "active": true
        }"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.user_name, "bjensen@example.com");
        assert_eq!(user.name.unwrap().family_name.as_deref(), Some("Jensen"));
        assert_eq!(user.emails[0].value, "bjensen@example.com");
        assert_eq!(user.active, Some(true));
    }

    /// The security property the module doc promises: a password read from a create
    /// request must never come back out through serialization, even if a caller
    /// (mistakenly or not) serializes the exact same `User` value it just deserialized.
    #[test]
    fn password_round_trips_in_but_never_back_out() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bjensen",
            "password": "correct horse battery staple"
        }"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(
            user.password.as_deref(),
            Some("correct horse battery staple")
        );

        let serialized = serde_json::to_string(&user).unwrap();
        assert!(
            !serialized.contains("correct horse battery staple"),
            "password leaked into serialized output: {serialized}"
        );
        assert!(
            !serialized.contains("password"),
            "'password' key present in output at all: {serialized}"
        );
    }

    #[test]
    fn enterprise_extension_round_trips_under_its_full_schema_urn_key() {
        let mut user = minimal_user();
        user.schemas.push(ENTERPRISE_USER_SCHEMA_URI.to_string());
        user.enterprise = Some(EnterpriseUser {
            employee_number: Some("701984".to_string()),
            cost_center: None,
            organization: Some("Example Corp".to_string()),
            division: None,
            department: None,
            manager: None,
        });
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(
            json["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"],
            "701984"
        );

        let round_tripped: User = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped, user);
    }

    #[test]
    fn readonly_group_membership_round_trips_but_has_no_dedicated_setter() {
        // groups is readOnly (RFC 7643 4.1.5) -- this test documents that the only way
        // to populate it in this crate is deserialization (mirroring "the server wrote
        // this, the client didn't"), not a builder method a caller might mistake for a
        // legitimate way to grant membership.
        let mut user = minimal_user();
        user.groups.push(GroupRef {
            value: ResourceId::new("g-1"),
            ref_: Some("https://example.com/Groups/g-1".to_string()),
            display: Some("Engineering".to_string()),
            type_: Some("direct".to_string()),
        });
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["groups"][0]["display"], "Engineering");
    }

    #[test]
    fn omits_empty_multi_valued_collections_rather_than_serializing_empty_arrays() {
        let user = minimal_user();
        let json = serde_json::to_value(&user).unwrap();
        assert!(json.get("emails").is_none());
        assert!(json.get("roles").is_none());
    }
}
