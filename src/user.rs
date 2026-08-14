//! RFC 7643 §4.1 (Core User) and §4.3 (Enterprise User extension) resource schemas.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::common::{ExternalId, Meta, ResourceId};
use crate::discovery::{AttributeDefinition, SchemaResource};

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

/// Wrapper around a user's password value that keeps it out of `Debug` output.
///
/// SCIM servers routinely log inbound provisioning requests -- `tracing::debug!(?user,
/// ...)` or an ad hoc `format!("{user:?}")` while troubleshooting a sync job -- and
/// because [`User`] derives `Debug`, a bare `Option<String>` field would print the
/// cleartext password verbatim into logs. `Password` exists so `User` can keep
/// `#[derive(Debug)]` for its many other fields while this one field is safe by
/// construction: its hand-written `Debug` impl always emits a fixed `"[REDACTED]"`
/// placeholder, whether the value is present or not, so the length of the password (and
/// even whether one was supplied) never leaks into logs either.
///
/// Serialization is unaffected: `#[serde(transparent)]` makes `Password` serialize and
/// deserialize exactly as a bare `Option<String>` would, so the existing
/// `#[serde(default, skip_serializing)]` annotation on `User::password` continues to work
/// unchanged.
///
/// Equality avoids the default derived structural comparison, which would short-circuit
/// byte-by-byte on the first mismatch and let an attacker who can measure comparison
/// timing recover a secret one byte at a time. Once both sides are known to be `Some`
/// values of equal length, the actual byte content is compared in constant time (an
/// XOR-fold with no early return). A `None`/`Some` mismatch or a length mismatch still
/// returns immediately without folding -- this matches the documented behavior of
/// established constant-time comparison primitives (Go's `crypto/subtle.
/// ConstantTimeCompare`, Python's `hmac.compare_digest`): the guarantee is about not
/// leaking *which bytes* differ once presence and length are already known, not about
/// hiding presence or length themselves.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Password(Option<String>);

impl Password {
    /// Mirrors `Option::as_deref` rather than exposing a blanket `Deref<Target =
    /// Option<String>>` -- a generic `Deref` impl lets a caller explicitly dereference
    /// past this type (`*user.password`, `&*user.password`) to obtain the raw
    /// `Option<String>` and format *that* with its own std `Debug` impl instead of
    /// [`Password`]'s redacted one, defeating the entire point of this type for the cost
    /// of one extra `*`. A named method returning `Option<&str>` gives every legitimate
    /// caller (comparing/hashing/persisting the value) the exact same access, without
    /// also handing out a route to the wrapped `Option<String>` itself.
    pub fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

impl From<Option<String>> for Password {
    fn from(value: Option<String>) -> Self {
        Password(value)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.len() == b.len()
                    && a.as_bytes()
                        .iter()
                        .zip(b.as_bytes())
                        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                        == 0
            }
            _ => false,
        }
    }
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
    /// requirement on whoever builds the response. Wrapped in [`Password`] rather than a
    /// bare `Option<String>` so it also never leaks into `Debug`/log output and so
    /// equality on it is constant-time.
    #[serde(default, skip_serializing)]
    pub password: Password,

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

/// RFC 7643 §4.1's full attribute table as a machine-readable [`SchemaResource`] -- the
/// single source of truth both for the `/Schemas` discovery endpoint (§7) and for
/// [`crate::patch`]'s schema-driven mutability enforcement, so the two can never drift
/// out of sync with each other (a hand-maintained second mutability table next to this
/// one would be exactly that risk).
pub fn user_schema() -> SchemaResource {
    let name_sub = |n: &str, d: &str| AttributeDefinition::simple(n, "string", d, "readWrite");
    SchemaResource {
        schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
        id: USER_SCHEMA_URI.to_string(),
        name: Some("User".to_string()),
        description: Some("User Account".to_string()),
        attributes: vec![
            AttributeDefinition {
                required: true,
                uniqueness: "server".to_string(),
                ..AttributeDefinition::simple(
                    "userName",
                    "string",
                    "Unique identifier for the User, typically used by the user to \
                     directly authenticate.",
                    "readWrite",
                )
            },
            AttributeDefinition {
                sub_attributes: vec![
                    name_sub("formatted", "The full name."),
                    name_sub("familyName", "The family name."),
                    name_sub("givenName", "The given name."),
                    name_sub("middleName", "The middle name(s)."),
                    name_sub("honorificPrefix", "The honorific prefix(es)."),
                    name_sub("honorificSuffix", "The honorific suffix(es)."),
                ],
                ..AttributeDefinition::simple(
                    "name",
                    "complex",
                    "The components of the user's real name.",
                    "readWrite",
                )
            },
            AttributeDefinition::simple(
                "displayName",
                "string",
                "The name of the User, suitable for display.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "nickName",
                "string",
                "The casual way to address the user.",
                "readWrite",
            ),
            AttributeDefinition {
                type_: "reference".to_string(),
                case_exact: true,
                reference_types: vec!["external".to_string()],
                ..AttributeDefinition::simple(
                    "profileUrl",
                    "reference",
                    "A URI that is a URL to the user's online profile.",
                    "readWrite",
                )
            },
            AttributeDefinition::simple("title", "string", "The user's title.", "readWrite"),
            AttributeDefinition::simple(
                "userType",
                "string",
                "Used to identify the relationship between the organization and the user.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "preferredLanguage",
                "string",
                "Indicates the User's preferred written or spoken language.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "locale",
                "string",
                "Used to indicate the User's default location.",
                "readWrite",
            ),
            AttributeDefinition::simple("timezone", "string", "The User's time zone.", "readWrite"),
            AttributeDefinition::simple(
                "active",
                "boolean",
                "A Boolean value indicating the User's administrative status.",
                "readWrite",
            ),
            AttributeDefinition {
                mutability: "writeOnly".to_string(),
                returned: "never".to_string(),
                ..AttributeDefinition::simple(
                    "password",
                    "string",
                    "The User's clear text password.",
                    "writeOnly",
                )
            },
            multi_valued_string_attr("emails", "Email addresses for the user.", "readWrite"),
            multi_valued_string_attr("phoneNumbers", "Phone numbers for the User.", "readWrite"),
            multi_valued_string_attr(
                "ims",
                "Instant messaging addresses for the User.",
                "readWrite",
            ),
            AttributeDefinition {
                multi_valued: true,
                type_: "reference".to_string(),
                reference_types: vec!["external".to_string()],
                ..AttributeDefinition::simple(
                    "photos",
                    "reference",
                    "URLs of photos of the User.",
                    "readWrite",
                )
            },
            AttributeDefinition {
                multi_valued: true,
                sub_attributes: vec![
                    name_sub("formatted", "The full mailing address."),
                    name_sub("streetAddress", "The street address."),
                    name_sub("locality", "The city or locality."),
                    name_sub("region", "The state or region."),
                    name_sub("postalCode", "The zip code or postal code."),
                    name_sub("country", "The country name."),
                ],
                ..AttributeDefinition::simple(
                    "addresses",
                    "complex",
                    "A physical mailing address for this User.",
                    "readWrite",
                )
            },
            AttributeDefinition {
                multi_valued: true,
                mutability: "readOnly".to_string(),
                sub_attributes: vec![
                    AttributeDefinition::simple(
                        "value",
                        "string",
                        "The identifier of the User's group.",
                        "readOnly",
                    ),
                    AttributeDefinition::simple(
                        "$ref",
                        "reference",
                        "The URI of the corresponding Group resource.",
                        "readOnly",
                    ),
                    AttributeDefinition::simple(
                        "display",
                        "string",
                        "A human-readable name for the Group.",
                        "readOnly",
                    ),
                    AttributeDefinition {
                        canonical_values: vec!["direct".to_string(), "indirect".to_string()],
                        ..AttributeDefinition::simple(
                            "type",
                            "string",
                            "A label indicating the attribute's function; e.g., 'direct' or 'indirect'.",
                            "readOnly",
                        )
                    },
                ],
                ..AttributeDefinition::simple(
                    "groups",
                    "complex",
                    "A list of groups that the user belongs to.",
                    "readOnly",
                )
            },
            AttributeDefinition {
                multi_valued: true,
                ..AttributeDefinition::simple(
                    "entitlements",
                    "string",
                    "A list of entitlements for the User.",
                    "readWrite",
                )
            },
            AttributeDefinition {
                multi_valued: true,
                ..AttributeDefinition::simple(
                    "roles",
                    "string",
                    "A list of roles for the User.",
                    "readWrite",
                )
            },
            AttributeDefinition {
                multi_valued: true,
                type_: "binary".to_string(),
                ..AttributeDefinition::simple(
                    "x509Certificates",
                    "binary",
                    "A list of certificates issued to the User.",
                    "readWrite",
                )
            },
        ],
    }
}

fn multi_valued_string_attr(
    name: &str,
    description: &str,
    mutability: &str,
) -> AttributeDefinition {
    AttributeDefinition {
        multi_valued: true,
        sub_attributes: vec![
            AttributeDefinition::simple("value", "string", "The value.", mutability),
            AttributeDefinition::simple("type", "string", "The type of value.", mutability),
            AttributeDefinition::simple(
                "primary",
                "boolean",
                "Whether this is the primary value.",
                mutability,
            ),
            AttributeDefinition::simple("display", "string", "A human-readable value.", mutability),
        ],
        ..AttributeDefinition::simple(name, "complex", description, mutability)
    }
}

/// RFC 7643 §4.3's full attribute table.
pub fn enterprise_user_schema() -> SchemaResource {
    SchemaResource {
        schemas: vec![crate::discovery::SCHEMA_SCHEMA_URI.to_string()],
        id: ENTERPRISE_USER_SCHEMA_URI.to_string(),
        name: Some("EnterpriseUser".to_string()),
        description: Some("Enterprise User".to_string()),
        attributes: vec![
            AttributeDefinition::simple(
                "employeeNumber",
                "string",
                "Numeric or alphanumeric identifier assigned to a person.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "costCenter",
                "string",
                "Identifies the name of a cost center.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "organization",
                "string",
                "Identifies the name of an organization.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "division",
                "string",
                "Identifies the name of a division.",
                "readWrite",
            ),
            AttributeDefinition::simple(
                "department",
                "string",
                "Identifies the name of a department.",
                "readWrite",
            ),
            AttributeDefinition {
                sub_attributes: vec![
                    AttributeDefinition::simple(
                        "value",
                        "string",
                        "The id of the SCIM resource representing the user's manager.",
                        "readWrite",
                    ),
                    AttributeDefinition::simple(
                        "$ref",
                        "reference",
                        "The URI of the SCIM resource representing the user's manager.",
                        "readWrite",
                    ),
                    AttributeDefinition::simple(
                        "displayName",
                        "string",
                        "The displayName of the user's manager.",
                        "readOnly",
                    ),
                ],
                ..AttributeDefinition::simple(
                    "manager",
                    "complex",
                    "The user's manager.",
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

    /// `user_schema()`/`enterprise_user_schema()` are large, hand-transcribed data
    /// structures -- everything else that exercises them (patch.rs's schema-driven
    /// mutability tests) only incidentally touches a handful of attributes (`groups`,
    /// `active`). This asserts the actual RFC 7643 §4.1/§4.3 characteristics directly,
    /// attribute by attribute, so a transcription error elsewhere in the list (a wrong
    /// mutability, a missing `multi_valued`, a `required` that shouldn't be) doesn't go
    /// silently uncaught.
    #[test]
    fn user_schema_matches_rfc_7643_section_4_1_characteristics() {
        let schema = user_schema();

        let user_name = find_attribute(&schema, "userName", None).unwrap();
        assert!(user_name.required, "userName is REQUIRED per 4.1");
        assert_eq!(user_name.uniqueness, "server");

        let name = find_attribute(&schema, "name", None).unwrap();
        assert_eq!(name.type_, "complex");
        assert!(!name.multi_valued);
        assert!(
            find_attribute(&schema, "name", Some("familyName")).is_some(),
            "name.familyName must be a resolvable sub-attribute"
        );

        let active = find_attribute(&schema, "active", None).unwrap();
        assert_eq!(active.type_, "boolean");

        let password = find_attribute(&schema, "password", None).unwrap();
        assert_eq!(password.mutability, "writeOnly");
        assert_eq!(password.returned, "never");

        let groups = find_attribute(&schema, "groups", None).unwrap();
        assert_eq!(groups.mutability, "readOnly");
        assert!(groups.multi_valued);

        let profile_url = find_attribute(&schema, "profileUrl", None).unwrap();
        assert_eq!(profile_url.type_, "reference");
        assert!(
            profile_url.case_exact,
            "profileUrl is explicitly caseExact: true per 4.1"
        );

        for multi_valued_name in ["emails", "phoneNumbers", "ims", "addresses"] {
            let attr = find_attribute(&schema, multi_valued_name, None)
                .unwrap_or_else(|| panic!("{multi_valued_name} must exist in user_schema()"));
            assert!(attr.multi_valued, "{multi_valued_name} must be multiValued");
        }

        let x509 = find_attribute(&schema, "x509Certificates", None).unwrap();
        assert_eq!(x509.type_, "binary");
        assert!(x509.multi_valued);

        // Lookup for an attribute this schema genuinely doesn't have must be None, not
        // panic or silently match something else.
        assert!(find_attribute(&schema, "notARealAttribute", None).is_none());
    }

    #[test]
    fn enterprise_user_schema_matches_rfc_7643_section_4_3_characteristics() {
        let schema = enterprise_user_schema();
        for readwrite_string_attr in [
            "employeeNumber",
            "costCenter",
            "organization",
            "division",
            "department",
        ] {
            let attr = find_attribute(&schema, readwrite_string_attr, None)
                .unwrap_or_else(|| panic!("{readwrite_string_attr} must exist"));
            assert_eq!(attr.mutability, "readWrite");
            assert_eq!(attr.type_, "string");
        }

        let manager = find_attribute(&schema, "manager", None).unwrap();
        assert_eq!(manager.type_, "complex");
        let manager_display_name = find_attribute(&schema, "manager", Some("displayName"))
            .expect("manager.displayName must be a resolvable sub-attribute");
        assert_eq!(manager_display_name.mutability, "readOnly");
        // Regression: manager.$ref was previously unmodeled, so find_attribute returned
        // None for it and check_mutability's unmodeled-attribute fallback resolved it as
        // ReadWrite by coincidence rather than by declaration -- explicitly modeling it
        // (same as manager.value) makes that intended, not accidental.
        let manager_ref = find_attribute(&schema, "manager", Some("$ref"))
            .expect("manager.$ref must be a resolvable sub-attribute");
        assert_eq!(manager_ref.type_, "reference");
        assert_eq!(manager_ref.mutability, "readWrite");
    }

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
            password: Password(None),
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
    fn password_never_leaks_the_cleartext_value_into_debug_output() {
        let with_value = Password(Some("correct horse battery staple".to_string()));
        let without_value = Password(None);
        assert_eq!(format!("{with_value:?}"), "[REDACTED]");
        assert_eq!(format!("{without_value:?}"), "[REDACTED]");
    }

    #[test]
    fn password_as_deref_still_works_without_a_blanket_deref_escape_hatch() {
        // Regression: Password's tuple field used to be `pub` and Deref<Target =
        // Option<String>> exposed the whole wrapped value, so `user.password.0` or
        // `*user.password` bypassed Password's own Debug entirely and printed the
        // std Option<String> Debug output (the plaintext) instead. This test's real
        // assertion is at compile time: the tuple field is private and there is no
        // Deref impl, so neither `.0` nor `*password` compiles from outside this
        // module -- only the purpose-built as_deref() method (which returns a plain
        // Option<&str>, the same thing any legitimate caller needs) is available.
        let with_value = Password(Some("correct horse battery staple".to_string()));
        assert_eq!(with_value.as_deref(), Some("correct horse battery staple"));
        assert_eq!(Password(None).as_deref(), None);
    }

    #[test]
    fn password_equality_compares_content_not_identity() {
        assert_eq!(
            Password(Some("secret".to_string())),
            Password(Some("secret".to_string()))
        );
        assert_ne!(
            Password(Some("secret".to_string())),
            Password(Some("different".to_string()))
        );
        assert_ne!(Password(Some("secret".to_string())), Password(None));
        assert_eq!(Password(None), Password(None));
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
