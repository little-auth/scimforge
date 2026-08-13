//! RFC 7643 §3.1 common attributes (`id`, `externalId`, `meta`) and the attribute
//! "characteristics" from §2.2 (`mutability`, `returned`, `uniqueness`) shared by every
//! resource schema.
//!
//! `id` and `externalId` are deliberately two distinct types with no conversion between
//! them, not two `String` fields a caller could swap. RFC 7643 §3.1 is explicit that
//! `id` "is always issued by the service provider and MUST NOT be specified by the
//! client" and `externalId` "is always issued by the provisioning client and MUST NOT be
//! specified by the service provider" -- conflating the two is exactly the root cause of
//! CVE-2025-41115 (a SCIM client provisioned a user whose client-supplied `externalId`
//! collided with an existing account's server-assigned internal ID, and the server
//! treated them as the same identity, letting the attacker impersonate that account).
//! Making them different Rust types turns that conflation into a compile error instead
//! of a discipline problem.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Server-assigned resource identifier (RFC 7643 §3.1 `id`). Never constructed from
/// client input -- the only public constructor takes ownership of a value the *server*
/// generated (e.g. from its own primary key), not anything read off the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    /// Wraps a server-generated identifier. Callers are responsible for actually
    /// generating it server-side (a UUID, a database primary key, etc.) -- this type
    /// only prevents *accidental* misuse (passing an `ExternalId` where an `id` is
    /// expected), not a caller who deliberately constructs one from untrusted input.
    pub fn new(server_assigned: impl Into<String>) -> Self {
        ResourceId(server_assigned.into())
    }

    /// Borrows the underlying string, e.g. for putting it into a JSON response body.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Client-supplied, opaque-to-the-server identifier (RFC 7643 §3.1 `externalId`). "The
/// service provider MUST always interpret the externalId as scoped to the provisioning
/// domain" -- i.e. never as a hint about the server's own internal identity space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExternalId(String);

impl ExternalId {
    pub fn new(client_supplied: impl Into<String>) -> Self {
        ExternalId(client_supplied.into())
    }

    /// Borrows the underlying string, e.g. for putting it into a JSON response body.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RFC 7643 §2.2 `mutability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    ReadOnly,
    /// Default per the spec.
    ReadWrite,
    Immutable,
    WriteOnly,
}

impl Mutability {
    /// Parses the exact lowercase string RFC 7643 §2.2 defines for this characteristic
    /// (as stored in [`crate::discovery::AttributeDefinition::mutability`]).
    pub fn from_rfc_str(s: &str) -> Option<Self> {
        match s {
            "readOnly" => Some(Mutability::ReadOnly),
            "readWrite" => Some(Mutability::ReadWrite),
            "immutable" => Some(Mutability::Immutable),
            "writeOnly" => Some(Mutability::WriteOnly),
            _ => None,
        }
    }
}

/// RFC 7643 §2.2 `returned`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Returned {
    Always,
    Never,
    /// Default per the spec.
    Default,
    Request,
}

/// RFC 7643 §2.2 `uniqueness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uniqueness {
    /// Default per the spec.
    None,
    Server,
    Global,
}

/// RFC 7643 §3.1 `meta` -- every sub-attribute is `readOnly`, hence no setters here:
/// construct a full value or not at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "lastModified")]
    pub last_modified: DateTime<Utc>,
    pub location: String,
    /// ETag-comparable version string (RFC 7643 §3.1, RFC 7644 §3.14). Optional per
    /// spec: "service provider support for this attribute is optional."
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_id_and_external_id_are_not_interchangeable_types() {
        // This test's real assertion is at compile time: there is no `From<ExternalId>
        // for ResourceId` (or the reverse) anywhere in this module. If one existed, or
        // if both were plain `String`, this file would still compile with the two
        // swapped at any call site -- exactly the CVE-2025-41115 shape. Nothing to
        // assert at runtime beyond "these are real, distinct, constructible types."
        let id = ResourceId::new("srv-generated-001");
        let ext = ExternalId::new("idp-supplied-001");
        assert_eq!(id.as_str(), "srv-generated-001");
        assert_eq!(ext.as_str(), "idp-supplied-001");
    }

    #[test]
    fn resource_id_with_the_same_text_as_an_external_id_are_still_different_values() {
        // Same underlying string, but they must never compare equal or be usable
        // interchangeably -- there is deliberately no PartialEq<ExternalId> for
        // ResourceId (or the reverse), so this is a type-level guarantee, not a value
        // comparison. This test documents that guarantee by construction: if the crate
        // ever grew such a cross-type PartialEq impl, code review (not this test) is the
        // backstop, since Rust's type system won't compile-error on adding one.
        let id = ResourceId::new("1");
        let ext = ExternalId::new("1");
        assert_eq!(id.as_str(), ext.as_str());
    }

    #[test]
    fn mutability_from_rfc_str_parses_all_four_values() {
        assert_eq!(
            Mutability::from_rfc_str("readOnly"),
            Some(Mutability::ReadOnly)
        );
        assert_eq!(
            Mutability::from_rfc_str("readWrite"),
            Some(Mutability::ReadWrite)
        );
        assert_eq!(
            Mutability::from_rfc_str("immutable"),
            Some(Mutability::Immutable)
        );
        assert_eq!(
            Mutability::from_rfc_str("writeOnly"),
            Some(Mutability::WriteOnly)
        );
        assert_eq!(Mutability::from_rfc_str("ReadOnly"), None);
        assert_eq!(Mutability::from_rfc_str("bogus"), None);
    }

    #[test]
    fn meta_serializes_resource_type_and_last_modified_with_correct_field_names() {
        let meta = Meta {
            resource_type: "User".to_string(),
            created: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            last_modified: DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            location: "https://example.com/Users/1".to_string(),
            version: Some(r#"W/"abc123""#.to_string()),
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["resourceType"], "User");
        assert_eq!(json["lastModified"], "2026-01-02T00:00:00Z");
        assert_eq!(json["version"], r#"W/"abc123""#);
    }

    #[test]
    fn meta_omits_version_when_absent_rather_than_serializing_null() {
        let meta = Meta {
            resource_type: "User".to_string(),
            created: Utc::now(),
            last_modified: Utc::now(),
            location: "https://example.com/Users/1".to_string(),
            version: None,
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert!(
            json.get("version").is_none(),
            "expected no 'version' key at all, got {json:?}"
        );
    }
}
