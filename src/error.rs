//! RFC 7644 §3.12 HTTP Status and Error Response Handling: the `Error` message schema
//! and the canonical `scimType` detail-error keywords from the RFC's own Table 9, quoted
//! from the actual spec text (not from memory of "the usual SCIM error codes").

use serde::{Deserialize, Serialize};

pub const ERROR_SCHEMA_URI: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// RFC 7644 §3.12 Table 9: "SCIM Detail Error Keyword Values" -- verbatim from the
/// spec, each variant's doc comment is the table's own "Description" column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScimType {
    /// "The specified filter syntax was invalid... or the specified attribute and
    /// filter comparison combination is not supported."
    #[serde(rename = "invalidFilter")]
    InvalidFilter,
    /// "The specified filter yields many more results than the server is willing to
    /// calculate or process."
    #[serde(rename = "tooMany")]
    TooMany,
    /// "One or more of the attribute values are already in use or are reserved."
    #[serde(rename = "uniqueness")]
    Uniqueness,
    /// "The attempted modification is not compatible with the target attribute's
    /// mutability or current state (e.g., modification of an 'immutable' attribute with
    /// an existing value)."
    #[serde(rename = "mutability")]
    Mutability,
    /// "The request body message structure was invalid or did not conform to the
    /// request schema."
    #[serde(rename = "invalidSyntax")]
    InvalidSyntax,
    /// "The 'path' attribute was invalid or malformed."
    #[serde(rename = "invalidPath")]
    InvalidPath,
    /// "The specified 'path' did not yield an attribute or attribute value that could
    /// be operated on. This occurs when the specified 'path' value contains a filter
    /// that yields no match."
    #[serde(rename = "noTarget")]
    NoTarget,
    /// "A required value was missing, or the value specified was not compatible with
    /// the operation or attribute type, or resource schema."
    #[serde(rename = "invalidValue")]
    InvalidValue,
    /// "The specified SCIM protocol version is not supported."
    #[serde(rename = "invalidVers")]
    InvalidVers,
    /// "The specified request cannot be completed, due to the passing of sensitive
    /// (e.g., personal) information in a request URI."
    #[serde(rename = "sensitive")]
    Sensitive,
}

impl ScimType {
    /// The exact Table 9 keyword string -- always identical to what this variant
    /// serializes to via its `#[serde(rename)]`, so a caller building an error body by
    /// hand (rather than serializing a whole [`ScimError`]) still gets the RFC's literal
    /// text.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScimType::InvalidFilter => "invalidFilter",
            ScimType::TooMany => "tooMany",
            ScimType::Uniqueness => "uniqueness",
            ScimType::Mutability => "mutability",
            ScimType::InvalidSyntax => "invalidSyntax",
            ScimType::InvalidPath => "invalidPath",
            ScimType::NoTarget => "noTarget",
            ScimType::InvalidValue => "invalidValue",
            ScimType::InvalidVers => "invalidVers",
            ScimType::Sensitive => "sensitive",
        }
    }
}

/// RFC 7644 §3.12's Error message. `status` is "expressed as a JSON string. REQUIRED."
/// per the spec text -- deliberately a `String`, not a numeric HTTP status type, to
/// match that exactly (the RFC's own worked examples show `"status": "404"`, not `404`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(rename = "scimType", skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<ScimType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ScimError {
    /// Builds an Error response with `schemas` set to [`ERROR_SCHEMA_URI`] and `status`
    /// converted to the RFC-required string form (e.g. `400` becomes `"400"`, matching
    /// the RFC's own worked examples) -- a caller only supplies the HTTP status as a
    /// plain `u16`, not a pre-stringified one.
    pub fn new(status: u16, scim_type: Option<ScimType>, detail: impl Into<String>) -> Self {
        ScimError {
            schemas: vec![ERROR_SCHEMA_URI.to_string()],
            status: status.to_string(),
            scim_type,
            detail: Some(detail.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips RFC 7644 §3.12's own worked "mutability" example verbatim.
    #[test]
    fn deserializes_the_rfc_7644_mutability_example_verbatim() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "mutability",
            "detail": "Attribute 'id' is readOnly",
            "status": "400"
        }"#;
        let err: ScimError = serde_json::from_str(json).unwrap();
        assert_eq!(err.status, "400");
        assert_eq!(err.scim_type, Some(ScimType::Mutability));
        assert_eq!(err.detail.as_deref(), Some("Attribute 'id' is readOnly"));
    }

    #[test]
    fn scim_type_serializes_to_the_exact_rfc_table_9_keyword() {
        let err = ScimError::new(400, Some(ScimType::NoTarget), "no match");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["scimType"], "noTarget");
    }

    #[test]
    fn omits_scim_type_when_none_rather_than_serializing_null() {
        let err = ScimError::new(404, None, "not found");
        let json = serde_json::to_value(&err).unwrap();
        assert!(json.get("scimType").is_none());
    }
}
