//! In-memory resource storage plus a raw-request capture log. The capture log exists
//! for exactly one reason: the Keycloak conformance test (`tests/keycloak_conformance.rs`)
//! needs to inspect the *literal* JSON body a real Keycloak SCIM-plugin instance sent,
//! not just this server's response -- that's the only way to tell "scimitar parsed real
//! traffic correctly" apart from "this server's handler happened to produce the right
//! response regardless."

use std::collections::BTreeMap;

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub resource_type: &'static str,
    pub method: &'static str,
    pub id: Option<String>,
    pub content_type: Option<String>,
    pub body: Value,
}

#[derive(Debug, Default)]
pub struct Store {
    pub users: BTreeMap<String, Value>,
    pub groups: BTreeMap<String, Value>,
    pub captured: Vec<CapturedRequest>,
}

impl Store {
    pub fn capture(
        &mut self,
        resource_type: &'static str,
        method: &'static str,
        id: Option<String>,
        content_type: Option<String>,
        body: Value,
    ) {
        self.captured.push(CapturedRequest {
            resource_type,
            method,
            id,
            content_type,
            body,
        });
    }
}
