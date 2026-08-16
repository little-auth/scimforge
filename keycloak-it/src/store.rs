//! In-memory resource storage plus a raw-request capture log. The capture log exists
//! for exactly one reason: the Keycloak conformance test (`tests/keycloak_conformance.rs`)
//! needs to inspect the *literal* JSON body a real Keycloak SCIM-plugin instance sent,
//! not just this server's response -- that's the only way to tell "little-auth-scim parsed real
//! traffic correctly" apart from "this server's handler happened to produce the right
//! response regardless."
//!
//! capture() redacts known-sensitive fields (SCIM core User's password, the only
//! writeOnly attribute in the core schema) before the body is stored.

use std::collections::BTreeMap;

use serde_json::Value;

const REDACTED: &str = "[REDACTED]";

const SENSITIVE_ATTRIBUTES: &[&str] = &["password"];

fn is_sensitive_attribute(attr: &str) -> bool {
    SENSITIVE_ATTRIBUTES
        .iter()
        .any(|sensitive| attr.eq_ignore_ascii_case(sensitive))
}

/// Whether a PATCH `path` string addresses a sensitive attribute anywhere within it.
/// A real SCIM path addresses exactly one leaf attribute, but this capture log stores
/// the raw, pre-validation request body -- nothing stops a malformed or adversarial path
/// (e.g. `password.x`, `password[type eq "x"]`, or any other shape) from putting
/// "password" somewhere other than a bare top-level path while still being paired with
/// a `value` a naive check would miss. Rather than enumerating individual SCIM path
/// delimiters one at a time as new bypasses surface (this function has already been
/// fixed once for `:`/`.` alone, then again for a `[`-bracketed value-path filter --
/// RFC 7644 3.5.2's `attrPath "[" valFilter "]"` grammar, which this same crate's own
/// filter.rs parses elsewhere), this splits on the *inverse*: anything that ISN'T a
/// valid SCIM attribute-name character per RFC 7643's ATTRNAME grammar (`ALPHA
/// *(nameChar)`; `nameChar = "-" / "_" / DIGIT / ALPHA`). That treats every delimiter
/// -- `:`, `.`, `[`, `]`, quotes, spaces, comparison operators -- as a separator in one
/// principled sweep, closing the whole class of "which punctuation did the check forget"
/// bugs instead of the next specific instance of it.
fn path_targets_a_sensitive_attribute(path: &str) -> bool {
    path.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .filter(|segment| !segment.is_empty())
        .any(is_sensitive_attribute)
}

/// The keys in `map` that are candidates for `name`: the exact-case key alone if
/// present (the only one `patch_request.rs::parse_one`'s own exact-case-only lookup,
/// `raw.get("path")`/`raw.get("value")`, will ever actually read and apply), or --
/// only when no exact-case key exists at all -- *every* differently-cased key that
/// matches case-insensitively, not just one of them.
///
/// This function has been fixed twice already for the same underlying mistake: first
/// treating a bare case-insensitive `.find()` (whichever candidate sorts first in
/// serde_json's BTreeMap, uppercase before lowercase in ASCII) as authoritative even
/// when an exact-case key was also present, letting a decoy shadow the real key; then,
/// after fixing that, still only inspecting the first case-insensitive candidate in the
/// *fallback* path (no exact-case key present at all) -- an attacker could plant TWO
/// decoys (e.g. both `"PATH"` and `"Path"`, no lowercase `"path"`), and only the
/// lexicographically-first one ever got examined, so a second, sensitive-targeting
/// decoy went unnoticed. There is no way to know in advance which of several
/// simultaneously-present, equally law-abiding-looking case-variant keys "is" the
/// intended one when none of them is the canonical exact-case key, so every candidate
/// must be considered: return `true`/redact the value for `path` if *any* candidate
/// targets a sensitive attribute; redact *all* candidate `value` keys, not just one.
fn candidate_keys<'a>(map: &'a serde_json::Map<String, Value>, name: &str) -> Vec<&'a str> {
    if let Some((k, _)) = map.get_key_value(name) {
        return vec![k.as_str()];
    }
    map.keys()
        .filter(|k| k.eq_ignore_ascii_case(name))
        .map(String::as_str)
        .collect()
}

fn redact_sensitive(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if is_sensitive_attribute(key) {
                    *v = Value::String(REDACTED.to_string());
                } else {
                    redact_sensitive(v);
                }
            }
            let path_keys: Vec<String> = candidate_keys(map, "path")
                .into_iter()
                .map(str::to_string)
                .collect();
            // A "path" that isn't a plain string is malformed/adversarial input -- this
            // capture log stores the raw, pre-validation body, so nothing guarantees
            // `path` is even a string. Default to redacting rather than silently
            // trusting that an unexpected shape couldn't be targeting a sensitive
            // attribute. True if *any* candidate path key targets one.
            let targets_sensitive_attribute = path_keys.iter().any(|k| match map.get(k) {
                Some(Value::String(s)) => path_targets_a_sensitive_attribute(s),
                Some(_) => true,
                None => false,
            });
            if targets_sensitive_attribute {
                let value_keys: Vec<String> = candidate_keys(map, "value")
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                // Snapshot the authoritative value(s) *before* redacting, so an inert
                // sibling "value"-named key (any case) holding a verbatim duplicate of
                // that same secret text can also be caught below. When an exact-case
                // "value" key exists, candidate_keys above returns only that one --
                // correct for determining what's actually *applied* (patch_request.rs::
                // parse_one is exact-case-only), but a client that also happens to
                // duplicate the identical secret text under an inert, differently-cased
                // key (e.g. both "value" and "Value" holding the same string) would
                // otherwise leave that copy of the secret untouched right next to the
                // properly-redacted one, even though it's the same information.
                let authoritative_texts: Vec<Value> = value_keys
                    .iter()
                    .filter_map(|k| map.get(k.as_str()).cloned())
                    .collect();
                for value_key in &value_keys {
                    if let Some(v) = map.get_mut(value_key) {
                        *v = Value::String(REDACTED.to_string());
                    }
                }
                let duplicate_keys: Vec<String> = map
                    .iter()
                    .filter(|(k, v)| {
                        !value_keys.contains(k)
                            && k.eq_ignore_ascii_case("value")
                            && authoritative_texts.contains(v)
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in duplicate_keys {
                    if let Some(v) = map.get_mut(&key) {
                        *v = Value::String(REDACTED.to_string());
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_sensitive(item);
            }
        }
        _ => {}
    }
}

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
        mut body: Value,
    ) {
        redact_sensitive(&mut body);
        self.captured.push(CapturedRequest {
            resource_type,
            method,
            id,
            content_type,
            body,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn capture_redacts_a_top_level_password_on_create() {
        let mut store = Store::default();
        store.capture(
            "User",
            "POST",
            None,
            None,
            json!({"userName": "bjensen", "password": "correct horse battery staple"}),
        );
        let captured = &store.captured[0].body;
        assert_eq!(captured["password"], json!(REDACTED));
        assert_eq!(captured["userName"], json!("bjensen"));
        assert!(
            !captured
                .to_string()
                .contains("correct horse battery staple")
        );
    }

    #[test]
    fn capture_redaction_is_case_insensitive_on_the_key() {
        let mut store = Store::default();
        store.capture("User", "POST", None, None, json!({"Password": "secret"}));
        assert_eq!(store.captured[0].body["Password"], json!(REDACTED));
    }

    #[test]
    fn capture_redacts_a_patch_operation_targeting_password() {
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "password", "value": "new-secret"},
                    {"op": "replace", "path": "active", "value": "true"}
                ]
            }),
        );
        let body = &store.captured[0].body;
        assert_eq!(body["Operations"][0]["value"], json!(REDACTED));
        assert_eq!(body["Operations"][1]["value"], json!("true"));
        assert!(!body.to_string().contains("new-secret"));
    }

    #[test]
    fn capture_redacts_a_fully_qualified_schema_urn_patch_path() {
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "urn:ietf:params:scim:schemas:core:2.0:User:password",
                    "value": "new-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_a_dot_qualified_sub_attribute_patch_path() {
        // Regression: path_attribute_name only stripped a colon-delimited urn schema
        // prefix, never a dotted sub-attribute chain, so a path like "credentials.password"
        // (or any bogus, unvalidated path a client sends -- capture() logs the raw
        // pre-validation body) survived redaction with the plaintext value intact.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "credentials.password",
                    "value": "new-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_a_urn_qualified_dot_sub_attribute_patch_path() {
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:credentials.password",
                    "value": "new-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_a_path_with_password_as_a_non_trailing_segment() {
        // Regression: path_attribute_name (predecessor of
        // path_targets_a_sensitive_attribute) only checked the *last* colon/dot segment,
        // so a path like "password.x" -- syntactically "a sub-attribute of password",
        // which the real schema doesn't have but this pre-validation capture log doesn't
        // check -- extracted leaf "x", not "password", and left the paired value
        // unredacted. Checking every segment closes this regardless of position.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "password.x",
                    "value": "new-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_the_value_when_path_is_not_a_plain_string() {
        // Regression: `map.get("path").and_then(Value::as_str)` silently returned None
        // for a non-string path (this log stores the raw, unvalidated pre-parse body,
        // so nothing guarantees "path" is a string), skipping redaction entirely.
        // Default to redacting when "path" is present but not a plain string, rather
        // than trusting an unexpected shape couldn't be targeting a sensitive attribute.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{"op": "replace", "path": ["password"], "value": "new-secret"}]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_a_differently_cased_value_key() {
        // Regression: the path-target redaction did an exact-case map.get_mut("value")
        // lookup while the sibling per-attribute loop above it is deliberately
        // case-insensitive -- a captured Operation with a capitalized "Value" key
        // satisfied the path check but the write-back never found a "value" key,
        // leaving the capitalized one untouched.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{"op": "replace", "path": "password", "Value": "new-secret"}]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["Value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_a_differently_cased_path_key() {
        // Regression: unlike the "value" key lookup (fixed above), the "path" key
        // lookup itself was still exact-case (`map.get("path")`), so a captured
        // Operation with a capitalized "Path" key skipped the whole redaction branch
        // entirely, leaving the paired plaintext value untouched.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{"op": "replace", "Path": "password", "value": "new-secret"}]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_the_real_value_key_even_alongside_a_decoy_cased_one() {
        // Regression: the case-insensitive "value" lookup used `.find()`, which returns
        // only the FIRST case-insensitive match in serde_json's BTreeMap-sorted key
        // order (uppercase sorts before lowercase in ASCII). An object with BOTH a
        // decoy "Value" and the real, lowercase "value" -- the exact key
        // patch_request.rs::parse_one actually reads and applies -- got the decoy
        // redacted while the real, applied secret survived in plaintext.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "password",
                    "Value": "decoy",
                    "value": "true-plaintext-secret"
                }]
            }),
        );
        let recorded_op = &store.captured[0].body["Operations"][0];
        assert_eq!(recorded_op["value"], json!(REDACTED));
        assert_ne!(recorded_op["Value"], json!("true-plaintext-secret"));
    }

    #[test]
    fn capture_redacts_a_decoy_cased_value_key_that_duplicates_the_real_secret_text() {
        // Regression: candidate_keys returns ONLY the exact-case "value" key when one
        // exists, correctly reflecting that it's the sole key patch_request.rs::
        // parse_one actually applies -- but that reasoning only protects the *applied*
        // value. A client (malformed, buggy, or adversarial) that also duplicates the
        // identical secret text under an inert, differently-cased sibling key (both
        // "value" and "Value" holding the same string) left that copy of the secret
        // untouched right next to the properly-redacted one. The sibling test above
        // uses a distinguishable "decoy" placeholder, which masks this gap -- here the
        // decoy holds a verbatim copy of the real secret.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "password",
                    "value": "SECRET-TEXT",
                    "Value": "SECRET-TEXT"
                }]
            }),
        );
        let recorded_op = &store.captured[0].body["Operations"][0];
        assert_eq!(recorded_op["value"], json!(REDACTED));
        assert_eq!(recorded_op["Value"], json!(REDACTED));
        assert!(!store.captured[0].body.to_string().contains("SECRET-TEXT"));
    }

    #[test]
    fn capture_redacts_via_the_real_path_key_even_alongside_a_decoy_cased_one() {
        // Regression: same root cause as the value-key case, applied to "path". An
        // object with both a non-sensitive decoy "Path" (e.g. "userName") and the
        // real, lowercase "path": "password" -- the exact key patch_request.rs::
        // parse_one actually reads -- had the decoy examined first, its non-sensitive
        // target made the whole redaction branch skip, and the real password value
        // survived in plaintext despite the authoritative path targeting "password".
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "Path": "userName",
                    "path": "password",
                    "value": "true-plaintext-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_a_value_path_bracket_filtered_password_path() {
        // Regression: path_targets_a_sensitive_attribute only split on ':' and '.',
        // never RFC 7644 3.5.2's third path delimiter -- a value-path bracket filter
        // (`attrPath "[" valFilter "]"`, which this same crate's own filter.rs parses
        // elsewhere). A path like `password[type eq "x"]` produced one segment that
        // didn't equal "password" under either prior fix, leaving the paired value
        // unredacted. Splitting on anything that isn't a valid SCIM attribute-name
        // character closes this and any future punctuation-specific bypass at once.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": r#"password[type eq "x"]"#,
                    "value": "new-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_treats_the_path_as_sensitive_if_any_case_variant_candidate_targets_password() {
        // Regression: when no exact-case "path" key exists at all, the fallback used
        // to inspect only the first case-insensitive candidate in BTreeMap-sorted
        // order. Two decoy candidates with no lowercase "path" -- "PATH" (sorts
        // first, targets a non-sensitive attribute) and "Path" (targets "password")
        // -- meant only "PATH" got examined, the redaction branch was skipped
        // entirely, and the real secret survived untouched. Every candidate must be
        // considered, not just the lexicographically-first one.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "PATH": "userName",
                    "Path": "password",
                    "value": "real-plaintext-secret"
                }]
            }),
        );
        assert_eq!(
            store.captured[0].body["Operations"][0]["value"],
            json!(REDACTED)
        );
    }

    #[test]
    fn capture_redacts_every_case_variant_value_candidate_when_none_is_exact_case() {
        // Regression: same root cause applied to "value". With a real, exact-case
        // "path": "password" but no lowercase "value" key, two case-variant "value"
        // candidates ("VALUE" and "Value") meant only the sorted-first one ("VALUE")
        // got redacted, leaving the real secret under "Value" untouched -- an inert
        // decoy redacted gave a false sense that redaction had succeeded.
        let mut store = Store::default();
        store.capture(
            "User",
            "PATCH",
            Some("abc".to_string()),
            None,
            json!({
                "Operations": [{
                    "op": "replace",
                    "path": "password",
                    "VALUE": "decoy",
                    "Value": "real-plaintext-secret-2"
                }]
            }),
        );
        let recorded_op = &store.captured[0].body["Operations"][0];
        assert_eq!(recorded_op["VALUE"], json!(REDACTED));
        assert_eq!(recorded_op["Value"], json!(REDACTED));
    }

    #[test]
    fn capture_leaves_unrelated_fields_intact() {
        let mut store = Store::default();
        store.capture(
            "User",
            "POST",
            None,
            None,
            json!({
                "userName": "bjensen",
                "name": {"givenName": "Barbara", "familyName": "Jensen"},
                "emails": [{"value": "bjensen@example.com", "type": "work"}]
            }),
        );
        let body = &store.captured[0].body;
        assert_eq!(body["name"]["givenName"], json!("Barbara"));
        assert_eq!(body["emails"][0]["value"], json!("bjensen@example.com"));
    }
}
