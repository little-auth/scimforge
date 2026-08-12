//! RFC 7644 §3.4.2 ListResponse and §3.4.2.4 pagination request parameters.

use serde::{Deserialize, Serialize};

pub const LIST_RESPONSE_SCHEMA_URI: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: u64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: u64,
    /// 1-based per RFC 7644 §3.4.2 -- never 0, even for an empty result set on an empty
    /// collection (§3.4.2.4's clamping rule applies to the *request* parameter; a
    /// response describing zero total results still reports where in the (empty)
    /// sequence this page starts, which is index 1).
    #[serde(rename = "startIndex")]
    pub start_index: u64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ListResponse<T> {
    pub fn new(resources: Vec<T>, total_results: u64, start_index: u64) -> Self {
        let items_per_page = resources.len() as u64;
        ListResponse {
            schemas: vec![LIST_RESPONSE_SCHEMA_URI.to_string()],
            total_results,
            items_per_page,
            start_index,
            resources,
        }
    }
}

/// The client-supplied `startIndex`/`count` query parameters, clamped per RFC 7644
/// §3.4.2.4's exact wording: "A value less than 1 SHALL be interpreted as 1" for
/// `startIndex`, "A negative value SHALL be interpreted as '0'" for `count`. `count`
/// itself has no server-imposed ceiling applied here (the spec: "the maximum number of
/// results is set by the service provider" -- a caller's own limit, not this crate's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    pub start_index: u64,
    pub count: Option<u64>,
}

impl Pagination {
    /// `raw_start_index`/`raw_count` are the query parameters as received (already
    /// `i64` to represent "could be negative or absent" before clamping -- pass `None`
    /// for an omitted `count`, matching "if unspecified" in the spec text).
    pub fn from_request(raw_start_index: Option<i64>, raw_count: Option<i64>) -> Self {
        let start_index = raw_start_index.map(|v| v.max(1) as u64).unwrap_or(1);
        let count = raw_count.map(|v| v.max(0) as u64);
        Pagination { start_index, count }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_response_reports_the_correct_items_per_page_for_the_returned_page() {
        let resp = ListResponse::new(vec!["a", "b", "c"], 50, 1);
        assert_eq!(resp.items_per_page, 3);
        assert_eq!(resp.total_results, 50);
    }

    #[test]
    fn list_response_serializes_resources_under_the_capital_r_key() {
        let resp = ListResponse::new(vec![1, 2], 2, 1);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("Resources").is_some());
        assert!(json.get("resources").is_none());
    }

    #[test]
    fn pagination_clamps_start_index_below_one_up_to_one() {
        assert_eq!(Pagination::from_request(Some(0), None).start_index, 1);
        assert_eq!(Pagination::from_request(Some(-100), None).start_index, 1);
        assert_eq!(Pagination::from_request(Some(1), None).start_index, 1);
        assert_eq!(Pagination::from_request(Some(42), None).start_index, 42);
    }

    #[test]
    fn pagination_defaults_start_index_to_one_when_omitted() {
        assert_eq!(Pagination::from_request(None, None).start_index, 1);
    }

    #[test]
    fn pagination_clamps_negative_count_to_zero() {
        assert_eq!(Pagination::from_request(None, Some(-5)).count, Some(0));
    }

    #[test]
    fn pagination_leaves_count_unset_when_omitted_rather_than_defaulting_to_zero() {
        // RFC 7644: "If unspecified, the maximum number of results is set by the
        // service provider" -- omitted must stay None (caller decides), never silently
        // become Some(0) (which would mean "return nothing," a very different thing).
        assert_eq!(Pagination::from_request(None, None).count, None);
    }
}
