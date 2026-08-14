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
    /// `items_per_page` is derived from `resources.len()`, not a separate parameter --
    /// RFC 7644 §3.4.2's `itemsPerPage` is defined as the count actually returned on this
    /// page, so there's no independent value for a caller to get out of sync with the
    /// `resources` it's also passing in. `total_results` (the count across every page,
    /// not just this one) has no such derivation and is the caller's own to supply.
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
///
/// # `count` has no upper bound -- callers MUST impose their own before using it
///
/// `from_request` only clamps `count`'s *lower* bound (negative -> 0); it never caps the
/// upper bound, so a client-supplied `count=9223372036854775807` (`i64::MAX`) round-trips
/// into `Pagination::count` completely unchanged. That is intentional here -- RFC 7644
/// leaves the ceiling to "the service provider," not this crate -- but it means **this
/// value is not safe to hand directly to an allocation or a database `LIMIT`/page-size
/// parameter**. For example, `Vec::with_capacity(pagination.count.unwrap() as usize)` or
/// `format!("LIMIT {}", pagination.count.unwrap())` fed straight from an untrusted
/// `count` query parameter lets a single request request an enormous allocation or an
/// unbounded scan. Integrators MUST apply their own ceiling to `count` before using it
/// for anything resource-affecting -- see [`Pagination::clamped`] for an ergonomic way to
/// do so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    pub start_index: u64,
    pub count: Option<u64>,
}

impl Pagination {
    /// `raw_start_index`/`raw_count` are the query parameters as received (already
    /// `i64` to represent "could be negative or absent" before clamping -- pass `None`
    /// for an omitted `count`, matching "if unspecified" in the spec text).
    ///
    /// `count`'s lower bound is clamped (negative -> 0) but **no upper bound is
    /// applied** -- see the type-level docs on [`Pagination`] for why, and for how to
    /// apply your own ceiling via [`Pagination::clamped`].
    pub fn from_request(raw_start_index: Option<i64>, raw_count: Option<i64>) -> Self {
        let start_index = raw_start_index.map(|v| v.max(1) as u64).unwrap_or(1);
        let count = raw_count.map(|v| v.max(0) as u64);
        Pagination { start_index, count }
    }

    /// Opt-in helper that caps `count` at `max_count`, leaving `start_index` and an
    /// unset (`None`) `count` untouched. `from_request` deliberately leaves `count`
    /// unbounded above (RFC 7644 §3.4.2.4 makes the ceiling "the service provider['s]"
    /// decision, not this crate's), so nothing calls this automatically -- integrators
    /// who plan to use `count` for allocation sizing or a database `LIMIT` should chain
    /// it themselves: `Pagination::from_request(start, count).clamped(500)`.
    #[must_use]
    pub fn clamped(self, max_count: u64) -> Self {
        Pagination {
            count: self.count.map(|c| c.min(max_count)),
            ..self
        }
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

    #[test]
    fn pagination_from_request_applies_no_upper_bound_to_count_by_default() {
        assert_eq!(
            Pagination::from_request(None, Some(i64::MAX)).count,
            Some(i64::MAX as u64)
        );
    }

    #[test]
    fn pagination_clamped_caps_an_oversized_count_at_the_given_ceiling() {
        let pagination = Pagination::from_request(None, Some(i64::MAX)).clamped(500);
        assert_eq!(pagination.count, Some(500));
    }

    #[test]
    fn pagination_clamped_leaves_a_count_already_under_the_ceiling_unchanged() {
        let pagination = Pagination::from_request(None, Some(10)).clamped(500);
        assert_eq!(pagination.count, Some(10));
    }

    #[test]
    fn pagination_clamped_leaves_an_unset_count_unset() {
        let pagination = Pagination::from_request(None, None).clamped(500);
        assert_eq!(pagination.count, None);
    }

    #[test]
    fn pagination_clamped_leaves_start_index_untouched() {
        let pagination = Pagination::from_request(Some(42), Some(i64::MAX)).clamped(1);
        assert_eq!(pagination.start_index, 42);
    }
}
