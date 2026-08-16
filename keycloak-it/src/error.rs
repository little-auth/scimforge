//! Maps this server's internal error conditions to RFC 7644 §3.12 `Error` responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use little_auth_scim::error::{ScimError, ScimType};
use little_auth_scim::patch::PatchError;

use crate::patch_request::PatchRequestError;

pub enum ApiError {
    NotFound(String),
    InvalidBody(String),
    Patch(PatchError),
    PatchRequest(PatchRequestError),
    Unauthorized,
}

impl From<PatchError> for ApiError {
    fn from(e: PatchError) -> Self {
        ApiError::Patch(e)
    }
}

impl From<PatchRequestError> for ApiError {
    fn from(e: PatchRequestError) -> Self {
        ApiError::PatchRequest(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, scim_type, detail) = match self {
            ApiError::NotFound(id) => (
                StatusCode::NOT_FOUND,
                None,
                format!("no resource with id '{id}'"),
            ),
            ApiError::InvalidBody(detail) => (
                StatusCode::BAD_REQUEST,
                Some(ScimType::InvalidValue),
                detail,
            ),
            ApiError::Patch(e) => (
                StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
                Some(e.scim_type()),
                format!("{e:?}"),
            ),
            ApiError::PatchRequest(e) => (
                StatusCode::BAD_REQUEST,
                Some(ScimType::InvalidSyntax),
                format!("{e:?}"),
            ),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                None,
                "missing or invalid bearer token".to_string(),
            ),
        };
        let body = ScimError::new(status.as_u16(), scim_type, detail);
        (status, Json(body)).into_response()
    }
}
