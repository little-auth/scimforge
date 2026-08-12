//! SCIM 2.0 (RFC 7643, RFC 7644) server-side protocol implementation.
//!
//! Storage-agnostic: this crate owns schema types, the RFC 7644 §3.4.2.2 filter
//! grammar, and RFC 7644 §3.5.2 PATCH semantics; callers provide their own
//! resource storage.

#![forbid(unsafe_code)]

pub mod bulk;
pub mod common;
pub mod discovery;
pub mod error;
pub mod filter;
pub mod group;
pub mod list_response;
pub mod patch;
pub mod user;
