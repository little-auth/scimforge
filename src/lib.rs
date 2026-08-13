// The crate's rustdoc front page is the README verbatim, not a separate summary that can
// drift out of sync with it -- and its code blocks are real doctests, run by `cargo test
// --doc` in CI, not prose that could silently stop matching the actual API.
#![doc = include_str!("../README.md")]
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
