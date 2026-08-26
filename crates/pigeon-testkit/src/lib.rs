//! Test harness shared across the workspace. Not published.
//!
//! An SMTP server is awkward to test by hand, and the properties that matter
//! most are the ones that are easiest to regress silently. This crate provides
//! the fixtures for them:
//!
//! - a scriptable SMTP peer that can be told to fail, stall or misbehave
//! - a fake resolver returning canned and deliberately malformed DNS
//! - signed message fixtures for DKIM/ARC round-trips
//!
//! The anti-open-relay suite is the release gate. It must cover every
//! combination of authenticated/unauthenticated sender against local/remote
//! recipient.

#![forbid(unsafe_code)]

// M0: scriptable SMTP peer. M4: fake resolver. M7: open-relay matrix.
