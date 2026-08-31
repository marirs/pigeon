//! Core Pigeon domain types.
//!
//! This crate performs no I/O and pulls in no runtime. Everything else in the
//! workspace depends on it, so it must stay small and cheap to compile.
//!
//! # Zero-copy contract
//!
//! Parsing types here borrow from a caller-owned buffer ([`Address`]) and never
//! allocate. Owned variants exist for the few places a value must outlive its
//! input or cross a task boundary ([`AddressBuf`]).
//!
//! Message bodies are never represented here. They live in `pigeon-spool` as
//! `bytes::Bytes` so that fanning one message out to N destinations costs N
//! refcount bumps rather than N copies.

#![forbid(unsafe_code)]

pub mod address;
pub mod datetime;
pub mod domain;

pub use address::{Address, AddressBuf, AddressError};
pub use datetime::{days_from_civil, rfc3339_utc, rfc5322_date};
pub use domain::{DeliveryMode, DomainGate, DomainStatus, ForwardPolicy};
