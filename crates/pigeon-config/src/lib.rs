//! Bootstrap configuration.
//!
//! Only machine identity lives here: hostname, listener addresses, database and
//! spool paths, TLS material, and the SRS secret. Mail-domain configuration is
//! *not* in TOML — it lives in SQLite and changes through the CLI.
//!
//! Everything this crate validates is local and unambiguous, so a failure here
//! aborts startup (see `pigeond`).

#![forbid(unsafe_code)]

// M1: Config struct, TOML deserialisation, path/permission validation.
