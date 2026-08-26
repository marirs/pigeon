//! SQLite storage: schema, migrations, repositories.
//!
//! Holds routing configuration and queue metadata. Message bodies never enter
//! the database; they live in the spool.
//!
//! Rules that are not negotiable:
//! - parameterised queries only, never string-built SQL
//! - foreign keys on
//! - migrations run inside a transaction
//! - WAL mode

#![forbid(unsafe_code)]

// M1: migration runner, domain/alias/destination repositories.
