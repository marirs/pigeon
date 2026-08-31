//! Durable spool and delivery queue.
//!
//! # Acceptance ordering
//!
//! ```text
//! receive DATA -> write temp file -> fsync -> atomic rename into spool
//!   -> SQLite transaction creates queue row -> reply 250
//! ```
//!
//! Reversing any two of those steps loses mail across a crash.
//!
//! # Retention
//!
//! Pigeon is a relay, not a mailbox. A message body is deleted once every
//! recipient reaches a terminal state. Delivery *metadata* is retained
//! separately and configurably, because without it queue inspection and
//! debugging are guesswork.
//!
//! Because nothing is archived, `Dead` is irreversible — so the retry schedule
//! is deliberately generous (the ~5 day SMTP convention) before giving up.
//!
//! # Queue ownership
//!
//! Workers claim messages with a time-bounded lease. A worker that dies mid
//! delivery must not hide its message forever; the lease expires and the
//! message becomes claimable again.
//!
//! Spool filenames are generated identifiers, never sender or recipient text,
//! and all path resolution stays inside the configured spool root.

#![forbid(unsafe_code)]

pub mod store;

pub use store::{InvalidSpoolId, Spool, SpoolError, SpoolId};

// M3: lease-based claim, exponential backoff, bounce via SRS. The writer is
// in `store`.
