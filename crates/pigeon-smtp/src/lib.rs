//! SMTP protocol: inbound receiver and outbound delivery client.
//!
//! # Layering
//!
//! [`command`] and [`session`] are pure: bytes in, decisions out, no sockets
//! and no runtime. The protocol is therefore testable without I/O, which
//! matters because the properties most worth testing — command sequencing,
//! limits, and what survives STARTTLS — are the ones hardest to observe from
//! outside a live connection.
//!
//! The I/O layer sits above them and does as little thinking as possible.
//!
//! # Receiver
//!
//! Unknown recipients are rejected at `RCPT TO`, before the sender transmits
//! DATA. This matters more than it looks: Pigeon retains nothing after
//! delivery, so anything accepted and later undeliverable has to be bounced —
//! and bouncing mail that should have been refused makes Pigeon a backscatter
//! source.
//!
//! `250` is returned only after the message is durably on disk and its queue
//! row is committed. Never before.
//!
//! # Zero-copy contract
//!
//! Commands are parsed from `&[u8]` with no intermediate `String`; a parsed
//! command is two or three subslices of bytes that already exist. DATA is read
//! into `BytesMut` and frozen into `Bytes`, so handing the same message to N
//! destinations costs N refcount bumps rather than N copies.
//!
//! Envelopes are the deliberate exception. A sender and its recipients outlive
//! the individual command lines they were read from, so [`session::Envelope`]
//! owns its strings — a few small allocations per transaction, not per byte.

#![forbid(unsafe_code)]

pub mod client;
pub mod codec;
pub mod command;
pub mod reply;
pub mod server;
pub mod session;

pub use client::{Accepted, ClientError, deliver};
pub use codec::{DataReader, DataStatus, LineError, LineReader};
pub use command::{Command, ParseError, parse};
pub use reply::Reply;
pub use server::{MessageSink, ServerConfig, serve};
pub use session::{Action, DataError, Envelope, Message, Session, State};

/// Largest message Pigeon will accept, before per-domain policy narrows it.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024;

// M0: tokio listener wiring these four modules together, and the delivery client.
