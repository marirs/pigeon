//! SMTP protocol: inbound receiver and outbound delivery client.
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
//! Commands are parsed from `&[u8]` with no intermediate `String`. DATA is read
//! into `BytesMut` and frozen into `Bytes`, so handing the same message to N
//! destinations costs N refcount bumps rather than N copies.

#![forbid(unsafe_code)]

// M0: EHLO/MAIL/RCPT/DATA/QUIT, STARTTLS, timeouts, limits.
