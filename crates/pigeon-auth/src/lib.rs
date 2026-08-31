//! Message authentication: DKIM, SPF, DMARC, ARC, SRS.
//!
//! Wraps `mail-auth` behind a Pigeon-shaped API. This is the crate that decides
//! whether forwarded mail survives, so it carries the heaviest test burden.
//!
//! # Why forwarding needs all of this
//!
//! Relaying mail breaks SPF: the destination sees Pigeon's IP under the original
//! sender's domain, which is not authorised. Three mechanisms together fix it:
//!
//! 1. **SRS** rewrites the envelope sender to a Pigeon-owned domain, so SPF is
//!    evaluated against a domain that authorises this host. It also gives
//!    bounces a return path back to the original sender.
//! 2. **Payload preservation** keeps the author's DKIM signature intact,
//!    which is what actually satisfies DMARC alignment on `From:`. A
//!    conforming payload is relayed byte for byte; one carrying a bare CR or
//!    LF is transport-converted first, and one whose last line is
//!    unterminated gains the CRLF the end-of-data marker requires. See
//!    `ForwardPolicy::Preserve` and `M2-DESIGN.md` §2.
//! 3. **ARC sealing** records that the message authenticated correctly on
//!    arrival, which major receivers honour when DKIM breaks anyway.
//!
//! # Copies
//!
//! `mail-parser` borrows from the input buffer rather than allocating, and
//! hashing is streamed, so verification adds no copy of the message.
//!
//! It is not zero-copy end to end, and an earlier version of this comment said
//! it was. `DataReader` already materialises the received payload, and R-1
//! normalisation produces a second buffer — deliberately, since the normalised
//! form is what gets signed, spooled and sent, and deriving it once is what
//! makes a retry byte-identical to the first attempt.

#![forbid(unsafe_code)]

pub mod dkim;

pub use dkim::{DkimError, KeyPair};

// M2: SRS0/SRS1 encode+decode with replay window, DKIM verify/sign, ARC seal.
