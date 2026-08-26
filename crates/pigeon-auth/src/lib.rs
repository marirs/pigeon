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
//! 2. **Byte-for-byte body preservation** keeps the author's DKIM signature
//!    intact, which is what actually satisfies DMARC alignment on `From:`.
//! 3. **ARC sealing** records that the message authenticated correctly on
//!    arrival, which major receivers honour when DKIM breaks anyway.
//!
//! # Zero-copy contract
//!
//! `mail-parser` borrows from the input buffer rather than allocating, and body
//! hashing is streamed. A message is canonicalised and hashed without ever
//! materialising a second copy.

#![forbid(unsafe_code)]

// M2: SRS0/SRS1 encode+decode with replay window, DKIM verify/sign, ARC seal.
