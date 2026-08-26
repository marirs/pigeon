//! DNS resolution and record validation.
//!
//! Answers one question per domain: are the published records correct enough
//! for this domain to carry mail?
//!
//! Findings are graded `Fatal` / `Error` / `Warning` / `Info`. A domain reaches
//! `Active` only with no `Fatal` or `Error` findings.
//!
//! DNS output is untrusted input: malformed records, oversized responses,
//! split TXT chunks, CNAME chains and resolver timeouts are all expected and
//! must be handled without panicking.

#![forbid(unsafe_code)]

// M5: MX, A/AAAA, PTR, SPF, DKIM selector, DMARC, TLS reachability.
