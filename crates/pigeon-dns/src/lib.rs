//! DNS resolution and record validation.
//!
//! Two jobs live here, and they are kept apart deliberately.
//!
//! **Deciding things**, such as which host to deliver to and whether a domain's
//! published records are good enough to carry mail, is pure logic over records
//! the caller supplies. It is testable without a resolver, without a network,
//! and without waiting — see [`mx`].
//!
//! **Asking DNS** is a thin adapter over a resolver library, and is the only
//! part that needs I/O.
//!
//! Validation findings are graded `Fatal` / `Error` / `Warning` / `Info`. A
//! domain reaches `Active` only with no `Fatal` or `Error` findings.
//!
//! DNS output is untrusted input: malformed records, oversized responses,
//! split TXT chunks, CNAME chains and resolver timeouts are all expected and
//! must be handled without panicking.

#![forbid(unsafe_code)]

pub mod dnsbl;
pub mod mx;
pub mod resolver;

pub use mx::{MxError, MxRecord, order_hosts};
pub use resolver::{FakeResolver, LookupError, MxLookup, SystemResolver};

// M5: MX, A/AAAA, PTR, SPF, DKIM selector, DMARC, TLS reachability.
