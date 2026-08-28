//! Recipient routing.
//!
//! Loads an immutable snapshot from the database and answers "where does this
//! address go?" without touching SQLite on the hot path. Swapping in a new
//! snapshot is atomic; an invalid update never replaces a live one.
//!
//! Precedence, highest first:
//!
//! ```text
//! exact alias  ->  wildcard (most literal characters)  ->  catch-all  ->  reject
//! ```
//!
//! The most specific matching rule wins and that rule decides whether mail is
//! forwarded or refused. Reject is not a tier above the others: one pattern has
//! exactly one rule, so no two rules of equal specificity can both match, and a
//! wildcard reject must not silently disable an address the operator named.
//! See `docs/M1-SNAPSHOT.md` §2.
//!
//! Plus-addressing is **not** simply stripped before matching. Stripping first
//! would make `hello+github@` unable to have an alias of its own; matching the
//! full local part all the way down would send every tagged address to the
//! catch-all before the alias its base names. So both forms are used, in this
//! order:
//!
//! ```text
//! 1. exact alias, full local part
//! 2. exact alias, base local part          (only when a tag was stripped)
//! 3. wildcards matching either form, ranked once by precedence
//! 4. catch-all
//! 5. reject unknown
//! ```
//!
//! Both exact lookups precede every wildcard, so exact still beats wildcard.
//! Both forms reach the wildcard tier, so `hello+*` matches `hello+github` —
//! which an earlier design could not, because the wildcard tier only ever saw
//! the base. See `docs/M1-SNAPSHOT.md` §4.
//!
//! An alias with no destination **inherits the domain default**; the absence is
//! the encoding, and it is what `pigeon domain forward` moves. A reject rule is
//! a separate kind, and also carries no destinations — which is why the two are
//! distinguished by a column rather than by counting rows. A domain carries a
//! default destination that its aliases inherit unless given their own, so the
//! common case — many addresses across many domains landing in one mailbox —
//! stores and states that mailbox once.
//!
//! Catch-all and aliases coexist rather than excluding each other. Catch-all
//! takes the long tail; aliases carry the addresses that route elsewhere, fan
//! out to several destinations, or are refused. An alias resolving to the same
//! destination as the catch-all is redundant — reported to the operator, never
//! rejected, since it becomes meaningful again the moment the catch-all
//! destination changes.
//!
//! Enabling catch-all has a cost the routing layer should make visible: every
//! address on the domain then resolves, so recipient rejection at `RCPT TO`
//! no longer applies and dictionary attacks are accepted rather than refused.
//!
//! # Loops are rejected when configured, not when mail arrives
//!
//! Forwarding an address to itself, or around a cycle of managed domains, is
//! refused at the point the alias is added. The snapshot builder walks the
//! destination chain through every managed domain before committing.
//!
//! This is checked here rather than at delivery because the runtime symptom
//! resembles nothing like the cause: messages multiply through the queue,
//! delivery counters climb, and the offending alias looks correct in
//! isolation. Delivery-time detection remains as a backstop for chains that
//! leave and re-enter through systems Pigeon cannot see.
//!
//! # Zero-copy contract
//!
//! Lookups take `pigeon_types::Address<'_>` and return borrows into the
//! snapshot. Resolving a recipient allocates nothing.

#![forbid(unsafe_code)]

pub mod fold;
pub mod load;
pub mod mutate;
pub mod pattern;
pub mod reload;
pub mod router;
pub mod snapshot;

pub use load::{LoadError, load};
pub use mutate::{MutationError, Outcome, mutate, preview};
pub use pattern::{PatternError, Wildcard};
pub use reload::{InitialError, Tick, Watcher};
pub use router::Router;
pub use snapshot::{
    AliasInput, BuildError, Built, CatchAllInput, Decision, Destination, DomainInput, Report, Rule,
    Snapshot, Tier,
};
