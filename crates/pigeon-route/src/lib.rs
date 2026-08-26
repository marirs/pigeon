//! Recipient routing.
//!
//! Loads an immutable snapshot from the database and answers "where does this
//! address go?" without touching SQLite on the hot path. Swapping in a new
//! snapshot is atomic; an invalid update never replaces a live one.
//!
//! Precedence, highest first:
//!
//! ```text
//! reject rule  ->  exact alias  ->  wildcard (longest match)  ->  catch-all  ->  reject
//! ```
//!
//! Plus-addressing is stripped before matching when the domain enables it, so
//! `hello+github@example.com` resolves through the `hello` alias.
//!
//! An alias with no destination is a reject rule. A domain carries a default
//! destination that its aliases inherit unless given their own, so the common
//! case — many addresses across many domains landing in one mailbox — stores
//! and states that mailbox once.
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

// M1: snapshot build, precedence resolution, glob wildcard matching.
