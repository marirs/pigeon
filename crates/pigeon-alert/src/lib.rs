//! Operator notifications for health transitions.
//!
//! Pigeon has no dashboard, so when a domain stops carrying mail the operator
//! finds out by email. This crate decides *whether* to send, *who* to send as,
//! and *where* to send — none of which is as obvious as it first looks.
//!
//! # The suppression paradox
//!
//! An alert must never be sent as the domain it is reporting on.
//!
//! Consider `example.com` whose DKIM record was deleted. Sending
//! `alerts@example.com` → the operator produces an unsigned message from a
//! domain publishing `p=reject`. The receiver discards it. The alert is
//! destroyed by precisely the fault it exists to report, and the operator
//! learns nothing.
//!
//! So alerts originate from a single operator-designated notification identity
//! on a domain the operator keeps healthy. That identity is never gated by
//! domain health, and Pigeon refuses to start if it is misconfigured — an
//! unusable alert path is itself a critical local failure.
//!
//! # Storms
//!
//! Domain health is not independent. A resolver outage fails every domain in
//! the same check cycle, so the naive implementation emits one alert per domain
//! per cycle, indefinitely.
//!
//! Four mechanisms, in order of how much noise they remove:
//!
//! 1. **Transitions, not states.** Alert when a domain moves healthy → failing.
//!    A domain that is still failing is not news.
//! 2. **Confirmation window.** Require N consecutive failed checks before a
//!    transition counts. A single resolver timeout is noise, not an outage.
//! 3. **Circuit breaker.** If more than a configured share of domains fail in
//!    one cycle, the resolver is the fault, not the domains. Suppress the
//!    per-domain alerts and send one message about the resolver instead.
//! 4. **Cooldown.** At most one alert per domain per window, however many times
//!    it flaps.
//!
//! Recovery notices matter as much as failures. Without them the operator has
//! no way to tell a fixed domain from a forgotten one, and learns to ignore the
//! channel.
//!
//! # Delivery path
//!
//! Alerts are delivered out of band and never traverse the routing engine.
//! Routing them normally would let an alert be caught by a catch-all, loop
//! between two Pigeon-managed domains, or be gated by the very domain it
//! concerns.
//!
//! # This channel can fail silently
//!
//! Email alerting about email infrastructure shares a failure domain with the
//! thing it monitors. If outbound port 25 is blocked or the host lands on a
//! blocklist, alerts stop arriving and the silence looks identical to health.
//!
//! Email is therefore the convenient channel, not the authoritative one.
//! `pigeon status`, the exit codes and the structured log remain the source of
//! truth, and an operator who depends on alerts should add a channel that does
//! not share this failure domain.

#![forbid(unsafe_code)]

/// What an alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// A domain's required DNS records regressed and it has been gated.
    DomainGated,
    /// A previously gated domain passed its checks again.
    DomainRecovered,
    /// Enough domains failed at once to implicate the resolver rather than the
    /// domains. Sent once, in place of the individual alerts.
    ResolverSuspect,
    /// The TLS certificate is approaching expiry.
    CertificateExpiring,
    /// The queue is growing faster than it drains.
    QueueBacklog,
    /// The spool filesystem is running out of space.
    DiskPressure,
}

impl AlertKind {
    /// Whether this alert reports a problem starting rather than ending.
    #[inline]
    pub fn is_failure(&self) -> bool {
        !matches!(self, Self::DomainRecovered)
    }
}

/// How an alert's recipient is chosen.
///
/// Deliberately *not* "every destination of every alias on the domain". A
/// domain with six aliases may forward to six unrelated people, none of whom
/// asked to be paged about DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertRecipient {
    /// A `notify` address set explicitly on the domain. Highest precedence.
    DomainNotify,
    /// The global operator address from the bootstrap configuration.
    GlobalOperator,
}

/// Why an alert was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppression {
    /// The domain was already failing; this is not a new transition.
    NotATransition,
    /// Failure has not yet persisted for the confirmation window.
    Unconfirmed,
    /// The circuit breaker tripped; a resolver alert was sent instead.
    CircuitBreaker,
    /// An alert for this domain was sent within the cooldown window.
    Cooldown,
    /// The only available recipient is on the failing domain itself, so the
    /// alert could not be delivered. Falls back to the global operator address.
    RecipientUnreachable,
}

// M5: transition tracking, confirmation window, circuit breaker, cooldown.
// M5: message rendering — reuse the `pigeon domain check` diff output, which
//     already states observed vs expected and the exact record to publish.
