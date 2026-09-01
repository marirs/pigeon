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

// ---------------------------------------------------------------- the decider

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How the four suppression rules are configured.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Consecutive failed checks before a domain counts as failing.
    ///
    /// One is not zero: a single resolver timeout is noise, and alerting on it
    /// teaches the operator that the channel is noise too.
    pub confirm_checks: u32,
    /// At most one alert per domain per window, however much it flaps.
    pub cooldown: Duration,
    /// The share of checked domains failing at once that implicates the
    /// resolver rather than the domains.
    pub breaker_threshold: f64,
}

/// What one cycle of checks decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Alerts to send, in the order they were decided.
    pub send: Vec<Alert>,
    /// What was not sent, and why. Kept because "no alert" is a thing an
    /// operator asks about, and "we suppressed it, here is the rule" is an
    /// answer where silence is not.
    pub suppressed: Vec<(String, Suppression)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    /// The domain this is about. Empty for [`AlertKind::ResolverSuspect`],
    /// which is about the host.
    pub domain: String,
    pub detail: String,
}

/// Tracks health across cycles so a transition can be told from a repetition.
///
/// In memory rather than in the database, deliberately. A restart forgetting
/// that a domain was already failing costs one duplicate alert; a restart
/// forgetting that it was *healthy* costs nothing at all, because the next
/// cycle re-derives it. Persisting it would buy the smaller of those two and
/// add a write to a path whose whole job is to observe.
#[derive(Debug, Default)]
pub struct Tracker {
    domains: HashMap<String, Health>,
}

#[derive(Debug, Clone, Default)]
struct Health {
    /// Consecutive failures observed, reset by any pass.
    failures: u32,
    /// Whether this domain is currently considered failing.
    failing: bool,
    /// Whether the operator was *told* it is failing.
    ///
    /// Separate from `failing`, because the suppression rules are about the
    /// mail Pigeon sends and not about the domain's state. A recovery notice is
    /// only sent for a failure that was reported: otherwise a flapping domain
    /// produces a stream of "recovered" messages about incidents nobody was
    /// ever told had started.
    alerted: bool,
    /// When a *failure* alert about it was last sent. Recovery notices do not
    /// stamp it — they close an incident rather than opening one.
    last_alert: Option<Instant>,
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide what to send about one cycle's results.
    ///
    /// `results` is every domain checked and whether it passed. The whole cycle
    /// is taken at once because the circuit breaker is a statement about the
    /// cycle: whether the resolver is the fault cannot be decided one domain at
    /// a time.
    pub fn cycle(&mut self, results: &[(String, bool)], policy: &Policy, now: Instant) -> Decision {
        let mut decision = Decision {
            send: Vec::new(),
            suppressed: Vec::new(),
        };

        if results.is_empty() {
            return decision;
        }

        let failing_now = results.iter().filter(|(_, ok)| !ok).count();
        let share = failing_now as f64 / results.len() as f64;

        // The breaker first, because it changes what every other rule is
        // allowed to do. Enough domains failing at once is evidence about the
        // resolver, not about forty independent zones — and forty alerts would
        // bury the one message that says what is actually wrong.
        //
        // A single domain failing can never trip it: one out of one is a share
        // of 1.0, and a host with one domain would otherwise never get a domain
        // alert at all.
        let tripped = results.len() > 1 && share >= policy.breaker_threshold;

        for (domain, ok) in results {
            let health = self.domains.entry(domain.clone()).or_default();

            if *ok {
                let recovered = health.failing;
                health.failures = 0;
                health.failing = false;

                // Recovery notices matter as much as failures: without them an
                // operator cannot tell a fixed domain from a forgotten one, and
                // learns to ignore the channel.
                if recovered && health.alerted {
                    health.alerted = false;
                    decision.send.push(Alert {
                        kind: AlertKind::DomainRecovered,
                        domain: domain.clone(),
                        detail: "its DNS records pass every check again".into(),
                    });
                }
                continue;
            }

            health.failures += 1;

            if health.failures < policy.confirm_checks {
                decision
                    .suppressed
                    .push((domain.clone(), Suppression::Unconfirmed));
                continue;
            }

            if health.failing {
                // Still failing is not news.
                decision
                    .suppressed
                    .push((domain.clone(), Suppression::NotATransition));
                continue;
            }

            // Confirmed, and new. The domain is failing from now on whatever
            // happens to the alert — the state is about the domain, and the
            // suppression rules are about the mail we send ourselves.
            health.failing = true;

            if tripped {
                decision
                    .suppressed
                    .push((domain.clone(), Suppression::CircuitBreaker));
                continue;
            }

            if let Some(last) = health.last_alert
                && now.duration_since(last) < policy.cooldown
            {
                decision
                    .suppressed
                    .push((domain.clone(), Suppression::Cooldown));
                continue;
            }

            health.last_alert = Some(now);
            health.alerted = true;
            decision.send.push(Alert {
                kind: AlertKind::DomainGated,
                domain: domain.clone(),
                detail: "its DNS records no longer pass, so it has stopped accepting mail".into(),
            });
        }

        if tripped {
            decision.send.push(Alert {
                kind: AlertKind::ResolverSuspect,
                domain: String::new(),
                detail: format!(
                    "{failing_now} of {} domains failed their checks in one cycle, which \
                     implicates the resolver rather than the domains",
                    results.len()
                ),
            });
        }

        decision
    }

    /// Whether a domain is currently considered failing.
    pub fn is_failing(&self, domain: &str) -> bool {
        self.domains.get(domain).is_some_and(|h| h.failing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            confirm_checks: 2,
            cooldown: Duration::from_secs(3600),
            breaker_threshold: 0.5,
        }
    }

    fn results(pairs: &[(&str, bool)]) -> Vec<(String, bool)> {
        pairs.iter().map(|(d, ok)| (d.to_string(), *ok)).collect()
    }

    #[test]
    fn one_failed_check_is_not_an_alert() {
        // A single resolver timeout is noise, and alerting on it teaches the
        // operator that the channel is noise too.
        let mut t = Tracker::new();
        let now = Instant::now();

        let first = t.cycle(&results(&[("a.example", false)]), &policy(), now);
        assert!(first.send.is_empty());
        assert_eq!(
            first.suppressed,
            vec![("a.example".into(), Suppression::Unconfirmed)]
        );

        let second = t.cycle(&results(&[("a.example", false)]), &policy(), now);
        assert_eq!(second.send.len(), 1);
        assert_eq!(second.send[0].kind, AlertKind::DomainGated);
    }

    #[test]
    fn a_domain_that_is_still_failing_is_not_news() {
        let mut t = Tracker::new();
        let now = Instant::now();
        let p = policy();

        for _ in 0..2 {
            t.cycle(&results(&[("a.example", false)]), &p, now);
        }
        let again = t.cycle(&results(&[("a.example", false)]), &p, now);
        assert!(again.send.is_empty());
        assert_eq!(
            again.suppressed,
            vec![("a.example".into(), Suppression::NotATransition)]
        );
    }

    #[test]
    fn recovery_is_reported_because_silence_is_not() {
        // Without a recovery notice an operator cannot tell a fixed domain from
        // a forgotten one.
        let mut t = Tracker::new();
        let now = Instant::now();
        let p = policy();

        for _ in 0..2 {
            t.cycle(&results(&[("a.example", false)]), &p, now);
        }
        let back = t.cycle(&results(&[("a.example", true)]), &p, now);
        assert_eq!(back.send.len(), 1);
        assert_eq!(back.send[0].kind, AlertKind::DomainRecovered);
        assert!(!t.is_failing("a.example"));
    }

    #[test]
    fn a_pass_resets_the_confirmation_count() {
        // Otherwise a domain that fails once a week eventually accumulates
        // enough failures to be alerted about, which is not what "consecutive"
        // means.
        let mut t = Tracker::new();
        let now = Instant::now();
        let p = policy();

        t.cycle(&results(&[("a.example", false)]), &p, now);
        t.cycle(&results(&[("a.example", true)]), &p, now);
        let after = t.cycle(&results(&[("a.example", false)]), &p, now);
        assert!(
            after.send.is_empty(),
            "a stale failure count produced an alert"
        );
    }

    #[test]
    fn enough_domains_failing_at_once_implicates_the_resolver() {
        // Forty alerts would bury the one message that says what is wrong.
        let mut t = Tracker::new();
        let now = Instant::now();
        let p = Policy {
            confirm_checks: 1,
            ..policy()
        };

        let d = t.cycle(
            &results(&[
                ("a.example", false),
                ("b.example", false),
                ("c.example", false),
                ("d.example", true),
            ]),
            &p,
            now,
        );

        assert_eq!(d.send.len(), 1);
        assert_eq!(d.send[0].kind, AlertKind::ResolverSuspect);
        assert_eq!(
            d.suppressed
                .iter()
                .filter(|(_, s)| *s == Suppression::CircuitBreaker)
                .count(),
            3
        );

        // The domains are still marked failing: the breaker suppresses the
        // mail, not the fact.
        assert!(t.is_failing("a.example"));
    }

    #[test]
    fn one_domain_alone_cannot_trip_the_breaker() {
        // One out of one is a share of 1.0, so a host with a single domain
        // would otherwise never receive a domain alert at all.
        let mut t = Tracker::new();
        let p = Policy {
            confirm_checks: 1,
            ..policy()
        };
        let d = t.cycle(&results(&[("only.example", false)]), &p, Instant::now());
        assert_eq!(d.send.len(), 1);
        assert_eq!(d.send[0].kind, AlertKind::DomainGated);
    }

    #[test]
    fn a_flapping_domain_is_alerted_about_once_per_window() {
        let mut t = Tracker::new();
        let start = Instant::now();
        let p = Policy {
            confirm_checks: 1,
            cooldown: Duration::from_secs(3600),
            ..policy()
        };

        assert_eq!(
            t.cycle(&results(&[("a.example", false)]), &p, start)
                .send
                .len(),
            1
        );
        // Recovers and fails again, inside the window.
        t.cycle(&results(&[("a.example", true)]), &p, start);
        let again = t.cycle(
            &results(&[("a.example", false)]),
            &p,
            start + Duration::from_secs(60),
        );
        assert!(again.send.is_empty());
        assert_eq!(
            again.suppressed,
            vec![("a.example".into(), Suppression::Cooldown)]
        );

        // And past it, the operator hears about it again. The recovery in
        // between is silent, because the failure it would be closing was
        // itself suppressed — a "recovered" for an incident nobody was told
        // about is noise.
        let quiet = t.cycle(
            &results(&[("a.example", true)]),
            &p,
            start + Duration::from_secs(7200),
        );
        assert!(
            quiet.send.is_empty(),
            "a recovery was reported for a failure that was suppressed"
        );
        let later = t.cycle(
            &results(&[("a.example", false)]),
            &p,
            start + Duration::from_secs(7300),
        );
        assert_eq!(later.send.len(), 1);
    }
}
