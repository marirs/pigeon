//! Domain lifecycle and per-domain policy.

/// Where a domain sits in its DNS validation lifecycle.
///
/// This is **one of two axes**, and on its own it does not decide whether mail
/// is accepted. Administrative suspension is the other, carried as a separate
/// flag — see [`DomainGate`].
///
/// There is deliberately no `Suspended` variant. Collapsing "the operator
/// switched this off" into the validation lifecycle makes the two states
/// mutually exclusive when they are independent: a domain can be gated by DNS
/// *and* disabled at once, and re-enabling one that was suspended would have to
/// re-derive validation state it never actually lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainStatus {
    /// Created, DNS records not yet rendered.
    New,
    /// Records rendered, waiting for the operator to publish them.
    PendingDns,
    /// All required checks pass; not yet switched on.
    Ready,
    /// Every required check passes.
    Active,
    /// A required check regressed. Mail for this domain is refused.
    ///
    /// Reaching this state gates the single domain. It never prevents the
    /// daemon from starting or from serving other domains.
    Error,
}

impl DomainStatus {
    /// Whether DNS validation currently passes.
    ///
    /// Necessary for accepting mail, and **not sufficient** — see
    /// [`DomainGate::accepts_inbound`]. Named for what it measures so that a
    /// caller reaching for it to answer "may this domain receive mail?" has to
    /// notice it is answering a different question.
    #[inline]
    pub fn is_validated(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// The value stored in `domain.status`.
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::PendingDns => "pending_dns",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Error => "error",
        }
    }

    /// Parse the value stored in `domain.status`.
    ///
    /// Named `from_stored` rather than `from_str` because it is not
    /// [`std::str::FromStr`] and must not be mistaken for it: this reads one
    /// specific serialised form, the one migration 1 constrains with a `CHECK`.
    ///
    /// Returns `None` rather than defaulting: a status the binary does not
    /// recognise means the row was written by something else, and guessing
    /// `New` would quietly stop a live domain carrying mail.
    pub fn from_stored(raw: &str) -> Option<Self> {
        Some(match raw {
            "new" => Self::New,
            "pending_dns" => Self::PendingDns,
            "ready" => Self::Ready,
            "active" => Self::Active,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

/// Both axes that decide whether a domain carries mail.
///
/// Kept together so the conjunction is written once. Every previous version of
/// this decision in the codebase asked only about the lifecycle, which is how
/// an administratively disabled domain would have kept accepting mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainGate {
    pub status: DomainStatus,
    /// Administrative. Independent of `status` in both directions.
    pub inbound_enabled: bool,
    /// Administrative, and separately granted: an inbound alias confers no
    /// authority to send (`OUTBOUND.md`).
    pub outbound_enabled: bool,
}

impl DomainGate {
    /// Whether this domain may accept inbound mail right now.
    #[inline]
    pub fn accepts_inbound(&self) -> bool {
        self.status.is_validated() && self.inbound_enabled
    }

    /// Whether this domain may be sent as right now.
    #[inline]
    pub fn allows_outbound(&self) -> bool {
        self.status.is_validated() && self.outbound_enabled
    }
}

/// How outbound mail for a domain reaches its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Resolve the recipient's MX and deliver over port 25 directly.
    Direct,
    /// Hand off to a configured authenticated smarthost.
    Relay,
}

/// How much of the original message is preserved when forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardPolicy {
    /// Relay the body byte for byte so the original DKIM signature survives,
    /// rewriting only the envelope sender via SRS and adding an ARC seal.
    /// This is the default and the only policy that preserves DMARC alignment
    /// on the original `From:` domain.
    ///
    /// One exception, forced by the protocol rather than chosen: a body whose
    /// final line is unterminated, or terminated with a bare LF, gains a CRLF
    /// before the end-of-data marker. The marker only counts at the start of a
    /// line, so the alternative is a `.` written mid-line that no receiver
    /// recognises as end-of-data. It is DKIM-safe — RFC 6376 §3.4.3 has the
    /// signer add the same CRLF during body canonicalisation — but it is not
    /// literally byte-for-byte, and the difference is worth knowing before
    /// someone diffs a spooled message against what arrived.
    #[default]
    Preserve,
    /// Replace the `From:` header with a Pigeon-owned address and set
    /// `Reply-To:` to the original sender. Always delivers, but the message no
    /// longer appears to come from its author. Per-domain escape hatch for
    /// destinations that reject forwarded mail regardless.
    RewriteFrom,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(status: DomainStatus, inbound: bool) -> DomainGate {
        DomainGate {
            status,
            inbound_enabled: inbound,
            outbound_enabled: false,
        }
    }

    #[test]
    fn both_axes_must_agree_before_mail_is_accepted() {
        // The pair is the point. A design that folded suspension into the
        // lifecycle could not represent the second and third rows here.
        assert!(gate(DomainStatus::Active, true).accepts_inbound());
        assert!(!gate(DomainStatus::Active, false).accepts_inbound());
        assert!(!gate(DomainStatus::Error, true).accepts_inbound());
        assert!(!gate(DomainStatus::Error, false).accepts_inbound());
    }

    #[test]
    fn outbound_is_granted_separately_from_inbound() {
        // An inbound alias confers no authority to send: OUTBOUND.md.
        let g = DomainGate {
            status: DomainStatus::Active,
            inbound_enabled: true,
            outbound_enabled: false,
        };
        assert!(g.accepts_inbound());
        assert!(!g.allows_outbound());
    }

    #[test]
    fn only_active_counts_as_validated() {
        for s in [
            DomainStatus::New,
            DomainStatus::PendingDns,
            DomainStatus::Ready,
            DomainStatus::Error,
        ] {
            assert!(!s.is_validated(), "{s:?} should not be validated");
        }
        assert!(DomainStatus::Active.is_validated());
    }

    #[test]
    fn status_round_trips_through_its_stored_form() {
        for s in [
            DomainStatus::New,
            DomainStatus::PendingDns,
            DomainStatus::Ready,
            DomainStatus::Active,
            DomainStatus::Error,
        ] {
            assert_eq!(DomainStatus::from_stored(s.as_str()), Some(s));
        }
    }

    #[test]
    fn an_unrecognised_status_is_not_guessed() {
        // A row written by a newer binary, or edited by hand. Defaulting to
        // `New` would stop a live domain carrying mail; refusing to parse makes
        // the caller decide what to do about it.
        assert_eq!(DomainStatus::from_stored("suspended"), None);
        assert_eq!(DomainStatus::from_stored(""), None);
        assert_eq!(DomainStatus::from_stored("ACTIVE"), None);
    }
}
