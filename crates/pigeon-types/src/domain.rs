//! Domain lifecycle and per-domain policy.

/// Where a domain sits in its onboarding lifecycle.
///
/// Only [`DomainStatus::Active`] may receive production mail. A domain reaches
/// it solely by passing every required DNS check; there is no manual override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainStatus {
    /// Created, DNS records not yet rendered.
    New,
    /// Records rendered, waiting for the operator to publish them.
    PendingDns,
    /// All required checks pass; not yet switched on.
    Ready,
    /// Serving mail.
    Active,
    /// Switched off by the operator. Not an error.
    Suspended,
    /// A required check regressed. Mail for this domain is refused.
    ///
    /// Reaching this state gates the single domain. It never prevents the
    /// daemon from starting or from serving other domains.
    Error,
}

impl DomainStatus {
    /// Whether this domain may accept inbound mail right now.
    #[inline]
    pub fn accepts_mail(&self) -> bool {
        matches!(self, Self::Active)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardPolicy {
    /// Relay the body byte for byte so the original DKIM signature survives,
    /// rewriting only the envelope sender via SRS and adding an ARC seal.
    /// This is the default and the only policy that preserves DMARC alignment
    /// on the original `From:` domain.
    Preserve,
    /// Replace the `From:` header with a Pigeon-owned address and set
    /// `Reply-To:` to the original sender. Always delivers, but the message no
    /// longer appears to come from its author. Per-domain escape hatch for
    /// destinations that reject forwarded mail regardless.
    RewriteFrom,
}

impl Default for ForwardPolicy {
    fn default() -> Self {
        Self::Preserve
    }
}
