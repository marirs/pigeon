//! Inbound authentication: SPF, DKIM, ARC, then DMARC (`M2-DESIGN.md` §3).
//!
//! # The boundary this module exists to hold
//!
//! Everything here runs against **the bytes that arrived** and nothing else.
//! Verification before mutation is not a preference: any header Pigeon prepends
//! is one the original signature did not cover, and normalising the payload
//! first would produce a verdict describing a message that never existed.
//!
//! That ordering is enforced by the type system rather than by this comment.
//! [`Received`] is what verification takes; [`Received::normalise`] consumes it
//! and yields a [`Relayable`], and only a `Relayable` can be signed, sealed or
//! spooled. There is no path from a `Relayable` back to something verifiable,
//! so "verify after mutating" is not an ordering mistake anyone can make here —
//! it does not compile.

use std::net::IpAddr;

use mail_auth::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    DmarcResult, MessageAuthenticator, SpfOutput, SpfResult, dmarc::Policy,
    dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
};

use crate::normalize;

/// How many DKIM signatures are verified (`M2-DESIGN.md` §4.4).
///
/// Each one is a DNS lookup and a body hash, and the number of them is chosen
/// by whoever sent the message.
pub const MAX_DKIM_SIGNATURES: usize = 10;

// --------------------------------------------------------- the two payloads

/// A payload exactly as it arrived: dot-unstuffed, terminator removed, nothing
/// else touched. The only thing that can be authenticated.
#[derive(Debug, Clone, Copy)]
pub struct Received<'a>(&'a [u8]);

impl<'a> Received<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self(payload)
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Transport conversion (R-1), and the one-way door out of verification.
    ///
    /// Consumes the received form deliberately. Holding both and picking the
    /// wrong one later is exactly the mistake this boundary exists to prevent.
    pub fn normalise(self) -> Relayable {
        Relayable {
            was_converted: normalize::needs_conversion(self.0),
            bytes: normalize::to_crlf(self.0).into_owned(),
        }
    }
}

/// A payload that may be mutated, signed, sealed and sent.
#[derive(Debug, Clone)]
pub struct Relayable {
    bytes: Vec<u8>,
    was_converted: bool,
}

impl Relayable {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether normalisation changed anything.
    ///
    /// Worth carrying: a message whose original signature covered the
    /// nonconforming bytes will fail downstream, and this is the only place
    /// that knows why.
    pub fn was_converted(&self) -> bool {
        self.was_converted
    }

    /// Remove every field with this name from the header block.
    ///
    /// Returns how many were removed. Folded continuation lines go with the
    /// field they belong to — a header is not a line, and removing only the
    /// first line of a folded `From:` leaves its continuation behind as a
    /// syntactically valid field of its own.
    ///
    /// Scoped to the header block: the terminating blank line stops the scan,
    /// so a body line that happens to read like a header is left alone.
    pub fn remove_headers(&mut self, name: &str) -> usize {
        let mut out = Vec::with_capacity(self.bytes.len());
        let mut removed = 0;
        let mut rest: &[u8] = &self.bytes;
        let mut dropping = false;

        while !rest.is_empty() {
            let (line, tail) = split_line(rest);
            rest = tail;

            // The blank line ends the header block; everything after it is
            // body and is copied verbatim.
            if line == b"\r\n" || line == b"\n" || line.is_empty() {
                out.extend_from_slice(line);
                out.extend_from_slice(rest);
                break;
            }

            let continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
            if continuation {
                if dropping {
                    continue;
                }
            } else {
                dropping = field_name_is(line, name);
                if dropping {
                    removed += 1;
                }
            }

            if !dropping {
                out.extend_from_slice(line);
            }
        }

        self.bytes = out;
        removed
    }

    /// Prepend header lines, topmost first.
    ///
    /// Existing headers are never touched — not reordered, refolded, re-encoded
    /// or deduplicated, each of which breaks `simple` header canonicalisation
    /// and plausibly breaks `relaxed`.
    pub fn prepend_headers(&mut self, headers: &[String]) {
        let mut out = Vec::with_capacity(
            self.bytes.len() + headers.iter().map(|h| h.len() + 2).sum::<usize>(),
        );
        for header in headers {
            out.extend_from_slice(header.as_bytes());
            if !header.ends_with("\r\n") {
                out.extend_from_slice(b"\r\n");
            }
        }
        out.extend_from_slice(&self.bytes);
        self.bytes = out;
    }
}

/// Split off one line, keeping its terminator.
fn split_line(input: &[u8]) -> (&[u8], &[u8]) {
    match input.iter().position(|&b| b == b'\n') {
        Some(i) => input.split_at(i + 1),
        None => (input, &[]),
    }
}

/// Whether a header line starts the named field.
///
/// Compared case-insensitively, and only up to the colon: RFC 5322 allows
/// whitespace before it, and a sender that writes `From :` is naming the same
/// field as one that writes `From:`.
fn field_name_is(line: &[u8], name: &str) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let field = &line[..colon];
    let trimmed: &[u8] = {
        let end = field
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(0, |i| i + 1);
        &field[..end]
    };
    trimmed.eq_ignore_ascii_case(name.as_bytes())
}

// ------------------------------------------------------------------ envelope

/// What the SMTP transaction said, which SPF is evaluated against.
#[derive(Debug, Clone)]
pub struct Envelope<'a> {
    pub client_ip: IpAddr,
    pub helo: &'a str,
    /// RFC5321.MailFrom. Empty for a bounce's null sender.
    pub mail_from: &'a str,
    /// This host's own name, for the `Authentication-Results` authserv-id.
    pub host_domain: &'a str,
}

// ------------------------------------------------------------------ verdicts

/// One verification outcome, in the vocabulary RFC 8601 uses.
///
/// `TempError` is kept distinct from `Fail` and from `PermError` because the
/// three mean different things to whoever reads the log: a DNS outage, a
/// message that does not authenticate, and a record that cannot be parsed.
/// Collapsing them is how a resolver problem gets investigated as a sender
/// problem — the mistake finding 13 in `M0-FINDINGS.md` already made once, in
/// the MX path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl Outcome {
    /// Whether retrying later could plausibly give a different answer.
    ///
    /// The permanent/transient split is the seam the Milestone 3 queue acts on,
    /// so it has exactly one definition.
    pub fn is_transient(self) -> bool {
        matches!(self, Outcome::TempError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimVerdict {
    /// The `d=` domain, lowercased.
    pub domain: String,
    pub outcome: Outcome,
    /// Whether `d=` aligns with the `RFC5322.From` domain under relaxed
    /// alignment — the only signatures that can produce a DMARC pass.
    pub aligned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcVerdict {
    pub domain: String,
    pub dkim: Outcome,
    pub spf: Outcome,
    /// The published policy: **recorded, not enforced** (R-5).
    pub policy: DmarcPolicy,
}

impl DmarcVerdict {
    /// An aligned pass on either mechanism, which is what DMARC asks for.
    pub fn passes(&self) -> bool {
        self.dkim == Outcome::Pass || self.spf == Outcome::Pass
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
    /// No DMARC record, or one that could not be read.
    Unspecified,
}

/// Everything learned about the message as it arrived.
///
/// Owned rather than borrowed from the parse. `mail-auth`'s outputs borrow from
/// the payload, and a verdict that cannot outlive that buffer is one the rest
/// of the pipeline cannot carry: the headers are built after normalisation,
/// from a different buffer entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdicts {
    pub spf: Outcome,
    pub dkim: Vec<DkimVerdict>,
    pub dmarc: DmarcVerdict,
    /// `None` when the message carries no ARC chain, which is the ordinary
    /// case and is a different fact from a chain that failed.
    pub arc: Option<Outcome>,
    /// `Authentication-Results`, rendered while the parse was still alive.
    pub authentication_results: String,
    /// Signatures present, and signatures verified. Unequal means the cap bit.
    pub dkim_signatures: (usize, usize),
}

impl From<&DkimResult> for Outcome {
    fn from(r: &DkimResult) -> Self {
        match r {
            DkimResult::Pass => Outcome::Pass,
            DkimResult::Neutral(_) => Outcome::Neutral,
            DkimResult::Fail(_) => Outcome::Fail,
            DkimResult::PermError(_) => Outcome::PermError,
            DkimResult::TempError(_) => Outcome::TempError,
            DkimResult::None => Outcome::None,
        }
    }
}

impl From<&DmarcResult> for Outcome {
    fn from(r: &DmarcResult) -> Self {
        match r {
            DmarcResult::Pass => Outcome::Pass,
            DmarcResult::Fail(_) => Outcome::Fail,
            DmarcResult::PermError(_) => Outcome::PermError,
            DmarcResult::TempError(_) => Outcome::TempError,
            DmarcResult::None => Outcome::None,
        }
    }
}

impl From<&SpfResult> for Outcome {
    fn from(r: &SpfResult) -> Self {
        match r {
            SpfResult::Pass => Outcome::Pass,
            SpfResult::Fail => Outcome::Fail,
            SpfResult::SoftFail | SpfResult::Neutral => Outcome::Neutral,
            SpfResult::TempError => Outcome::TempError,
            SpfResult::PermError => Outcome::PermError,
            SpfResult::None => Outcome::None,
        }
    }
}

impl From<Policy> for DmarcPolicy {
    fn from(p: Policy) -> Self {
        match p {
            Policy::None => DmarcPolicy::None,
            Policy::Quarantine => DmarcPolicy::Quarantine,
            Policy::Reject => DmarcPolicy::Reject,
            Policy::Unspecified => DmarcPolicy::Unspecified,
        }
    }
}

// ------------------------------------------------------------------ verifier

/// Wraps `mail-auth` and the DNS resolver it verifies through.
#[derive(Clone)]
pub struct Verifier {
    authenticator: MessageAuthenticator,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verifier")
    }
}

impl Verifier {
    /// Build from the system resolver configuration.
    ///
    /// One DNS stack for the daemon: `mail-auth` and `pigeon-dns` resolve
    /// through the same hickory version (R-6), so "what did Pigeon ask DNS?"
    /// has one answer rather than two.
    pub fn from_system() -> Result<Self, String> {
        let resolver = mail_auth::hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| e.to_string())?
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            authenticator: MessageAuthenticator(resolver),
        })
    }

    /// Authenticate the received payload.
    ///
    /// The order is the one §3 requires. SPF and DKIM first, because DMARC is
    /// evaluated *from* their results; DMARC against the identities as
    /// received, never against an envelope Pigeon has rewritten — that would
    /// return a meaningless pass on a domain Pigeon controls.
    /// Authenticate a message that the caller has already parsed.
    ///
    /// The borrowed half of [`Verifier::verify`], separated so one scope can
    /// hold the parse, the ARC output and the rendered results together —
    /// sealing needs all three alive at once, and an owner-plus-borrow struct
    /// to carry them would be self-referential. The pipeline holds them as
    /// locals instead; see [`crate::pipeline`].
    pub(crate) async fn authenticate<'x>(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        envelope: &'x Envelope<'x>,
    ) -> Authenticated<'x> {
        let spf = self
            .authenticator
            .verify_spf(SpfParameters::verify_mail_from(
                envelope.client_ip,
                envelope.helo,
                envelope.host_domain,
                envelope.mail_from,
            ))
            .await;

        let dkim = self.authenticator.verify_dkim(message).await;

        // Absent chain and failed chain are different facts, so an empty chain
        // is never verified into a `Fail`.
        let arc = if message.as_headers.is_empty() {
            None
        } else {
            Some(self.authenticator.verify_arc(message).await)
        };

        let mail_from_domain = envelope
            .mail_from
            .rsplit_once('@')
            .map_or(envelope.helo, |(_, d)| d);
        let dmarc = self
            .authenticator
            .verify_dmarc(DmarcParameters::new(message, &dkim, mail_from_domain, &spf))
            .await;

        // Rendered here, while the borrows are alive. R-5: written whenever
        // authentication was evaluated, not only when something failed.
        let mut results = AuthenticationResults::new(envelope.host_domain)
            .with_spf_mailfrom_result(&spf, envelope.client_ip, envelope.mail_from, envelope.helo)
            .with_dkim_results(&dkim, dmarc.domain())
            .with_dmarc_result(&dmarc);
        if let Some(arc) = &arc {
            results = results.with_arc_result(arc, envelope.client_ip);
        }

        Authenticated {
            spf,
            dkim,
            arc,
            dmarc,
            results,
        }
    }

    pub async fn verify<'x>(&self, received: Received<'x>, envelope: &'x Envelope<'x>) -> Verdicts {
        let spf = self
            .authenticator
            .verify_spf(SpfParameters::verify_mail_from(
                envelope.client_ip,
                envelope.helo,
                envelope.host_domain,
                envelope.mail_from,
            ))
            .await;

        let Some(mut message) = AuthenticatedMessage::parse(received.as_bytes()) else {
            // Unparseable as a message: "nothing to say" rather than "failed",
            // which are different facts and are recorded as different ones.
            return Verdicts {
                spf: (&spf.result()).into(),
                dkim: Vec::new(),
                dmarc: DmarcVerdict {
                    domain: String::new(),
                    dkim: Outcome::None,
                    spf: Outcome::None,
                    policy: DmarcPolicy::Unspecified,
                },
                arc: None,
                authentication_results: AuthenticationResults::new(envelope.host_domain)
                    .with_spf_mailfrom_result(
                        &spf,
                        envelope.client_ip,
                        envelope.mail_from,
                        envelope.helo,
                    )
                    .to_string(),
                dkim_signatures: (0, 0),
            };
        };

        let present = message.dkim_headers.len();
        let from = from_domains(&message);
        prioritise_signatures(&mut message, &from, MAX_DKIM_SIGNATURES);
        let verified = message.dkim_headers.len();

        let authenticated = self.authenticate(&message, envelope).await;
        authenticated.into_verdicts(&from, (present, verified))
    }
}

/// The borrowed outputs of one authentication pass.
///
/// Lives only as long as the parse it came from. Everything the rest of the
/// pipeline needs afterwards is copied out by [`Authenticated::into_verdicts`];
/// what stays borrowed is what sealing consumes — the ARC output and the
/// rendered results — and the pipeline keeps those as locals beside the buffer
/// they point into.
pub(crate) struct Authenticated<'x> {
    pub spf: SpfOutput,
    pub dkim: Vec<DkimOutput<'x>>,
    pub arc: Option<ArcOutput<'x>>,
    pub dmarc: DmarcOutput,
    pub results: AuthenticationResults<'x>,
}

impl Authenticated<'_> {
    pub(crate) fn into_verdicts(
        self,
        from_domains: &[String],
        signature_counts: (usize, usize),
    ) -> Verdicts {
        self.verdicts(from_domains, signature_counts)
    }

    /// The same, without consuming — the pipeline keeps the borrowed outputs
    /// alive for sealing after it has taken the owned summary.
    pub(crate) fn verdicts(
        &self,
        from_domains: &[String],
        signature_counts: (usize, usize),
    ) -> Verdicts {
        Verdicts {
            spf: (&self.spf.result()).into(),
            dkim: self
                .dkim
                .iter()
                .map(|d| {
                    let domain = d
                        .signature()
                        .map(|s| s.d.to_ascii_lowercase())
                        .unwrap_or_default();
                    DkimVerdict {
                        aligned: is_aligned(&domain, from_domains),
                        domain,
                        outcome: d.result().into(),
                    }
                })
                .collect(),
            dmarc: DmarcVerdict {
                domain: self.dmarc.domain().to_string(),
                dkim: self.dmarc.dkim_result().into(),
                spf: self.dmarc.spf_result().into(),
                policy: self.dmarc.policy().into(),
            },
            arc: self.arc.as_ref().map(|a| a.result().into()),
            authentication_results: self.results.to_string(),
            dkim_signatures: signature_counts,
        }
    }
}

/// The `RFC5322.From` domains, lowercased.
pub(crate) fn from_domains(message: &AuthenticatedMessage<'_>) -> Vec<String> {
    message
        .from
        .iter()
        .filter_map(|address| {
            address
                .rsplit_once('@')
                .map(|(_, d)| d.to_ascii_lowercase())
        })
        .collect()
}

/// Relaxed DMARC alignment: the signing domain, or an organisational relative
/// of it, matching a `From:` domain.
///
/// Strict alignment is a subset, so ordering by the looser rule cannot drop a
/// signature the stricter one would have kept.
fn is_aligned(signing_domain: &str, from_domains: &[String]) -> bool {
    !signing_domain.is_empty()
        && from_domains.iter().any(|from| {
            from == signing_domain
                || from.ends_with(&format!(".{signing_domain}"))
                || signing_domain.ends_with(&format!(".{from}"))
        })
}

/// Order the signatures so the ones that can produce a DMARC pass are verified
/// first, then bound the work (`M2-DESIGN.md` §4.4).
///
/// A cap by position alone is a hole rather than a limit: an attacker prepends
/// ten bogus signatures and the aligned one falls off the end, turning a
/// deliverable message into a DMARC failure. An unaligned signature that goes
/// unverified costs nothing — it cannot produce an aligned pass either way.
///
/// Sorting is stable, so signatures that tie keep the order they arrived in,
/// and a message under the cap is not reordered at all.
pub(crate) fn prioritise_signatures(
    message: &mut AuthenticatedMessage<'_>,
    from_domains: &[String],
    cap: usize,
) {
    if message.dkim_headers.len() <= cap {
        return;
    }

    message.dkim_headers.sort_by_key(|header| {
        u8::from(!is_aligned(
            &header.header.d.to_ascii_lowercase(),
            from_domains,
        ))
    });
    message.dkim_headers.truncate(cap);
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFORMING: &[u8] = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n";

    #[test]
    fn normalising_is_a_one_way_door() {
        // The boundary in the module docs, asserted on the data rather than
        // only on the types: what comes out of `normalise` is conforming, and
        // there is no method on it that authenticates anything.
        let relayable = Received::new(b"a\nb").normalise();
        assert!(relayable.was_converted());
        assert_eq!(relayable.as_bytes(), b"a\r\nb");
        assert!(!normalize::needs_conversion(relayable.as_bytes()));
    }

    #[test]
    fn a_conforming_payload_is_not_marked_converted() {
        let relayable = Received::new(CONFORMING).normalise();
        assert!(!relayable.was_converted());
        assert_eq!(relayable.as_bytes(), CONFORMING);
    }

    // ------------------------------------------------------ header removal

    fn removed(message: &[u8], name: &str) -> (String, usize) {
        let mut r = Received::new(message).normalise();
        let n = r.remove_headers(name);
        (String::from_utf8(r.as_bytes().to_vec()).unwrap(), n)
    }

    #[test]
    fn every_matching_field_is_removed_with_its_continuations() {
        let (out, n) = removed(
            b"From: <a@x.example>\r\nTo: <b@y.example>\r\nFrom: \"Folded\"\r\n <c@z.example>\r\n\r\nbody\r\n",
            "From",
        );
        assert_eq!(n, 2);
        assert!(!out.contains("a@x.example"), "{out}");
        assert!(!out.contains("c@z.example"), "{out}");
        assert!(!out.contains("Folded"), "{out}");
        assert!(out.contains("To: <b@y.example>"), "{out}");
        assert!(out.ends_with("\r\nbody\r\n"), "{out}");
    }

    #[test]
    fn removal_stops_at_the_body() {
        // A body line that reads like a header is body. Scanning past the
        // blank line would let a quoted email in the text of a message delete
        // part of it — silent corruption, and only for messages that quote
        // mail, which is most of them.
        let (out, n) = removed(
            b"From: <a@x.example>\r\nSubject: hi\r\n\r\nQuoting you:\r\nFrom: <someone@else.example>\r\nregards\r\n",
            "From",
        );
        assert_eq!(n, 1, "a body line was counted as a header");
        assert!(
            out.contains("From: <someone@else.example>"),
            "a body line was deleted:\n{out}"
        );
        assert!(out.contains("regards"), "{out}");
    }

    #[test]
    fn a_similarly_named_field_is_left_alone() {
        // `From-Original:` and `X-From:` are different fields. Matching by
        // prefix would delete headers a forwarder is often the one to add.
        let (out, n) = removed(
            b"From-Original: <a@x.example>\r\nX-From: <b@y.example>\r\nFrom: <c@z.example>\r\n\r\nbody\r\n",
            "From",
        );
        assert_eq!(n, 1);
        assert!(out.contains("From-Original: <a@x.example>"), "{out}");
        assert!(out.contains("X-From: <b@y.example>"), "{out}");
        assert!(!out.contains("c@z.example"), "{out}");
    }

    #[test]
    fn whitespace_before_the_colon_still_names_the_field() {
        // RFC 5322 allows it, and a sender that writes `From :` is naming the
        // same field. Missing it would leave the author's header in place
        // beside Pigeon's.
        let (out, n) = removed(
            b"From : <a@x.example>\r\nSubject: hi\r\n\r\nbody\r\n",
            "From",
        );
        assert_eq!(n, 1, "`From :` was not recognised:\n{out}");
        assert!(!out.contains("a@x.example"), "{out}");
    }

    #[test]
    fn removing_a_field_that_is_not_there_changes_nothing() {
        let original = b"To: <b@y.example>\r\nSubject: hi\r\n\r\nbody\r\n";
        let (out, n) = removed(original, "From");
        assert_eq!(n, 0);
        assert_eq!(out.as_bytes(), original);
    }

    #[test]
    fn prepended_headers_come_out_topmost_and_in_order() {
        let mut r = Received::new(CONFORMING).normalise();
        r.prepend_headers(&[
            "ARC-Seal: i=1".to_string(),
            "Received: by pigeon\r\n".to_string(),
        ]);
        let out = String::from_utf8(r.as_bytes().to_vec()).unwrap();
        assert!(
            out.starts_with("ARC-Seal: i=1\r\nReceived: by pigeon\r\nFrom: a@"),
            "{out}"
        );
        // And the original message is untouched below them.
        assert!(out.ends_with(std::str::from_utf8(CONFORMING).unwrap()));
    }

    #[test]
    fn a_header_that_already_ends_in_crlf_does_not_gain_a_second_one() {
        // A blank line inserted here would end the header block early and turn
        // every header below it into body text.
        let mut r = Received::new(CONFORMING).normalise();
        r.prepend_headers(&["X-A: 1\r\n".to_string()]);
        assert!(!r.as_bytes().starts_with(b"X-A: 1\r\n\r\n"));
    }

    // ------------------------------------------------- signature prioritising

    fn message_with(from: &str, signing_domains: &[&str]) -> Vec<u8> {
        let mut raw = String::new();
        for d in signing_domains {
            // Enough of a signature for the parser to accept and record `d=`.
            raw.push_str(&format!(
                "DKIM-Signature: v=1; a=rsa-sha256; d={d}; s=s; c=relaxed/relaxed; \
                 h=from; bh=AAAA; b=AAAA\r\n"
            ));
        }
        raw.push_str(&format!("From: <a@{from}>\r\nSubject: hi\r\n\r\nbody\r\n"));
        raw.into_bytes()
    }

    #[test]
    fn the_aligned_signature_survives_the_cap() {
        // The attack the cap would otherwise enable: ten unaligned signatures
        // prepended so the one that could produce a DMARC pass falls off.
        let mut domains: Vec<&str> = vec!["spam.example"; 12];
        domains.push("example.com");
        let raw = message_with("example.com", &domains);

        let mut message = AuthenticatedMessage::parse(&raw).unwrap();
        assert_eq!(message.dkim_headers.len(), 13);

        let from = from_domains(&message);
        prioritise_signatures(&mut message, &from, MAX_DKIM_SIGNATURES);

        assert_eq!(message.dkim_headers.len(), MAX_DKIM_SIGNATURES);
        assert_eq!(
            message.dkim_headers[0].header.d, "example.com",
            "the aligned signature was not verified first"
        );
    }

    #[test]
    fn a_subdomain_signature_counts_as_aligned() {
        // Relaxed alignment. Ordering by the looser rule cannot drop a
        // signature the stricter one would have kept.
        let mut domains: Vec<&str> = vec!["spam.example"; 12];
        domains.push("mail.example.com");
        let raw = message_with("example.com", &domains);

        let mut message = AuthenticatedMessage::parse(&raw).unwrap();
        let from = from_domains(&message);
        prioritise_signatures(&mut message, &from, MAX_DKIM_SIGNATURES);
        assert_eq!(message.dkim_headers[0].header.d, "mail.example.com");
    }

    #[test]
    fn a_message_under_the_cap_keeps_its_original_order() {
        // Reordering when there is no need to would change which signature a
        // reader sees first for no benefit.
        let raw = message_with("example.com", &["b.example", "example.com", "c.example"]);
        let mut message = AuthenticatedMessage::parse(&raw).unwrap();
        let from = from_domains(&message);
        prioritise_signatures(&mut message, &from, MAX_DKIM_SIGNATURES);

        let order: Vec<&str> = message
            .dkim_headers
            .iter()
            .map(|h| h.header.d.as_str())
            .collect();
        assert_eq!(order, ["b.example", "example.com", "c.example"]);
    }

    #[test]
    fn signatures_are_counted_before_and_after_the_cap() {
        let domains: Vec<&str> = vec!["spam.example"; 15];
        let raw = message_with("example.com", &domains);
        let mut message = AuthenticatedMessage::parse(&raw).unwrap();
        let before = message.dkim_headers.len();
        let from = from_domains(&message);
        prioritise_signatures(&mut message, &from, MAX_DKIM_SIGNATURES);
        assert_eq!((before, message.dkim_headers.len()), (15, 10));
    }
}
