//! The forwarding pipeline: verify, normalise, rewrite, sign, seal
//! (`M2-DESIGN.md` §3).
//!
//! # Why this is one function
//!
//! Each step consumes a state the next one destroys, and two of them need
//! `mail-auth` values that borrow the buffer they were computed from:
//!
//! - The ARC set must cover the message **as sent**, so sealing happens after
//!   the rewrite and after Pigeon's own DKIM signature.
//! - `ArcSealer::seal` needs the *inbound* `ArcOutput`, which borrows the
//!   *received* buffer, at the moment it signs the *outbound* one.
//!
//! So both buffers have to be alive simultaneously. A struct owning one and
//! borrowing the other would be self-referential; instead [`Pipeline::process`]
//! holds them as locals, and every `mail-auth` borrow lives and dies inside it.
//! What comes out owns itself.
//!
//! ```text
//! received: &[u8] ──parse──> AuthenticatedMessage ──> Authenticated { arc, results, .. }
//!        │                                                    │
//!        └─normalise─> Relayable ─rewrite─> ─sign─> ─────seal──┘   <- both alive here
//!                                                        │
//!                                                        v
//!                                             Outbound { owns its bytes }
//! ```

use std::sync::Arc;

use sha2::{Digest as _, Sha256 as Sha256Digest};

use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};

use mail_auth::{
    AuthenticatedMessage,
    arc::ArcSealer,
    common::{
        crypto::{Algorithm, RsaKey, Sha256, SigningKey as MailAuthSigningKey},
        headers::{HeaderWriter, Writable},
    },
    dkim::DkimSigner,
};

use crate::verify::{
    Envelope, MAX_DKIM_SIGNATURES, Received, Relayable, Verdicts, Verifier, from_domains,
    prioritise_signatures,
};

/// Headers Pigeon signs and seals over.
///
/// Oversigning is deliberate for `From`: listing a header twice commits to the
/// number of times it appears, so a downstream that adds a second `From` breaks
/// the signature instead of silently changing who the message is from.
const SIGNED_HEADERS: [&str; 8] = [
    "From",
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
];

/// Pigeon's own signing identity, for ARC seals and `rewrite_from` signatures.
///
/// Holds the key as PKCS#8 DER rather than as a parsed `RsaKey`, because
/// `mail-auth`'s signer and sealer each take one by value and `RsaKey` is
/// neither `Clone` nor implemented for references. Parsing per operation costs
/// a DER decode against an RSA signature, which is not a trade worth thinking
/// about — and it keeps the key material in one zeroizing buffer rather than
/// copied into two long-lived parsed forms.
///
/// The `rsa` crate is deliberately not involved: `deny.toml`'s advisory
/// exception rests on `rsa` being used only to *generate* keys, and signing
/// stays entirely on `ring` (`M2-DESIGN.md` §6.1).
pub struct SigningKey {
    key: SharedKey,
    domain: String,
    selector: String,
    /// Which key material this is, without being the key material.
    ///
    /// The published runtime's fingerprint has to change when a key file's
    /// *contents* change, not merely when its path or selector does: rotating a
    /// key in place under an unchanged selector is otherwise invisible, and a
    /// message recorded as signed by "sel" would not say which "sel". A hash
    /// rather than the DER because this value is compared and stored, and the
    /// private components must not travel with it.
    identity: [u8; 32],
}

/// A parsed key that can be handed to `mail-auth` more than once.
///
/// `DkimSigner::from_key` and `ArcSealer::from_key` each take a key **by
/// value**, and `RsaKey` is neither `Clone` nor implemented for references. The
/// obvious workaround — keep the DER and parse per use — signs and seals with
/// two freshly parsed keys per message, which puts two more copies of the
/// private components in memory that nothing zeroizes, and hands an attacker a
/// per-message RSA key parse for free.
///
/// So the key is parsed once, at startup, and shared. The wrapper is what makes
/// that possible: it implements `mail-auth`'s public `SigningKey` trait by
/// forwarding to the `Arc`, so a clone costs a refcount.
#[derive(Clone)]
struct SharedKey(Arc<RsaKey<Sha256>>);

impl MailAuthSigningKey for SharedKey {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> mail_auth::Result<Vec<u8>> {
        self.0.sign(input)
    }

    fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }
}

impl std::fmt::Debug for SigningKey {
    /// Never the key. The same rule `dkim::KeyPair` follows: a `Debug` that
    /// prints key material puts it in every log line that formats the value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("domain", &self.domain)
            .field("selector", &self.selector)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SigningKey {
    /// Load from the PKCS#8 PEM that `dkim::KeyPair::generate` writes.
    ///
    /// Parsed here and only here, so a key that cannot sign is a startup
    /// failure rather than a per-message one — and so the DER, which is the
    /// form the private components arrive in, is dropped before this returns
    /// rather than kept for re-parsing.
    pub fn from_pkcs8_pem(
        pem: &str,
        domain: impl Into<String>,
        selector: impl Into<String>,
    ) -> Result<Self, PipelineError> {
        let der = PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|e| PipelineError::Key(e.to_string()))?;
        let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(der))
            .map_err(|e| PipelineError::Key(e.to_string()))?;
        let domain = domain.into();
        let selector = selector.into();
        // Over the PEM, which is the form on disk, and bound to the identity it
        // was loaded for so the same file installed under two selectors is two
        // different signing identities.
        let mut h = Sha256Digest::new();
        h.update(domain.as_bytes());
        h.update(b"\0");
        h.update(selector.as_bytes());
        h.update(b"\0");
        h.update(pem.as_bytes());

        Ok(Self {
            key: SharedKey(Arc::new(key)),
            domain,
            selector,
            identity: h.finalize().into(),
        })
    }

    /// A hash identifying the loaded key material. Never the key itself.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("the signing key could not be read: {0}")]
    Key(String),

    #[error("the rewritten From: address is not usable: {0}")]
    InvalidRewrite(String),

    /// R-8, and the one failure that must not be forwarded.
    ///
    /// A rewritten `From:` sent unsigned fails DMARC on a domain Pigeon
    /// controls, which is strictly worse than not rewriting: it turns a message
    /// that would have been delivered on the original signature into one
    /// refused on Pigeon's own identity.
    #[error("a rewritten From: could not be signed: {0}")]
    UnsignedRewrite(String),
}

/// What to do with the `From:` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rewrite {
    /// Relay the author's `From:` unchanged. DMARC then depends on the original
    /// signature surviving, which is what §2 is about.
    Preserve,
    /// Replace it with an address in a Pigeon-controlled domain, which **must**
    /// then be signed by that domain.
    From(FromAddress),
}

/// A validated address for a rewritten `From:`.
///
/// A plain `String` was wrong twice over. It let a caller pass a whole header
/// line, so a value containing CRLF would inject headers of its own — the
/// message is assembled by concatenation, and a newline in a field value is
/// indistinguishable from the end of that field. And it invited the caller to
/// build the header text, which is this module's job.
///
/// Constructed only through [`FromAddress::new`], which parses the address with
/// the same code the envelope uses, so CR, LF, angle brackets and everything
/// else structural are refused rather than escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromAddress {
    address: String,
    display: Option<String>,
}

impl FromAddress {
    pub fn new(address: &str) -> Result<Self, PipelineError> {
        pigeon_types::Address::parse(address)
            .map_err(|e| PipelineError::InvalidRewrite(e.to_string()))?;
        Ok(Self {
            address: address.to_string(),
            display: None,
        })
    }

    /// Add a display name, which is also validated.
    ///
    /// Anything structural in a display name — a quote, a CR, a LF — would
    /// change what the header means, so it is refused rather than quoted.
    /// Quoting correctly is possible; refusing is checkable.
    pub fn with_display_name(mut self, display: &str) -> Result<Self, PipelineError> {
        if display
            .bytes()
            .any(|b| b == b'"' || b == b'\\' || b == b'\r' || b == b'\n' || b == b'<' || b == b'>')
        {
            return Err(PipelineError::InvalidRewrite(
                "the display name contains a character that would change the header".into(),
            ));
        }
        self.display = Some(display.to_string());
        Ok(self)
    }

    pub fn domain(&self) -> &str {
        self.address.rsplit_once('@').map_or("", |(_, d)| d)
    }

    /// The header line, built here rather than by the caller.
    fn header(&self) -> String {
        match &self.display {
            Some(name) => format!("From: \"{name}\" <{}>", self.address),
            None => format!("From: <{}>", self.address),
        }
    }
}

/// The finished message, owning its bytes.
#[derive(Debug)]
pub struct Outbound {
    pub payload: Relayable,
    pub verdicts: Verdicts,
    /// Whether an ARC set was added.
    ///
    /// `false` is not necessarily an error: a chain that arrived `cv=fail` is
    /// terminally broken and must not be extended (RFC 8617), which is a normal
    /// outcome rather than a local failure.
    pub sealed: bool,
    /// Why no ARC set was added, when none was.
    pub seal_skipped: Option<SealSkipped>,
    /// Whether Pigeon added a DKIM signature of its own.
    pub signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealSkipped {
    /// The inbound chain already declared `cv=fail`. Correct, and not a fault.
    ChainAlreadyFailed,
    /// No key configured for sealing.
    NoKey,
    /// Sealing was attempted and failed. Degrades to the pre-ARC status quo,
    /// which is survivable — but it is a local fault and is logged as one.
    Failed,
}

/// Verifier and host identity.
///
/// Deliberately holds **no** signing key. Which key signs and seals is a
/// property of the domain the message was accepted for, and that comes from the
/// same transaction-pinned snapshot as the routing decision — so it is passed
/// per message rather than baked in here. A pipeline that owned one key would
/// quietly sign every domain's mail with it.
#[derive(Debug)]
pub struct Pipeline {
    verifier: Verifier,
    host_domain: String,
}

impl Pipeline {
    pub fn new(verifier: Verifier, host_domain: impl Into<String>) -> Self {
        Self {
            verifier,
            host_domain: host_domain.into(),
        }
    }

    /// Run the whole pipeline over one received payload.
    ///
    /// `received` is borrowed for the duration and outlives every `mail-auth`
    /// value derived from it, which is what lets the seal read the inbound
    /// chain while signing the outbound bytes.
    pub async fn process(
        &self,
        received: &[u8],
        envelope: &Envelope<'_>,
        received_header: &str,
        rewrite: &Rewrite,
        signing: Option<&SigningKey>,
    ) -> Result<Outbound, PipelineError> {
        // The host domain is borrowed by `AuthenticationResults`, so the
        // envelope handed to authentication must borrow from something that
        // outlives the seal. `self.host_domain` does.
        let envelope = Envelope {
            host_domain: &self.host_domain,
            ..envelope.clone()
        };

        // 1. Parse and verify the received bytes, and nothing else.
        let Some(mut message) = AuthenticatedMessage::parse(received) else {
            // Unparseable: no verdicts to record and nothing to seal over, but
            // the payload is still forwarded — refusing here would lose mail
            // over a parser disagreement.
            let mut payload = Received::new(received).normalise();
            payload.prepend_headers(&[received_header.to_string()]);
            return Ok(Outbound {
                verdicts: self
                    .verifier
                    .verify(Received::new(received), &envelope)
                    .await,
                payload,
                sealed: false,
                seal_skipped: Some(SealSkipped::Failed),
                signed: false,
            });
        };

        let present = message.dkim_headers.len();
        let from = from_domains(&message);
        prioritise_signatures(&mut message, &from, MAX_DKIM_SIGNATURES);
        let verified = message.dkim_headers.len();

        let authenticated = self.verifier.authenticate(&message, &envelope).await;

        // 2. Owned verdicts, so the rest of the pipeline is not tied to the
        //    parse. The ARC output and the rendered results stay borrowed —
        //    sealing consumes them — and are kept as locals here rather than
        //    packed into a struct beside the buffer they point into.
        let arc_output = authenticated.arc.as_ref();
        let results = &authenticated.results;
        let verdicts = Verdicts {
            ..authenticated_verdicts(&authenticated, &from, (present, verified))
        };

        // 3. Transport conversion (R-1). A separate buffer; `received` is still
        //    alive and still borrowed by everything above.
        let mut payload = Received::new(received).normalise();

        // 4. Pigeon's changes: headers first, then the rewrite, then the
        //    signature over the result.
        let mut headers = vec![received_header.to_string()];
        headers.push(format!(
            "Authentication-Results: {}",
            verdicts.authentication_results
        ));
        payload.prepend_headers(&headers);

        let mut signed = false;
        if let Rewrite::From(from) = rewrite {
            // Replaced, not prepended. Leaving the author's `From:` below a new
            // one produces a message with two of a field RFC 5322 permits once,
            // and receivers disagree about which one counts — a `h=from`
            // signature ordinarily covers the *last* occurrence, so Pigeon
            // would sign the original and display its own.
            let replaced = payload.remove_headers("From");
            payload.prepend_headers(&[from.header()]);
            debug_assert!(
                replaced <= 1 || cfg!(test),
                "a message carried {replaced} From: fields"
            );
            let _ = replaced;

            // R-8: a rewritten From: is never forwarded unsigned.
            let key =
                signing.ok_or_else(|| PipelineError::UnsignedRewrite("no signing key".into()))?;
            let signature = DkimSigner::from_key(key.key.clone())
                .domain(&key.domain)
                .selector(&key.selector)
                .headers(SIGNED_HEADERS)
                .sign(payload.as_bytes())
                .map_err(|e| PipelineError::UnsignedRewrite(e.to_string()))?;
            payload.prepend_headers(&[signature.to_header().trim_end().to_string()]);
            signed = true;
        }

        // 5. Seal, over the finished outbound form, using the still-live
        //    inbound chain.
        let (sealed, seal_skipped) = seal(signing, &mut payload, results, arc_output);

        // 6. Every inbound borrow dies here.
        Ok(Outbound {
            payload,
            verdicts,
            sealed,
            seal_skipped,
            signed,
        })
    }
}

/// Add an ARC set, or say why not.
///
/// A chain that arrived `cv=fail` is terminally broken: RFC 8617 does not allow
/// extending it, and `mail-auth` enforces that by refusing to seal. That is a
/// correct outcome, not a fault — distinct from having no key, or from sealing
/// being attempted and failing, which are local problems.
///
/// A free function rather than a method: it needs the key it was handed, not
/// the pipeline, and taking `&self` would have invited the key to live there.
fn seal(
    signing: Option<&SigningKey>,
    payload: &mut Relayable,
    results: &mail_auth::AuthenticationResults<'_>,
    arc_output: Option<&mail_auth::ArcOutput<'_>>,
) -> (bool, Option<SealSkipped>) {
    let Some(key) = signing else {
        return (false, Some(SealSkipped::NoKey));
    };

    if arc_output.is_some_and(|a| !a.can_be_sealed()) {
        return (false, Some(SealSkipped::ChainAlreadyFailed));
    }

    // Parsed again, because the ARC set signs what is *sent*: the message
    // including the Received header, the Authentication-Results and any
    // rewrite made above.
    let bytes = payload.as_bytes().to_vec();
    let Some(outbound) = AuthenticatedMessage::parse(&bytes) else {
        return (false, Some(SealSkipped::Failed));
    };

    // An absent inbound chain seals as i=1 with cv=none, which is what a
    // default `ArcOutput` expresses.
    let default_arc = mail_auth::ArcOutput::default();
    let arc = arc_output.unwrap_or(&default_arc);

    match ArcSealer::from_key(key.key.clone())
        .domain(&key.domain)
        .selector(&key.selector)
        .headers(SIGNED_HEADERS)
        .seal(&outbound, results, arc)
    {
        Ok(set) => {
            payload.prepend_headers(&[set.to_header().trim_end().to_string()]);
            (true, None)
        }
        Err(_) => (false, Some(SealSkipped::Failed)),
    }
}

/// Bridge to the owned verdicts, kept out of `process` so the borrow scope
/// there stays readable.
fn authenticated_verdicts(
    authenticated: &crate::verify::Authenticated<'_>,
    from_domains: &[String],
    counts: (usize, usize),
) -> Verdicts {
    authenticated.verdicts(from_domains, counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::OnceLock;

    /// One generated key for the whole module: RSA-2048 keygen is slow enough
    /// that generating per test would dominate the run.
    fn key() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            crate::dkim::KeyPair::generate(2048)
                .unwrap()
                .private_pem()
                .to_string()
        })
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_pkcs8_pem(key(), "pigeon.test", "sel").unwrap()
    }

    #[test]
    fn a_key_identity_says_which_key_material_this_is() {
        // What the published runtime's fingerprint uses to notice a rotation.
        // Rotating a key in place, under a selector that does not change, is
        // otherwise invisible: the path is the same, the selector is the same,
        // and every message afterwards is signed by a different key.
        let other = crate::dkim::KeyPair::generate(2048)
            .unwrap()
            .private_pem()
            .to_string();

        assert_eq!(
            signing_key().identity(),
            signing_key().identity(),
            "the same key loaded twice has two identities"
        );
        assert_ne!(
            signing_key().identity(),
            SigningKey::from_pkcs8_pem(&other, "pigeon.test", "sel")
                .unwrap()
                .identity(),
            "a rotated key kept its predecessor's identity"
        );
        // Bound to who it signs for: the same file installed for two domains or
        // two selectors is two signing identities, and a runtime that swapped
        // one for the other would hash the same.
        assert_ne!(
            signing_key().identity(),
            SigningKey::from_pkcs8_pem(key(), "other.test", "sel")
                .unwrap()
                .identity(),
            "the same key under a different domain has one identity"
        );
        assert_ne!(
            signing_key().identity(),
            SigningKey::from_pkcs8_pem(key(), "pigeon.test", "other")
                .unwrap()
                .identity(),
            "the same key under a different selector has one identity"
        );
    }

    /// Offline, so the result is a property of the bytes rather than of the
    /// machine. Nothing below reaches DNS anyway — every path under test has no
    /// signatures to verify or fails to parse — but "does not need the network"
    /// and "cannot use it" are different claims, and only the second one is
    /// enforceable.
    fn pipeline() -> Pipeline {
        // Built here rather than taken from `pigeon-testkit`: testkit depends
        // on this crate, so the unit-test build would link a second copy of it
        // and the two `Verifier` types would not be the same type. The
        // integration tests use testkit's fixture, which is the same resolver.
        use mail_auth::MessageAuthenticator;
        use mail_auth::hickory_resolver::{Resolver, config::ResolverConfig};

        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            mail_auth::hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .build()
        .expect("a resolver with no name servers should always build");

        Pipeline::new(
            Verifier::with_resolver(MessageAuthenticator(resolver)),
            "pigeon.test",
        )
    }

    fn envelope() -> Envelope<'static> {
        Envelope {
            client_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
            helo: "sender.example",
            mail_from: "alice@sender.example",
            host_domain: "pigeon.test",
        }
    }

    const MESSAGE: &[u8] =
        b"From: <alice@sender.example>\r\nTo: <bob@example.com>\r\nSubject: hi\r\n\r\nbody\r\n";

    const RECEIVED: &str = "Received: from sender.example by pigeon.test; today";

    fn text(out: &Outbound) -> String {
        String::from_utf8(out.payload.as_bytes().to_vec()).unwrap()
    }

    fn header_order(out: &Outbound, names: &[&str]) -> Vec<usize> {
        let body = text(out);
        names
            .iter()
            .map(|n| {
                body.find(n)
                    .unwrap_or_else(|| panic!("{n} is missing from:\n{body}"))
            })
            .collect()
    }

    #[tokio::test]
    async fn the_seal_is_the_topmost_header() {
        // RFC 8617: the ARC set covers the message as it leaves, so nothing
        // Pigeon adds may appear above it.
        let out = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::Preserve,
                Some(&signing_key()),
            )
            .await
            .unwrap();

        assert!(out.sealed, "not sealed: {:?}", out.seal_skipped);
        assert!(
            text(&out).starts_with("ARC-Seal:"),
            "something was added above the seal:\n{}",
            text(&out)
        );
    }

    #[tokio::test]
    async fn the_original_message_is_untouched_below_the_added_headers() {
        let out = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::Preserve,
                Some(&signing_key()),
            )
            .await
            .unwrap();
        assert!(
            text(&out).ends_with(std::str::from_utf8(MESSAGE).unwrap()),
            "the relayed message differs below the added headers"
        );
    }

    #[tokio::test]
    async fn added_headers_are_ordered_seal_then_results_then_received() {
        let out = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::Preserve,
                Some(&signing_key()),
            )
            .await
            .unwrap();
        let at = header_order(
            &out,
            &[
                "ARC-Seal:",
                "ARC-Message-Signature:",
                "Authentication-Results:",
                "Received: from",
            ],
        );
        assert!(
            at.windows(2).all(|w| w[0] < w[1]),
            "headers are out of order: {at:?}\n{}",
            text(&out)
        );
    }

    #[tokio::test]
    async fn a_rewritten_from_is_signed_and_the_seal_covers_the_signature() {
        // R-8, and the ordering that makes it meaningful: sealing after signing
        // means the ARC set commits to Pigeon's own DKIM signature. Sealing
        // first would sign a message that never goes on the wire.
        let out = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::From(FromAddress::new("forward@pigeon.test").unwrap()),
                Some(&signing_key()),
            )
            .await
            .unwrap();

        assert!(out.signed, "the rewritten From: was not signed");
        assert!(out.sealed);

        let at = header_order(
            &out,
            &[
                "ARC-Seal:",
                "DKIM-Signature:",
                "From: <forward@pigeon.test>",
            ],
        );
        assert!(at[0] < at[1], "the seal does not cover Pigeon's signature");
        assert!(at[1] < at[2], "the signature is below the header it signs");
    }

    #[tokio::test]
    async fn a_rewrite_replaces_the_original_from_rather_than_adding_one() {
        // Prepending leaves a message with two From: fields, which RFC 5322
        // permits once. Receivers then disagree about which one counts, and a
        // `h=from` signature ordinarily covers the last occurrence — so Pigeon
        // would sign the author's header and display its own.
        let out = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::From(FromAddress::new("forward@pigeon.test").unwrap()),
                Some(&signing_key()),
            )
            .await
            .unwrap();

        let body = text(&out);
        assert_eq!(
            body.matches("\r\nFrom:").count() + usize::from(body.starts_with("From:")),
            1,
            "the message carries more than one From: field:\n{body}"
        );
        assert!(body.contains("From: <forward@pigeon.test>"));
        assert!(
            !body.contains("alice@sender.example>\r\n"),
            "the author's From: survived:\n{body}"
        );
    }

    #[tokio::test]
    async fn a_folded_from_is_removed_whole() {
        // A header is not a line. Removing only the first line of a folded
        // From: leaves its continuation behind, which then parses as a field
        // of its own — and one that starts with whitespace, so it attaches to
        // whatever Pigeon prepended above it.
        let folded = b"From: \"A Long Display Name\"\r\n <alice@sender.example>\r\n                       To: <bob@example.com>\r\nSubject: hi\r\n\r\nbody\r\n";
        let out = pipeline()
            .process(
                folded,
                &envelope(),
                RECEIVED,
                &Rewrite::From(FromAddress::new("forward@pigeon.test").unwrap()),
                Some(&signing_key()),
            )
            .await
            .unwrap();

        let body = text(&out);
        // Scoped to the continuation line itself. The author's address still
        // appears legitimately inside `Authentication-Results` as
        // `smtp.mailfrom=`, which is a record of the envelope and not a header
        // that survived — an assertion on the bare address would have been
        // green for the wrong reason, or red for a correct one.
        assert!(
            !body.contains(" <alice@sender.example>"),
            "the folded continuation survived as its own field:\n{body}"
        );
        assert!(
            !body.contains("A Long Display Name"),
            "the first line of the folded From: survived:\n{body}"
        );
        assert!(body.contains("From: <forward@pigeon.test>"));
    }

    #[test]
    fn a_rewrite_address_containing_crlf_is_refused() {
        // The reason the value is a type rather than a String: the message is
        // assembled by concatenation, so a newline in a field value is
        // indistinguishable from the end of that field.
        for bad in [
            "a@b.example\r\nBcc: victim@example.com",
            "a@b.example\nX-Injected: yes",
            "a@b.example\rX",
            "<a@b.example>",
        ] {
            assert!(
                FromAddress::new(bad).is_err(),
                "{bad:?} was accepted as a rewrite address"
            );
        }
    }

    #[test]
    fn a_display_name_containing_structure_is_refused() {
        let ok = FromAddress::new("a@b.example").unwrap();
        for bad in ["has \"quotes\"", "has\r\nnewline", "has <brackets>"] {
            assert!(
                ok.clone().with_display_name(bad).is_err(),
                "{bad:?} was accepted as a display name"
            );
        }
        assert!(ok.with_display_name("Perfectly Fine").is_ok());
    }

    #[tokio::test]
    async fn a_rewrite_without_a_key_is_refused_rather_than_sent_unsigned() {
        // The one local failure that must not degrade. An unsigned rewrite
        // fails DMARC on a domain Pigeon controls, which is worse than not
        // rewriting at all.
        let err = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::From(FromAddress::new("forward@pigeon.test").unwrap()),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PipelineError::UnsignedRewrite(_)), "{err:?}");
    }

    #[tokio::test]
    async fn preserve_without_a_key_still_forwards_unsealed() {
        // The opposite rule, and the reason the two are separate: a missing ARC
        // set drops a recovery path, which is the pre-ARC status quo and is
        // survivable. Refusing here would lose mail over a local key problem.
        let out = pipeline()
            .process(MESSAGE, &envelope(), RECEIVED, &Rewrite::Preserve, None)
            .await
            .unwrap();
        assert!(!out.sealed);
        assert_eq!(out.seal_skipped, Some(SealSkipped::NoKey));
        assert!(text(&out).contains("Authentication-Results:"));
    }

    #[tokio::test]
    async fn authentication_results_is_written_even_when_nothing_authenticated() {
        // R-5: unconditional whenever authentication was evaluated. This
        // message is unsigned and its sender publishes nothing, which is
        // precisely the case a "write it only on failure" rule would skip.
        let out = pipeline()
            .process(
                MESSAGE,
                &envelope(),
                RECEIVED,
                &Rewrite::Preserve,
                Some(&signing_key()),
            )
            .await
            .unwrap();
        assert!(text(&out).contains("Authentication-Results: pigeon.test"));
        assert!(!out.verdicts.authentication_results.is_empty());
    }

    #[tokio::test]
    async fn a_nonconforming_payload_is_converted_before_anything_is_added() {
        // R-1, end to end: what gets signed and sent is the converted form, and
        // no bare LF survives into the relayed message.
        let raw = b"From: <alice@sender.example>\nSubject: hi\n\nbody\n.\nnot smuggled\n";
        let out = pipeline()
            .process(
                raw,
                &envelope(),
                RECEIVED,
                &Rewrite::Preserve,
                Some(&signing_key()),
            )
            .await
            .unwrap();

        assert!(out.payload.was_converted());
        assert!(
            !out.payload.as_bytes().windows(3).any(|w| w == b"\n.\n"),
            "the bare-LF dot sequence survived into the relay form"
        );
        assert!(!crate::normalize::needs_conversion(out.payload.as_bytes()));
    }

    #[tokio::test]
    async fn the_received_header_is_present_even_when_the_message_does_not_parse() {
        // Refusing over a parser disagreement would lose mail; the message is
        // still relayed, and the absence of a seal is recorded.
        let out = pipeline()
            .process(
                b"not a message at all",
                &envelope(),
                RECEIVED,
                &Rewrite::Preserve,
                Some(&signing_key()),
            )
            .await
            .unwrap();
        assert!(text(&out).starts_with("Received: from"));
        assert!(!out.sealed);
    }

    #[test]
    fn a_signing_key_never_prints_its_material() {
        let shown = format!("{:?}", signing_key());
        assert!(shown.contains("redacted"), "{shown}");
        assert!(!shown.contains("BEGIN"), "the key was printed: {shown}");
    }

    #[test]
    fn a_key_that_cannot_sign_is_refused_at_load() {
        let err = SigningKey::from_pkcs8_pem(
            "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----",
            "d",
            "s",
        );
        assert!(matches!(err, Err(PipelineError::Key(_))), "{err:?}");
    }
}
