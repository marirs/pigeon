//! The Pigeon daemon.
//!
//! # Startup gating
//!
//! Two classes of failure, deliberately treated differently:
//!
//! **Local and unambiguous — abort startup.** Unreadable database, failed
//! migration, unwritable spool, invalid TLS configuration, missing DKIM private
//! key for a signing domain, listener that will not bind. These are
//! misconfiguration, and running half-configured is worse than not running.
//!
//! **Remote DNS state — gate the individual domain, keep serving.** A domain
//! whose records regressed moves to `Error` and stops accepting its own mail.
//! The daemon still starts and other domains are unaffected.
//!
//! The distinction matters: a resolver outage must not turn into a total mail
//! outage across every domain on the host. Strictness belongs on the domain
//! lifecycle — nothing reaches `Active` without passing every check — not on
//! process startup.
//!
//! # Milestone 0
//!
//! This is the skeleton. Accepted mail is written to the spool directory and,
//! when `PIGEON_FORWARD_TO` is set, forwarded to a single hardcoded
//! destination resolved through its MX records. There is no routing table and
//! no queue: a forward that fails is logged and the spool copy is left where
//! it is, for an operator to find. Configuration comes from the environment
//! because the TOML loader and SQLite schema arrive in Milestone 1.

mod delivery;
mod reload;
mod startup;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pigeon_dns::{LookupError, MxError, MxLookup, SystemResolver, order_hosts};
use pigeon_smtp::{DataError, Envelope, Message, MessageSink, Recipient, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Where a receiving MTA listens. Overridden only by tests.
const SUBMISSION_PORT: u16 = 25;

/// How long to wait for a receiving server to answer its door.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Deliveries attempted at once.
///
/// Inbound is capped too. Bounding one direction and not the other does not
/// make the process harder to exhaust — it only changes which resource runs
/// out first.
const MAX_CONCURRENT_DELIVERIES: usize = 32;

/// How long one message may spend being forwarded, across every host tried.
///
/// `pigeon_smtp::deliver` carries its own 30-minute budget, but that bounds a
/// single *connection*. The host loop below calls it once per MX record, so a
/// destination publishing ten exchanges that accept TCP and then go silent
/// held one of `MAX_CONCURRENT_DELIVERIES` permits for five hours. Bounding
/// the connection and not the delivery is the same mistake as bounding one
/// direction of concurrency and not the other: it changes which resource runs
/// out first, not whether one does.
const TOTAL_FORWARD_BUDGET: Duration = Duration::from_secs(1800);

/// How long a queue claim is held.
///
/// Must outlast [`TOTAL_FORWARD_BUDGET`], or a row is reclaimed underneath a
/// running attempt and the outcome the remote gave is discarded as fenced.
/// Checked at startup rather than trusted: the two live in different crates.
const CLAIM_LEASE: Duration =
    Duration::from_secs(pigeon_spool::queue::DEFAULT_LEASE_SECONDS as u64);

/// How long a message may keep failing before Pigeon gives up (R-3).
///
/// Five days, the SMTP convention, and fixed: configurability is deferred, and
/// if it is ever exposed it has to be validated against the 21-day SRS window
/// — a return path that expires before the bounce is sent is a failure nobody
/// hears about.
const GIVE_UP_AFTER: Duration = Duration::from_secs(5 * 24 * 60 * 60);

/// Where forwarded mail is sent, and who we claim to be when sending it.
///
/// Generic over the resolver so delivery can be driven by `FakeResolver` in
/// tests. `MxLookup` returns `impl Future`, so it is not dyn-compatible and a
/// type parameter is the way to get the seam.
struct Forwarding<R: MxLookup> {
    resolver: Arc<R>,
    /// Name given in EHLO. Its forward and reverse DNS must agree with the
    /// sending address or receivers will treat everything as suspect.
    ehlo_name: String,
    destination: String,
    limit: Arc<Semaphore>,
    /// Always 25 in production. Injectable so a test can point the delivery
    /// path at a scripted peer on an ephemeral port instead of at the internet.
    port: u16,
    /// How long one message may spend being forwarded, across every host.
    ///
    /// A field rather than a constant for the same reason as `port`: a
    /// half-hour bound cannot be asserted against in a test suite, and a
    /// defence that is never exercised is one this project has repeatedly
    /// found to be broken.
    budget: Duration,
}

// Derived `Clone` would demand `R: Clone`, which the resolver need not be —
// every field is already shared behind an `Arc`.
impl<R: MxLookup> Clone for Forwarding<R> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            ehlo_name: self.ehlo_name.clone(),
            destination: self.destination.clone(),
            limit: Arc::clone(&self.limit),
            port: self.port,
            budget: self.budget,
        }
    }
}

/// Why a forward did not happen, keeping the distinction the delivery client
/// took the trouble to make.
///
/// `forward` used to return `Result<String, String>`. It consumed
/// `is_permanent()` internally to decide whether to try the next host and then
/// discarded it at the return, so the caller — and, from Milestone 3, the queue
/// deciding between retry and dead-letter — could not tell a refused recipient
/// from an unreachable network.
#[derive(Debug)]
enum ForwardError {
    /// Retrying will not help. Bounce rather than queue.
    Permanent(String),
    /// Worth trying again later.
    Transient(String),
}

impl ForwardError {
    fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permanent(m) => write!(f, "permanent: {m}"),
            Self::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

/// Where mail lands, and what is allowed to arrive.
/// Resolve the authentication machinery once, at startup.
///
/// Everything here is a *local* configuration question, so every failure stops
/// the process rather than being discovered one message at a time. A missing
/// SRS ring means every forwarded message loses its return path; a `rewrite_from`
/// domain with no usable key means every message for it would have to be
/// refused at delivery, after acceptance — which is the outcome R-4 exists to
/// avoid, arrived at from the other side.
fn build_auth(
    started: &startup::Started,
    snapshot: pigeon_route::Snapshot,
    hostname: &str,
) -> io::Result<Auth> {
    let checked = started.config.clone();
    let ring_path = checked.config().srs_secret_file.clone();
    let host = hostname.to_string();

    let verifier = pigeon_auth::verify::Verifier::from_system()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("resolver: {e}")))?;
    let pipeline = pigeon_auth::pipeline::Pipeline::new(verifier, host.clone());

    // Keys and the ring are derived by one closure, so every publication
    // rebuilds both from the state on disk at that moment. `pigeon srs rotate`
    // writes a new ring; a daemon holding the old one would keep issuing return
    // paths under the key that was just displaced.
    let ring_for_derive = ring_path.clone();
    let derive: Deriver = Box::new(move |snapshot| {
        let ring = pigeon_auth::KeyRing::load(&ring_for_derive)
            .map_err(|e| format!("SRS key ring {}: {e}", ring_for_derive.display()))?;
        Ok(Derived {
            keys: load_keys(snapshot, &checked)?,
            srs: Arc::new(pigeon_auth::Srs::new(ring, host.clone())),
        })
    });

    // The first publication happens here rather than through the reload path,
    // and it fails startup: a key that will not load at boot will not load at
    // the first message either, and the operator should hear about it once,
    // now, rather than per message.
    let derived = derive(&snapshot).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    tracing::info!(domains = derived.keys.len(), "loaded DKIM signing keys");

    Ok(Auth {
        pipeline: Arc::new(pipeline),
        runtime: Arc::new(RuntimeState {
            current: std::sync::RwLock::new(Arc::new(Runtime {
                snapshot: Arc::new(snapshot),
                keys: derived.keys,
                srs: derived.srs,
            })),
            ring_fingerprint: std::sync::Mutex::new(ring_fingerprint(&ring_path)),
            ring_path,
            derive,
        }),
    })
}

/// A content hash of the SRS ring file, or `None` if it cannot be read.
///
/// An unreadable ring is deliberately *not* a change: it would otherwise flap
/// between present and absent while an operator edits it, republishing on every
/// poll. A ring that stays unreadable is caught the next time it is loaded,
/// which reports the reason.
fn ring_fingerprint(path: &Path) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    Some(Sha256::digest(&bytes).into())
}

/// Parse every signing key the snapshot names.
///
/// Every failure is a *local* configuration question, so none of them is
/// tolerated: a `rewrite_from` domain with no usable key would have to have
/// every one of its messages refused after acceptance, which is the outcome
/// R-4 exists to avoid reached from the other side.
fn load_keys(
    snapshot: &pigeon_route::Snapshot,
    checked: &pigeon_config::Checked,
) -> Result<HashMap<String, pigeon_auth::pipeline::SigningKey>, String> {
    use pigeon_auth::pipeline::SigningKey;

    let mut keys = HashMap::new();
    for domain in snapshot.domains() {
        let Some(forwarding) = snapshot.forwarding(domain) else {
            continue;
        };
        let Some(identity) = &forwarding.dkim else {
            if forwarding.policy == pigeon_types::ForwardPolicy::RewriteFrom {
                return Err(format!(
                    "domain {domain} is set to rewrite_from and has no active DKIM key; \
                     a rewritten From: that cannot be signed fails DMARC on a domain \
                     Pigeon controls"
                ));
            }
            continue;
        };

        // The stored path is operator-editable, so it is resolved against the
        // configured root and refused if it escapes.
        let path = checked
            .resolve_key(&identity.private_key_path)
            .map_err(|e| format!("DKIM key for {domain}: {e}"))?;
        let pem = std::fs::read_to_string(&path)
            .map_err(|e| format!("DKIM key for {domain} at {}: {e}", path.display()))?;
        let key = SigningKey::from_pkcs8_pem(&pem, domain, &identity.selector)
            .map_err(|e| format!("DKIM key for {domain}: {e}"))?;
        keys.insert(domain.to_string(), key);
    }

    Ok(keys)
}

/// The routing table and the keys derived from it, as one indivisible thing.
///
/// They cannot be published separately. Adding a DKIM key changes the policy a
/// domain can support; rotating one changes which key must sign. Installing the
/// snapshot without its keys would leave a `rewrite_from` domain with nothing
/// to sign with, and installing keys without the snapshot would sign under a
/// policy that is no longer in force. So one struct, swapped in one write.
#[derive(Debug)]
struct Runtime {
    snapshot: Arc<pigeon_route::Snapshot>,
    /// Parsed signing keys, by domain, from the paths *this* snapshot names.
    keys: HashMap<String, pigeon_auth::pipeline::SigningKey>,
    /// The SRS ring, as of this publication.
    ///
    /// In here rather than beside it because rotation is the same kind of event
    /// as a key change: `pigeon srs rotate` writes a new ring, and a daemon
    /// holding the old one would keep signing return paths with the key that
    /// was just displaced — which verifies today and stops verifying when the
    /// operator eventually deletes it.
    srs: Arc<pigeon_auth::Srs>,
}

/// The published [`Runtime`], and what it takes to build one.
///
/// Implements [`pigeon_route::Publish`], so the reload worker installs the
/// combined state through the same path a snapshot would have taken — and a
/// key that will not load fails the publication rather than being discovered
/// one message later.
struct RuntimeState {
    current: std::sync::RwLock<Arc<Runtime>>,
    /// How keys are derived from a snapshot.
    ///
    /// A closure rather than the configuration itself, because the derivation
    /// is what has to happen on every publication and the configuration is only
    /// one of its inputs. It also lets a test publish a snapshot and see the
    /// keys rebuilt, which is the property this whole type exists for.
    derive: Deriver,
    /// What the SRS ring file looked like at the last publication.
    ///
    /// The database has `data_version` to say it changed; a file has nothing,
    /// so the content is hashed. It is a handful of lines — hashing it once a
    /// second is not a cost worth avoiding, and comparing modification times
    /// would miss a rotation landing inside a timestamp's granularity.
    ring_fingerprint: std::sync::Mutex<Option<[u8; 32]>>,
    ring_path: PathBuf,
}

/// Derives everything a [`Runtime`] holds besides the table itself.
///
/// One closure rather than two, because the keys and the SRS ring are published
/// together for the same reason they are published *with* the table: a state
/// assembled from two moments is a state nobody configured.
type Deriver = Box<dyn Fn(&pigeon_route::Snapshot) -> Result<Derived, String> + Send + Sync>;

struct Derived {
    keys: HashMap<String, pigeon_auth::pipeline::SigningKey>,
    srs: Arc<pigeon_auth::Srs>,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState")
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl RuntimeState {
    /// The state for one mail transaction.
    ///
    /// Pinned at `MAIL FROM` and used for every decision until the message is
    /// spooled, so a reload landing mid-transaction cannot accept a recipient
    /// under one configuration and sign under another.
    fn pin(&self) -> Arc<Runtime> {
        Arc::clone(&self.current.read().expect("runtime lock poisoned"))
    }

    /// Republish if the SRS ring file has changed since the last publication.
    ///
    /// Driven by the existing reload worker rather than by a watcher of its
    /// own: a second publisher would be a second thing that can install a
    /// runtime, and the ordering between the two would have to be reasoned
    /// about every time either changed. One publisher, one order.
    ///
    /// `None` when nothing changed.
    fn reconcile_ring(&self) -> Option<Result<(), String>> {
        let current = ring_fingerprint(&self.ring_path);
        if current == *self.ring_fingerprint.lock().expect("ring lock poisoned") {
            return None;
        }

        // The table is republished as it stands: what has to be rebuilt is what
        // is *derived* from it, which now includes the ring.
        let snapshot = (*self.pin().snapshot).clone();
        Some(pigeon_route::Publish::publish(self, snapshot))
    }
}

impl reload::Reconcile for RuntimeState {
    fn reconcile(&self) -> Option<Result<(), String>> {
        self.reconcile_ring()
    }
}

impl pigeon_route::Publish for RuntimeState {
    fn publish(&self, snapshot: pigeon_route::Snapshot) -> Result<(), String> {
        // Keys first: a snapshot whose keys will not load is not installed at
        // all. The previous runtime keeps serving, which is the same rule the
        // detector applies to a configuration that will not build.
        let derived = (self.derive)(&snapshot)?;
        *self.current.write().expect("runtime lock poisoned") = Arc::new(Runtime {
            snapshot: Arc::new(snapshot),
            keys: derived.keys,
            srs: derived.srs,
        });
        Ok(())
    }
}

/// Everything the authentication pipeline needs.
///
/// One `Pipeline` for the process, one `Srs`, and the published runtime. All
/// shared: the keys and the SRS ring are key material, and a copy per message
/// would be a copy of the key material per message.
#[derive(Clone)]
struct Auth {
    pipeline: Arc<pigeon_auth::pipeline::Pipeline>,
    runtime: Arc<RuntimeState>,
}

/// The database side of acceptance.
///
/// One connection, serialised: SQLite admits one writer anyway, and acceptance
/// is a single commit. `path` is here for reconciliation, which must open its
/// own connection — the one that failed may be unusable.
#[derive(Clone)]
struct Queue {
    conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    path: Arc<PathBuf>,
}

struct SpoolSink<R: MxLookup> {
    dir: Arc<PathBuf>,
    spool: pigeon_spool::Spool,
    /// Absent on the Milestone 0 environment path, where there is no database
    /// to queue into.
    queue: Option<Queue>,
    /// Absent on the Milestone 0 environment path, where there is no database
    /// and so no policy, no keys and no SRS ring.
    auth: Option<Auth>,
    /// Recipients to accept. Empty means accept anything, which is only
    /// reasonable while there is no real routing table.
    accept: Arc<HashSet<String>>,
    counter: Arc<AtomicU64>,
    /// Distinguishes identifiers from different runs of the process.
    boot: u32,
    /// Absent means spool and stop, which is useful for testing the receiver
    /// without sending anything onward.
    forwarding: Option<Forwarding<R>>,
}

// As with `Forwarding`: shared state behind `Arc`, so the resolver itself does
// not have to be `Clone` for the sink to be.
impl<R: MxLookup> Clone for SpoolSink<R> {
    fn clone(&self) -> Self {
        Self {
            dir: Arc::clone(&self.dir),
            spool: self.spool.clone(),
            queue: self.queue.clone(),
            auth: self.auth.clone(),
            accept: Arc::clone(&self.accept),
            counter: Arc::clone(&self.counter),
            boot: self.boot,
            forwarding: self.forwarding.clone(),
        }
    }
}

/// Run the authentication pipeline for this message.
///
/// The forwarding policy and the signing key come from the snapshot the
/// routing decision was made against, selected by the recipient's domain —
/// the domain Pigeon accepted the mail *for*, which is the identity it
/// forwards under and the one an ARC seal should carry.
///
/// One recipient decides it, because fan-out does not exist yet: a message
/// to several domains is Milestone 3's problem, where each destination gets
/// independently durable state. Until then the first recipient is the
/// policy, and that is a documented narrowing rather than an oversight.
async fn authenticate(
    auth: &Auth,
    runtime: Option<&Arc<Runtime>>,
    peer: std::net::IpAddr,
    helo: &str,
    envelope: &Envelope,
    received: &str,
    body: &[u8],
) -> Result<pigeon_auth::pipeline::Outbound, pigeon_auth::pipeline::PipelineError> {
    use pigeon_auth::pipeline::Rewrite;

    // Pinned at `MAIL FROM`, not read here: the policy that decides how this
    // message is signed must be the one that accepted its recipients. Reading
    // it now would let a reload between `RCPT TO` and the end of `DATA` sign
    // under a configuration that never accepted the message.
    //
    // The fallback exists only for the environment path, where there is no
    // database and every domain is unknown — which resolves to `Preserve` and
    // no key, the same as an unmanaged domain.
    let fallback = auth.runtime.pin();
    let runtime = runtime.unwrap_or(&fallback);
    let snapshot = &runtime.snapshot;

    let recipient_domain = envelope
        .recipients
        .first()
        .and_then(|r| pigeon_types::Address::parse(r).ok())
        .map(|a| a.domain().to_ascii_lowercase())
        .unwrap_or_default();

    let forwarding = snapshot.forwarding(&recipient_domain);
    let signing = runtime.keys.get(&recipient_domain);

    let rewrite = match forwarding.map(|f| f.policy) {
        Some(pigeon_types::ForwardPolicy::RewriteFrom) => {
            // The rewritten address is in the domain that signs it, which is
            // what makes the DMARC pass aligned. Anything else would sign
            // one domain's mail with another's key.
            let address = format!("srs@{recipient_domain}");
            Rewrite::From(pigeon_auth::pipeline::FromAddress::new(&address)?)
        }
        _ => Rewrite::Preserve,
    };

    let envelope_view = pigeon_auth::verify::Envelope {
        client_ip: peer,
        helo,
        mail_from: &envelope.sender,
        host_domain: "",
    };

    auth.pipeline
        .process(body, &envelope_view, received, &rewrite, signing)
        .await
}

impl<R: MxLookup + 'static> MessageSink for SpoolSink<R> {
    /// The runtime pinned for this transaction, if there is one to pin.
    ///
    /// `None` on the Milestone 0 environment path, where there is no database
    /// and so no snapshot, no keys and no policy.
    type Transaction = Option<Arc<Runtime>>;

    fn begin(&self) -> Self::Transaction {
        self.auth.as_ref().map(|a| a.runtime.pin())
    }

    fn accepts_recipient(
        &self,
        transaction: &Self::Transaction,
        address: &str,
        accepted: &[String],
    ) -> Recipient {
        // Until fan-out exists, one message is forwarded under one domain's
        // policy and signed with one domain's key — so a second recipient in a
        // different managed domain would have its policy decided by the order
        // the sender listed them in. That is a decision belonging to the
        // sender, which it must not be.
        //
        // Deferred rather than rejected: the address is deliverable, just not
        // alongside the others, so a permanent answer would tell the sender to
        // give up on a working mailbox. Milestone 3's per-destination state is
        // what removes the restriction.
        if let Some(runtime) = transaction
            && let Some(first) = accepted.first()
            && let (Ok(new), Ok(old)) = (
                pigeon_types::Address::parse(address),
                pigeon_types::Address::parse(first),
            )
        {
            let new_domain = new.domain().to_ascii_lowercase();
            let old_domain = old.domain().to_ascii_lowercase();
            if new_domain != old_domain
                && runtime.snapshot.forwarding(&new_domain).is_some()
                && runtime.snapshot.forwarding(&old_domain).is_some()
            {
                tracing::debug!(
                    %address,
                    first = %first,
                    "deferring a recipient in a second managed domain"
                );
                return Recipient::Defer;
            }
        }

        if self.accepts_recipient_inner(address) {
            Recipient::Accept
        } else {
            Recipient::Reject
        }
    }

    async fn deliver(
        &self,
        transaction: Self::Transaction,
        message: Message,
    ) -> Result<String, DataError> {
        self.deliver_inner(transaction, message).await
    }
}

impl<R: MxLookup + 'static> SpoolSink<R> {
    fn accepts_recipient_inner(&self, address: &str) -> bool {
        if self.accept.is_empty() {
            return true;
        }
        // Folds the domain only, matching `Address::same_mailbox` and RFC 5321
        // §2.4. Lowercasing the whole address made `Bob@example.com` in the
        // accept list authorise `bob@example.com` as well — a different
        // mailbox, and one the operator never listed. Over-accepting is not
        // mail loss, but it is the same folding mistake that was corrected in
        // the dedup path, and leaving one half of an invariant undone is how
        // it comes back.
        let Ok(parsed) = pigeon_types::Address::parse(address) else {
            return false;
        };
        self.accept
            .iter()
            .filter_map(|a| pigeon_types::Address::parse(a).ok())
            .any(|allowed| allowed.same_mailbox(&parsed))
    }

    async fn deliver_inner(
        &self,
        transaction: Option<Arc<Runtime>>,
        message: Message,
    ) -> Result<String, DataError> {
        let id = self.next_id();
        let Message {
            mut envelope,
            peer,
            helo,
            received,
            body,
        } = message;

        // Authentication happens here, before anything is written, because the
        // spooled bytes must be the bytes that go on the wire: a retry that
        // re-derived the relay form would be a second chance to derive it
        // differently, and the ARC set signs one of the two.
        //
        // `received` comes from the SMTP layer, which already built it for this
        // hop — trace headers are the only cross-system loop guard there is,
        // and a second generator here would be a second answer to "which host
        // handled this?".
        let processed = match &self.auth {
            Some(auth) => {
                match authenticate(
                    auth,
                    transaction.as_ref(),
                    peer,
                    &helo,
                    &envelope,
                    &received,
                    &body,
                )
                .await
                {
                    Ok(out) => Some(out),
                    Err(e) => {
                        // R-8. A rewritten `From:` that cannot be signed fails DMARC
                        // on a domain Pigeon controls, which is worse than not
                        // rewriting — so it is never written or sent. 451: the key
                        // is a local problem and the sender may usefully retry once
                        // an operator has fixed it.
                        tracing::error!(%id, error = %e, "refusing a message that cannot be signed");
                        return Err(DataError::Temporary);
                    }
                }
            }
            None => None,
        };

        // What the sender used, kept before SRS replaces it: the DSN and the
        // log need the address a person would recognise, and the envelope no
        // longer holds it after the rewrite.
        let original_sender = envelope.sender.clone();

        // The envelope sender is rewritten **once**, here, and carried. Deriving
        // it again at delivery would let a key rotation or a date change between
        // the two produce a return path that differs from the one a receiver was
        // given.
        if let Some(runtime) = transaction.as_ref()
            && !envelope.sender.is_empty()
        {
            let (local, domain) = envelope
                .sender
                .rsplit_once('@')
                .unwrap_or((envelope.sender.as_str(), ""));
            match runtime.srs.forward(local, domain, pigeon_auth::Day::now()) {
                Ok(rewritten) => envelope.sender = rewritten,
                Err(e) => {
                    // The over-long case was refused at RCPT, before acceptance
                    // (R-4). Anything reaching here is a local fault, and the
                    // message still forwards — with SPF failing at the receiver,
                    // which is the pre-SRS status quo rather than lost mail.
                    tracing::error!(%id, error = %e, "forwarding without an SRS return path");
                }
            }
        }

        let (received, body) = match &processed {
            // One buffer: the pipeline's output already carries the trace
            // header, the authentication results and the ARC set.
            Some(out) => ("", out.payload.as_bytes()),
            None => (received.as_str(), body.as_slice()),
        };

        let spool_id = match pigeon_spool::SpoolId::new(&id) {
            Ok(s) => s,
            Err(e) => {
                // Generated a few lines above, so this is a bug rather than an
                // input problem, and one to fail loudly at.
                tracing::error!(%id, error = %e, "generated an unusable spool identifier");
                return Err(DataError::Temporary);
            }
        };

        let installed = self.install(&spool_id, received, body).await;

        // Queue admission is the acceptance boundary. The spool file is durable
        // by the time this runs, so the only remaining question is whether the
        // rows that refer to it exist — and on a failed commit that question is
        // answered by reading the database back, never by assuming.
        let admitted = match (&installed, &self.queue) {
            (Ok(()), Some(queue)) => {
                match self
                    .admit(
                        queue,
                        &spool_id,
                        &envelope,
                        &original_sender,
                        received.len() + body.len(),
                        &self
                            .forwarding
                            .as_ref()
                            .map(|f| f.destination.clone())
                            .unwrap_or_default(),
                    )
                    .await
                {
                    Ok(()) => Ok(()),
                    Err((why, removable)) => {
                        if removable {
                            // Established non-commit: the file is an orphan and
                            // removing it costs a sweep nothing.
                            if let Err(e) = self.spool.remove(&spool_id).await {
                                tracing::warn!(%id, error = %e, "could not remove an orphaned spool file");
                            }
                            tracing::error!(%id, error = %why, "nothing was queued");
                        } else {
                            // Unknown: the rows may exist and the body must
                            // stay. Orphan recovery resolves it later; a
                            // duplicate on retry is survivable and losing the
                            // body is not.
                            tracing::error!(
                                %id,
                                error = %why,
                                "keeping the spooled message: the queue transaction's outcome is unknown"
                            );
                        }
                        Err(io::Error::other(why))
                    }
                }
            }
            // No database: Milestone 0's environment path, where the spool
            // write is all there is.
            (Ok(()), None) => Ok(()),
            (Err(_), _) => Ok(()),
        };

        match installed.and(admitted) {
            Ok(()) => {
                let from = display_sender(&envelope);
                tracing::info!(
                    %id,
                    %from,
                    to = ?envelope.recipients,
                    bytes = received.len() + body.len(),
                    sealed = processed.as_ref().map(|p| p.sealed),
                    signed = processed.as_ref().map(|p| p.signed),
                    "accepted"
                );
                if let Some(out) = &processed
                    && let Some(reason) = out.seal_skipped
                {
                    // A missing ARC set degrades to the pre-ARC status quo,
                    // which is survivable — but silently, which is why it is an
                    // error and not a debug line. `ChainAlreadyFailed` is the
                    // exception: that one is correct behaviour, not a fault.
                    match reason {
                        pigeon_auth::pipeline::SealSkipped::ChainAlreadyFailed => {
                            tracing::debug!(%id, "not extending a chain that arrived cv=fail");
                        }
                        other => {
                            tracing::error!(%id, reason = ?other, "forwarded without an ARC seal")
                        }
                    }
                }

                // Acknowledge now that the message is durable, and forward
                // separately. Holding the SMTP session open for the length of
                // an onward delivery would make Pigeon's response time hostage
                // to the slowest receiving server in the world.
                //
                // Nothing retries yet: a failure here leaves the message in
                // the spool and says so. The queue arrives in Milestone 3.
                // Milestone 0's path: with no database there is no queue to
                // deliver from, so the message is forwarded straight away and
                // nothing retries it. With a queue, delivery is the worker's
                // job — acceptance ends at the commit.
                if let Some(f) = self.forwarding.clone().filter(|_| self.queue.is_none()) {
                    let rotation = self.counter.load(Ordering::Relaxed);
                    let id2 = id.clone();
                    let dir = Arc::clone(&self.dir);
                    let spool_for_delivery = self.spool.clone();
                    let spool_id = match pigeon_spool::SpoolId::new(&id) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!(%id, error = %e, "generated an unusable spool id");
                            return Err(DataError::Temporary);
                        }
                    };
                    let envelope = envelope.clone();

                    // The task carries an identifier, not a message. It re-reads
                    // the body from the spool file that was just fsynced, so a
                    // queue of pending deliveries costs a few hundred bytes each
                    // instead of pinning up to `max_message_size` apiece.
                    //
                    // This is why the permit is taken *inside* the task. An
                    // earlier attempt acquired it before spawning, to bound the
                    // number of pending tasks — but `deliver` is awaited by the
                    // SMTP session, so that parked the session on the outbound
                    // pool and made the 250 hostage to the slowest receiving
                    // server in the world, which is the exact thing the comment
                    // above says this design avoids. Worse: the sender times out
                    // inside its own DATA-ack window and retries, turning an
                    // unbounded-memory bug into a duplicate-delivery one.
                    tokio::spawn(async move {
                        let _permit = match f.limit.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::error!(id = %id2, "delivery limiter closed");
                                return;
                            }
                        };

                        let spooled = match spool_for_delivery.read(&spool_id).await {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!(id = %id2, error = %e, "cannot re-read spooled message");
                                return;
                            }
                        };

                        // The spooled file is already header-then-body, so it
                        // goes out as one part.
                        let destination = f.destination.clone();
                        match forward(&f, rotation, &destination, &envelope.sender, &spooled).await
                        {
                            Ok(remote) => {
                                tracing::info!(id = %id2, %remote, "forwarded");
                                // Pigeon is a relay, not an archive. The spool
                                // copy exists to survive a crash between
                                // acceptance and delivery, and that window has
                                // now closed.
                                if let Err(e) = discard_spooled(&dir, &id2).await {
                                    tracing::warn!(id = %id2, error = %e, "could not clean spool");
                                }
                            }
                            // Kept on failure, deliberately: with no retry queue
                            // yet, this copy is the only thing between a
                            // transient failure and a lost message.
                            //
                            // The permanent/transient split is logged rather
                            // than acted on, because there is nothing yet to
                            // act with. Milestone 3's queue is what turns it
                            // into retry-or-dead-letter; until then it tells an
                            // operator reading the log whether the message is
                            // worth resending by hand.
                            Err(e) => tracing::error!(
                                id = %id2,
                                error = %e,
                                permanent = e.is_permanent(),
                                "forwarding failed; message left in spool"
                            ),
                        }
                    });
                }

                Ok(id)
            }
            Err(e) => {
                // A 451 tells the sender to try again later. Answering 250 for
                // a message that never reached disk would silently lose it,
                // since the sender then considers it delivered.
                tracing::error!(%id, error = %e, "could not spool message");
                Err(DataError::Temporary)
            }
        }
    }
}

impl<R: MxLookup> SpoolSink<R> {
    /// A spool identifier that will not collide with one from a previous run.
    ///
    /// The counter restarts at zero on every boot, so `secs-000000` is handed
    /// out again within any second the process starts in — and because failed
    /// messages are retained deliberately, a collision would overwrite mail
    /// that was already acknowledged. `boot` distinguishes runs; `create_new`
    /// in `write_durably` refuses to clobber if one slips through anyway.
    fn next_id(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{secs:010}-{boot:08x}-{n:06}", boot = self.boot)
    }

    /// Put the message on disk so that a `250` can be promised.
    ///
    /// Writes, fsyncs, installs without clobbering, and fsyncs the directory.
    /// The envelope is no longer written beside it: the sender and the
    /// recipients live in `message`, `original_recipient` and `delivery` rows,
    /// which is also what makes them queryable and retryable.
    async fn install(
        &self,
        spool_id: &pigeon_spool::SpoolId,
        received: &str,
        body: &[u8],
    ) -> io::Result<()> {
        // Header then body, written in sequence rather than concatenated, so
        // the message is not copied to prepend a few hundred bytes to it.
        self.spool
            .install(spool_id, &[received.as_bytes(), body])
            .await
            .map_err(io::Error::from)
    }

    /// Queue what was just spooled, and decide what the sender is told.
    ///
    /// The acceptance boundary: `250` means these rows are committed, not that
    /// a forward was attempted. Returns whether the spool file may be removed
    /// on failure — which only an *established* non-commit permits.
    async fn admit(
        &self,
        queue: &Queue,
        spool_id: &pigeon_spool::SpoolId,
        envelope: &Envelope,
        original_sender: &str,
        size: usize,
        destination: &str,
    ) -> Result<(), (String, bool)> {
        use pigeon_spool::accept::{Acceptance, Destination};

        let acceptance = Acceptance {
            spool_id: spool_id.clone(),
            return_path: envelope.sender.clone(),
            original_sender: original_sender.to_string(),
            size_bytes: size as i64,
            // Recorded, never re-resolved. Routing from the snapshot arrives
            // with fan-out; until then there is one destination and the
            // revision is what the pinned runtime said at acceptance.
            routing_revision: 0,
            routing_fingerprint: vec![0; 32],
            original_recipients: envelope.recipients.clone(),
            destinations: vec![Destination {
                address: destination.to_string(),
                // Every recipient reaches this destination today, because
                // there is one. A DSN still names the address the sender
                // wrote, which is the point of recording the mapping at all.
                from_recipients: (0..envelope.recipients.len()).collect(),
            }],
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut conn = queue.conn.lock().await;
        match pigeon_spool::accept(&mut conn, &queue.path, &[acceptance], now) {
            Ok(_) => Ok(()),
            Err(failure) => {
                let removable = failure.spool_may_be_removed();
                Err((failure.to_string(), removable))
            }
        }
    }
}

/// What an earlier run left behind.
#[derive(Debug, Default, PartialEq, Eq)]
struct SpoolSurvey {
    /// Acknowledged messages that were never delivered.
    messages: usize,
    /// Temporary files from a write that never completed.
    partials: usize,
}

/// Look at what is in the spool, without changing any of it.
///
/// Partials are counted rather than removed. A sweep cannot tell an abandoned
/// temporary from one a concurrently running instance is writing this instant,
/// and deleting the second is destroying mail in flight to save a few bytes.
/// They are inert — `boot` differs per run, so no later identifier reuses the
/// name — but "harmless" and "invisible" are not the same thing, and an
/// operator whose disk is filling should be able to see why.
async fn survey_spool(dir: &Path) -> io::Result<SpoolSurvey> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut survey = SpoolSurvey::default();
    while let Some(e) = entries.next_entry().await? {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".eml") {
            survey.messages += 1;
        } else if name.starts_with('.') && name.ends_with(".partial") {
            survey.partials += 1;
        }
    }
    Ok(survey)
}

/// Remove a spooled message once it is safely somewhere else.
async fn discard_spooled(dir: &Path, id: &str) -> io::Result<()> {
    // Through the spool, so removal is one implementation: unlink, then flush
    // the directory, and a missing file is the desired state rather than an
    // error — the operator may have cleaned up, or a crash may already have
    // done the work.
    let spool = pigeon_spool::Spool::new(dir.to_path_buf());
    let id = pigeon_spool::SpoolId::new(id)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    spool.remove(&id).await.map_err(io::Error::from)
}

/// Send one message onward.
///
/// Hosts are tried in preference order, but only for failures worth retrying.
/// A permanent rejection stops the attempt immediately: the backup MX for a
/// domain answers from the same mailbox database as the primary, so asking it
/// about a recipient the primary just refused only wastes time and makes the
/// sender look like it is probing.
async fn forward<R: MxLookup>(
    f: &Forwarding<R>,
    rotation: u64,
    destination: &str,
    // The envelope sender to transmit: the SRS return path stored at
    // acceptance, or empty for a bounce.
    return_path: &str,
    message: &[u8],
) -> Result<String, ForwardError> {
    // The whole forward, not one connection. Every wait below is measured
    // against this, so the total cost of a message is bounded however many
    // hosts the destination publishes.
    let deadline = Instant::now() + f.budget;

    let domain = destination
        .rsplit_once('@')
        .map(|(_, d)| d)
        .ok_or_else(|| {
            // Startup validates the destination, so reaching this means the guard
            // was bypassed. Permanent either way: retrying will not add an '@'.
            ForwardError::Permanent(format!("destination {destination} has no domain"))
        })?;

    let hosts = match f.resolver.lookup_mx(domain).await {
        Ok(records) => order_hosts(&records, rotation).map_err(|e| match e {
            // The domain has said in DNS that it accepts no mail. Retrying is
            // not politeness, it is ignoring the answer.
            MxError::NullMx => ForwardError::Permanent(e.to_string()),
            // Records exist but none is usable — malformed exchanges, say.
            // Transient: the zone may be mid-edit, and this is the direction
            // that does not bounce mail which would have delivered.
            MxError::NoUsableHost => ForwardError::Transient(e.to_string()),
        })?,
        // A domain with no MX still accepts mail at its own address record.
        // This is the implicit MX rule, and skipping it loses mail to small
        // domains that never published one.
        Err(LookupError::NoRecords(_)) => vec![domain.to_string()],
        Err(e) if e.is_permanent() => return Err(ForwardError::Permanent(e.to_string())),
        Err(e) => return Err(ForwardError::Transient(e.to_string())),
    };

    // The envelope Pigeon sends is its own: one recipient, and the return path
    // the message was accepted with. Built from the two arguments rather than
    // from a caller's envelope, because a caller that supplied both a
    // recipient list and a destination would have two answers to one question
    // — and the recipient list was silently ignored.
    let outgoing = Envelope {
        sender: return_path.to_string(),
        recipients: vec![destination.to_string()],
    };

    // Transient by default: having tried nothing is not evidence that the
    // destination is refusing.
    let mut last = ForwardError::Transient("no hosts tried".into());

    for host in &hosts {
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            tracing::warn!(%host, "forward budget exhausted; remaining hosts not tried");
            return Err(ForwardError::Transient(
                "overall forward budget exhausted".into(),
            ));
        };

        let connect = tokio::time::timeout(
            CONNECT_TIMEOUT.min(remaining),
            TcpStream::connect((host.as_str(), f.port)),
        );

        let stream = match connect.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                last = ForwardError::Transient(format!("{host}: {e}"));
                tracing::warn!(%host, error = %e, "connect failed, trying next host");
                continue;
            }
            Err(_) => {
                last = ForwardError::Transient(format!("{host}: connect timed out"));
                tracing::warn!(%host, "connect timed out, trying next host");
                continue;
            }
        };

        // Recomputed: the connect above consumed part of the budget.
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Err(ForwardError::Transient(
                "overall forward budget exhausted".into(),
            ));
        };

        // Bound to outlive the future that borrows it.
        let parts: [&[u8]; 1] = [message];
        let attempt = tokio::time::timeout(
            remaining,
            pigeon_smtp::deliver(stream, &f.ehlo_name, &outgoing, &parts),
        );

        match attempt.await {
            Ok(Ok(accepted)) => return Ok(accepted.message),
            // A permanent rejection stops the attempt immediately: the backup
            // MX for a domain answers from the same mailbox database as the
            // primary, so asking it about a recipient the primary just refused
            // only wastes time and makes the sender look like it is probing.
            Ok(Err(e)) if e.is_permanent() => {
                return Err(ForwardError::Permanent(format!("{host}: {e}")));
            }
            Ok(Err(e)) => {
                last = ForwardError::Transient(format!("{host}: {e}"));
                tracing::warn!(%host, error = %e, "temporary failure, trying next host");
            }
            Err(_) => {
                last = ForwardError::Transient(format!("{host}: forward budget exhausted"));
                tracing::warn!(%host, "forward budget exhausted mid-delivery");
            }
        }
    }

    Err(last)
}

/// The null sender prints as `<>` rather than as nothing, so a bounce is
/// distinguishable from a truncated log line.
fn display_sender(envelope: &Envelope) -> &str {
    if envelope.sender.is_empty() {
        "<>"
    } else {
        envelope.sender.as_str()
    }
}

/// Create the spool directory and prove it is actually usable.
///
/// `create_dir_all` succeeds on a directory that already exists and is
/// read-only, so on its own it does not support the startup-gating promise
/// this module opens by making. The probe writes, fsyncs and removes a file by
/// the same route a message takes, which is the only way to learn that the
/// path is writable, that fsync works on it, and that the process is not out
/// of space or inodes — before the listener binds and a sender is told 250.
async fn prepare_spool(dir: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;

    // 0700 on a directory we created. Restricting an existing one is not our
    // decision to make — the operator may have set a group deliberately — but
    // the permissions are logged below so a permissive spool is visible rather
    // than assumed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = tokio::fs::metadata(dir).await?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %dir.display(),
                mode = format!("{mode:04o}"),
                "spool directory is accessible to other local users; 0700 is expected"
            );
        }
    }

    // Through the spool, by the same route a message takes — which is the
    // whole point of a probe: it learns that the path is writable, that fsync
    // works on it, and that the process is not out of space or inodes, using
    // the code that will do it for real.
    let spool = pigeon_spool::Spool::new(dir.to_path_buf());
    let probe_id = pigeon_spool::SpoolId::new("pigeon-writable-probe")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    // An earlier run that died between the write and the removal leaves this
    // behind, and a probe that fails on its own leftovers is a daemon that
    // will not start for a reason that no longer exists.
    spool.remove(&probe_id).await.map_err(io::Error::from)?;
    spool
        .install(&probe_id, &[b"probe"])
        .await
        .map_err(io::Error::from)?;
    spool.remove(&probe_id).await.map_err(io::Error::from)?;
    Ok(())
}

/// Identifies this process's claims.
///
/// Hostname plus a random boot value (R-7). Not a PID, which is reused within
/// minutes on a busy host, and not a timestamp alone, which collides across
/// machines that boot together and after a clock step. The hostname is for the
/// operator reading a stuck row; the random half is what makes it unique.
fn worker_identity(hostname: &str) -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // A worker that cannot generate a unique identity would share one, and
        // two workers sharing an identity is precisely what the claim token
        // exists to survive — but it also makes a log unreadable. Fall back to
        // the clock rather than to a constant.
        return format!("{hostname}-{}", unix_now());
    }
    format!(
        "{hostname}-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Seconds since the Unix epoch.
///
/// Wall clock, because the queue's schedule has to survive a restart and a
/// monotonic clock does not.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // `Display`, not `Debug`. Returning `Result` from `main` prints the
            // debug form, which renders a multi-line explanation as one line of
            // escaped `\n` — and every startup error here is a paragraph
            // telling an operator what to do about it.
            eprintln!("pigeond: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Milestone 1 configuration when a file is named, Milestone 0 environment
    // variables otherwise.
    //
    // Both paths exist on purpose and only for now. `startup::start` runs the
    // whole ordered sequence — validate, migrate, cross-check, probe the spool —
    // but routing still comes from `PIGEON_ACCEPT`, because the routing snapshot
    // is what replaces it and the snapshot builder is not written. Wiring the
    // config file to a routing table that does not exist would be pretending.
    //
    // The environment path goes away when the snapshot builder lands, and with
    // it `PIGEON_ACCEPT` and `PIGEON_FORWARD_TO`.
    let booted = match std::env::var("PIGEON_CONFIG") {
        Ok(path) if !path.trim().is_empty() => {
            let mut started = startup::start(Path::new(path.trim()), |dir| async move {
                prepare_spool(&dir).await
            })
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;

            if started.migration.is_empty() {
                tracing::info!(version = started.migration.to, "database schema up to date");
            } else {
                tracing::info!(
                    from = started.migration.from,
                    to = started.migration.to,
                    applied = ?started.migration.versions,
                    backup = ?started.migration.backup,
                    "database migrated"
                );
            }
            for w in &started.warnings {
                tracing::warn!("{w}");
            }

            // The routing table is built and validated — every rule in it has
            // passed the checks SQLite cannot make — but it is not yet what
            // decides where mail goes. Acceptance still comes from
            // `PIGEON_ACCEPT` and delivery from `PIGEON_FORWARD_TO`.
            //
            // Wiring acceptance to the snapshot while delivery still goes to
            // one hardcoded address would accept mail for `hello@example.com`
            // on the strength of a rule and then ignore where that rule points.
            // Connecting both means fanning one message out to several
            // destinations with per-recipient outcomes, which needs the
            // Milestone 3 queue — finding 19 is the same gap seen from the
            // delivery side.
            //
            // So it is reported rather than half-used, and the log says which.
            let domains = started.snapshot.domain_names().count();
            let schema = pigeon_db::schema_version(&started.db).unwrap_or(0);
            let db_path = started.config.config().database.clone();
            tracing::info!(schema, "control plane open");
            tracing::info!(
                domains,
                "routing table built and validated. It is not serving yet: acceptance \
                 still comes from PIGEON_ACCEPT and delivery from PIGEON_FORWARD_TO."
            );

            // The pieces the reload worker needs, carried forward. It is
            // deliberately **not** started here: everything between this point
            // and the listener binding can fail, and a worker started before
            // them would be left running by an early return.
            //
            // That is survivable now — the worker also exits when its stop
            // sender is dropped — but relying on the escape hatch instead of the
            // ordering means the next fallible step added above the start is a
            // hang again.
            // The snapshot rather than a `Router`: the daemon publishes a
            // combined runtime — the table *and* the keys derived from it —
            // and a `Router` here would be a second place a table could be
            // installed, which is exactly the split this replaces.
            let snapshot = started.snapshot.clone();
            let watcher = std::mem::take(&mut started.watcher);

            Some((started, (db_path, snapshot, watcher)))
        }
        _ => {
            tracing::warn!(
                "PIGEON_CONFIG is unset: running on Milestone 0 environment configuration.                  No database, no routing table, no DNS validation."
            );
            None
        }
    };

    let listen = match &booted {
        Some((b, _)) => b.config.config().smtp.inbound.listen.to_string(),
        None => env_or("PIGEON_LISTEN", "127.0.0.1:2525"),
    };
    let hostname = match &booted {
        Some((b, _)) => b.config.config().hostname.clone(),
        None => env_or("PIGEON_HOSTNAME", "localhost"),
    };
    // The listener config takes `hostname` by value below.
    let hostname_for_worker = hostname.clone();
    let spool = match &booted {
        Some((b, _)) => b.config.config().spool.clone(),
        None => PathBuf::from(env_or("PIGEON_SPOOL", "./spool")),
    };

    // Case preserved. The local part belongs to the destination host and only
    // the domain may be folded, which `accepts_recipient` does at comparison
    // time — see `Address::same_mailbox`.
    let accept: HashSet<String> = env_or("PIGEON_ACCEPT", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Entries that cannot be parsed would silently never match, so a typo in
    // the accept list would present as mail being refused for no stated
    // reason. Local, unambiguous misconfiguration: stop startup.
    for entry in &accept {
        if pigeon_types::Address::parse(entry).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("PIGEON_ACCEPT contains an invalid address: {entry:?}"),
            ));
        }
    }

    // Already done inside `startup::start` on the config path, in the ordered
    // position. Repeating it here would probe twice and, worse, would put step 6
    // after step 8 for one of the two paths.
    if booted.is_none() {
        // An unusable spool is local, unambiguous misconfiguration, so it stops
        // startup rather than being discovered on the first message.
        prepare_spool(&spool).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("spool directory {} is unusable: {e}", spool.display()),
            )
        })?;
    }
    let sink_dir = spool.clone();

    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {listen}: {e}")))?;

    if accept.is_empty() {
        tracing::warn!(
            "PIGEON_ACCEPT is unset: accepting every recipient. \
             Set it to a comma-separated list once you have real addresses."
        );
    }

    tracing::info!(
        %listen,
        %hostname,
        spool = %spool.display(),
        recipients = accept.len(),
        "pigeond listening"
    );

    // A resolver that cannot be built is local misconfiguration and stops
    // startup. A resolver that later fails to answer is not, and must not.
    let forwarding = match std::env::var("PIGEON_FORWARD_TO") {
        Ok(destination) if !destination.trim().is_empty() => {
            let destination = destination.trim().to_string();

            // Local, unambiguous misconfiguration, so it stops startup — the
            // policy this module opens by stating. Checked here rather than
            // per-message because the alternative is a daemon that starts
            // cleanly, answers 250 to everything, and fails every delivery.
            if pigeon_types::Address::parse(&destination).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("PIGEON_FORWARD_TO is not a valid address: {destination:?}"),
                ));
            }

            let resolver = SystemResolver::from_system()
                .map_err(|e| io::Error::other(format!("cannot build resolver: {e}")))?;
            tracing::info!(%destination, "forwarding enabled");
            Some(Forwarding {
                resolver: Arc::new(resolver),
                ehlo_name: hostname.clone(),
                destination,
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: SUBMISSION_PORT,
                budget: TOTAL_FORWARD_BUDGET,
            })
        }
        _ => {
            tracing::info!("PIGEON_FORWARD_TO is unset: messages will be spooled only");
            None
        }
    };

    // Anything already in the spool was accepted by a previous run and never
    // delivered. Nothing rescans it yet, so the least Pigeon can do is refuse
    // to let it pass unnoticed — an operator who is never told has no way to
    // discover it except by looking.
    match survey_spool(&sink_dir).await {
        Ok(s) => {
            if s.messages > 0 {
                tracing::warn!(
                    stranded = s.messages,
                    path = %sink_dir.display(),
                    "spool is not empty: these messages were acknowledged but never delivered, \
                     and nothing will retry them. Inspect and resend or remove them."
                );
            }
            if s.partials > 0 {
                // Not removed here: see `survey_spool`. Named so that disk
                // consumed by a crash loop is attributable rather than
                // mysterious.
                tracing::warn!(
                    partials = s.partials,
                    path = %sink_dir.display(),
                    "spool holds incomplete temporary files from writes that never finished. \
                     They are never read and never retried; remove them once no other \
                     pigeond is running against this spool."
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not read the spool directory"),
    }

    // Everything the authentication pipeline needs, resolved once here rather
    // than per message: the SRS ring, the per-domain signing keys, and the
    // routing table the policy is read from.
    //
    // The ring is loaded once and shared by both users below. Loading it twice
    // would put two copies of the secret in memory and, worse, allow them to
    // disagree after a rotation.
    let auth = match &booted {
        Some((b, (_, snapshot, _))) => Some(build_auth(b, snapshot.clone(), &hostname)?),
        None => None,
    };

    // R-4: a sender whose rewritten return path would not fit in a 64-octet
    // local part cannot be forwarded, and the last moment at which refusing is
    // still the *upstream* MTA's problem is `RCPT`. After `250` there is a
    // message that can neither be forwarded nor bounced, and generating a DSN
    // here would be generating mail — which needs the Milestone 3 queue.
    //
    // Absent configuration, no check: a Pigeon with no SRS ring refuses nobody
    // for this reason.
    // Cloned before the sink takes ownership: the reload worker publishes into
    // the same state the sink reads from, which is the point.
    let auth_runtime = auth.as_ref().map(|a| Arc::clone(&a.runtime));

    let return_path = auth.as_ref().map(|a| {
        // The published runtime rather than a captured ring: a rotation must
        // change what this refuses as well as what the pipeline signs, and both
        // read the same state.
        let runtime = Arc::clone(&a.runtime);
        Arc::new(move |sender: &str| {
            let srs = Arc::clone(&runtime.pin().srs);
            let (local, domain) = sender.rsplit_once('@').unwrap_or((sender, ""));
            match srs.forward(local, domain, pigeon_auth::Day::now()) {
                Err(pigeon_auth::SrsError::TooLong { octets }) => Err(octets),
                // Every other failure is about this host — no signing key, a
                // ring that stopped signing — and is not the sender's fault.
                // Refusing their mail for it would be blaming them for a local
                // fault.
                _ => Ok(()),
            }
        }) as Arc<pigeon_smtp::server::SharedReturnPathCheck>
    });

    // A claim must outlast the delivery it covers, or a row is reclaimed
    // underneath a live attempt and the remote's real answer is discarded as
    // fenced. The two constants live in different crates, so the relationship
    // is checked rather than assumed — and at startup, because the failure it
    // prevents looks like a remote problem rather than a configuration one.
    pigeon_spool::queue::assert_lease_exceeds_deadline(
        CLAIM_LEASE.as_secs() as i64,
        TOTAL_FORWARD_BUDGET.as_secs() as i64,
    );

    // The queue's own connection. Opened here rather than shared with the
    // reload worker's: that one is read-only by design, so that a detector
    // cannot write, and acceptance needs to.
    let queue = match &booted {
        Some((b, (db_path, _, _))) => {
            let conn = pigeon_db::open(db_path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot open {} for queueing: {e}", db_path.display()),
                )
            })?;
            let _ = b;
            Some(Queue {
                conn: Arc::new(tokio::sync::Mutex::new(conn)),
                path: Arc::new(db_path.clone()),
            })
        }
        None => None,
    };

    let sink = SpoolSink {
        queue,
        spool: pigeon_spool::Spool::new(sink_dir.clone()),
        dir: Arc::new(sink_dir),
        auth,
        accept: Arc::new(accept),
        counter: Arc::new(AtomicU64::new(0)),
        boot: std::process::id(),
        forwarding,
    };

    let config = ServerConfig {
        hostname,
        // TLS arrives with the rest of Milestone 5; advertising it now would
        // invite clients to negotiate something that does not exist.
        tls_available: false,
        return_path,
        ..Default::default()
    };

    // The delivery loop, if there is a queue to deliver from. Started after
    // every fallible step, for the reason the reload worker is: an early `?`
    // between the start and the listener bind would drop the handle and leave
    // the task running.
    let stop_delivery = match (&sink.queue, &sink.forwarding) {
        (Some(queue), Some(forwarding)) => {
            let worker = worker_identity(&hostname_for_worker);
            tracing::info!(%worker, concurrency = MAX_CONCURRENT_DELIVERIES, "delivery worker starting");
            let d = delivery::Deliverer::start(delivery::DeliveryConfig {
                queue: queue.clone(),
                spool: sink.spool.clone(),
                forwarding: forwarding.clone(),
                concurrency: MAX_CONCURRENT_DELIVERIES,
                lease_seconds: CLAIM_LEASE.as_secs() as i64,
                horizon_seconds: GIVE_UP_AFTER.as_secs() as i64,
                worker,
            });
            Some(d)
        }
        _ => None,
    };

    // Supervised from here rather than left to a dropped handle. A panicking
    // task cannot report its own death, and an unpolled `JoinHandle` holds the
    // result silently — a daemon that spawned the worker and forgot it would
    // keep serving the last published table forever with routing frozen and
    // nothing saying why.
    // Started here, after every fallible step: the spool probe, the listener
    // bind, the resolver. Nothing below this line returns early before the
    // shutdown path.
    //
    // The routing table is republished when the database changes even though
    // nothing routes from it yet, so the detector — the part with the property
    // worth proving — is exercised by every run rather than only once it has a
    // consumer.
    // The reload worker publishes into the combined runtime, so a reload that
    // adds or rotates a key installs the table and the key together or neither.
    // Publishing the table alone would leave a `rewrite_from` domain with no
    // key, or one still signing with the key that was just retired.
    let stop_reload = booted
        .zip(auth_runtime)
        .map(|((_, (db_path, _, watcher)), runtime)| {
            let r = reload::Reloader::start(db_path, runtime, watcher);
            // `supervise` consumes the handle and becomes the only join, so the
            // stopper is taken first. Two ways to stop one worker would be two
            // orderings to keep straight.
            let stopper = r.stopper();
            (stopper, r.supervise())
        });

    let outcome = tokio::select! {
        r = pigeon_smtp::serve(listener, config, sink) => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    };

    // Signalled *and* joined, through the supervisor.
    if let Some((stopper, supervisor)) = stop_reload {
        stopper.stop_and_join(supervisor).await;
    }

    // The delivery loop stops taking new work; attempts already in flight are
    // left to finish or to be reclaimed by lease expiry after a restart. Not
    // joined, deliberately: a delivery can take the whole forward budget, and
    // waiting for one would make shutdown hostage to the slowest remote server
    // currently being tried. The claim token is what makes an unjoined
    // attempt harmless.
    if let Some(d) = stop_delivery {
        d.stop();
        // Supervised so a panic in the loop is reported rather than swallowed,
        // and not awaited so shutdown does not wait on a delivery in flight.
        drop(d.supervise());
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    /// A private directory that removes itself.
    ///
    /// A dependency for this would be three lines of `Cargo.toml` and a new
    /// entry in the reviewed dependency set, for something the standard
    /// library already does.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let unique = format!(
                "pigeond-test-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best effort: a failure here must not mask the test's own result.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A sink that spools and stops. `FakeResolver` names the type parameter
    /// without ever being asked anything.
    fn sink(dir: &Path, accept: &[&str]) -> SpoolSink<pigeon_dns::FakeResolver> {
        SpoolSink {
            queue: None,
            spool: pigeon_spool::Spool::new(dir.to_path_buf()),
            auth: None,
            dir: Arc::new(dir.to_path_buf()),
            accept: Arc::new(accept.iter().map(|s| s.to_string()).collect()),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x1234_5678,
            forwarding: None,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_spooled_message_is_the_bytes_that_will_be_sent() {
        // The envelope no longer sits beside the message: the sender and the
        // recipients are `message`, `original_recipient` and `delivery` rows,
        // which is what makes them queryable and retryable. What is on disk is
        // exactly what goes on the wire.
        let tmp = TempDir::new("write");
        let s = sink(tmp.path(), &[]);

        let id = s.next_id();
        let spool_id = pigeon_spool::SpoolId::new(&id).unwrap();
        s.install(&spool_id, "Received: here\r\n", b"body\r\n")
            .await
            .expect("install");

        let eml = tokio::fs::read(tmp.path().join(format!("{id}.eml")))
            .await
            .unwrap();
        assert_eq!(eml, b"Received: here\r\nbody\r\n");

        // And nothing beside it.
        let mut entries: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, vec![format!("{id}.eml")], "a sidecar was written");
    }

    #[tokio::test]
    async fn discarding_a_message_twice_is_not_an_error() {
        // The operator may have cleaned up by hand, and a second failure here
        // would only produce noise about work already done.
        let tmp = TempDir::new("discard");
        discard_spooled(tmp.path(), "absent")
            .await
            .expect("discard");
    }

    /// A sink with a real database behind it, for the acceptance path.
    fn queued_sink(dir: &Path) -> (SpoolSink<pigeon_dns::FakeResolver>, PathBuf) {
        let db = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&db).unwrap();
        pigeon_db::migrate(&mut conn, &db).unwrap();

        let mut s = sink(dir, &[]);
        s.queue = Some(Queue {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            path: Arc::new(db.clone()),
        });
        (s, db)
    }

    // ------------------------------------------------------ the delivery loop

    /// A queue with `n` due deliveries and their spool files, plus a deliverer
    /// pointed at `peer_addr`.
    async fn delivery_fixture(
        dir: &Path,
        peer_addr: SocketAddr,
        destinations: &[&str],
        concurrency: usize,
        write_bodies: bool,
    ) -> (Queue, delivery::Deliverer) {
        use pigeon_dns::{FakeResolver, MxRecord};

        let db = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&db).unwrap();
        pigeon_db::migrate(&mut conn, &db).unwrap();
        let queue = Queue {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            path: Arc::new(db.clone()),
        };
        let spool = pigeon_spool::Spool::new(dir.to_path_buf());

        for (i, destination) in destinations.iter().enumerate() {
            let spool_id = pigeon_spool::SpoolId::new(&format!("msg-{i}")).unwrap();
            if write_bodies {
                spool
                    .install(&spool_id, &[b"From: <a@remote.test>\r\n\r\nbody\r\n"])
                    .await
                    .unwrap();
            }
            let acceptance = pigeon_spool::accept::Acceptance {
                spool_id,
                return_path: "SRS0=tag=AAA=remote.test=alice@pigeon.test".into(),
                original_sender: "alice@remote.test".into(),
                size_bytes: 30,
                routing_revision: 1,
                routing_fingerprint: vec![0; 32],
                original_recipients: vec!["hello@example.com".into()],
                destinations: vec![pigeon_spool::accept::Destination {
                    address: (*destination).to_string(),
                    from_recipients: vec![0],
                }],
            };
            let mut conn = queue.conn.lock().await;
            // Accepted *now*: a message dated at the epoch is five days past
            // the give-up horizon before the worker ever sees it.
            pigeon_spool::accept(&mut conn, &queue.path, &[acceptance], unix_now()).unwrap();
        }

        let deliverer = delivery::Deliverer::start(delivery::DeliveryConfig {
            queue: queue.clone(),
            spool,
            forwarding: Forwarding {
                resolver: Arc::new(FakeResolver::new().with(
                    "example.net",
                    vec![MxRecord::new(10, peer_addr.ip().to_string())],
                )),
                ehlo_name: "pigeon.test".into(),
                destination: String::new(),
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: peer_addr.port(),
                budget: Duration::from_secs(5),
            },
            concurrency,
            lease_seconds: 2400,
            horizon_seconds: 5 * 24 * 60 * 60,
            worker: "test-worker".into(),
        });

        (queue, deliverer)
    }

    async fn states(queue: &Queue) -> Vec<String> {
        let conn = queue.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT state FROM delivery ORDER BY destination")
            .unwrap();
        let mut v: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn no_more_is_claimed_than_can_be_attempted() {
        // The permit is acquired *before* the claim, so a row is only claimed
        // when it is about to be attempted. Claiming first and waiting for a
        // permit afterwards would let a row spend its lease sitting in memory,
        // and the lease-outlasts-the-deadline guarantee would prove nothing.
        //
        // Observable with one permit and two due deliveries: exactly one row
        // may be `delivering` at a time.
        let tmp = TempDir::new("permit-order");
        // A peer that accepts the connection and then says nothing, so the
        // first attempt stays in flight for the length of the test.
        let (peer_addr, _t) = pigeon_testkit::Peer::new()
            .send("220 test.invalid ESMTP")
            .stall(Duration::from_secs(30))
            .close()
            .spawn()
            .await;

        let (queue, deliverer) = delivery_fixture(
            tmp.path(),
            peer_addr,
            &["a@example.net", "b@example.net"],
            1,
            true,
        )
        .await;

        // Long enough for the loop to claim, connect and block.
        tokio::time::sleep(Duration::from_millis(600)).await;

        let states = states(&queue).await;
        let delivering = states.iter().filter(|s| *s == "delivering").count();
        assert_eq!(
            delivering, 1,
            "with one permit, {delivering} rows were claimed at once: {states:?}"
        );

        deliverer.stop();
    }

    #[tokio::test]
    async fn a_missing_body_is_a_local_failure_not_a_remote_rejection() {
        // Telling the sender their recipient refused the message would be
        // false and unactionable: the fault is here. Deferred, so it can still
        // be delivered if an operator restores the file — and if it never is,
        // the age horizon gives up and says so honestly.
        let tmp = TempDir::new("missing-body");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;

        let (queue, deliverer) = delivery_fixture(
            tmp.path(),
            peer_addr,
            &["a@example.net"],
            1,
            // No spool file: the row refers to a body that is not there.
            false,
        )
        .await;

        for _ in 0..40 {
            if states(&queue).await.iter().any(|s| s == "deferred") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let conn = queue.conn.lock().await;
        let (state, code, response): (String, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT state, last_code, last_response FROM delivery",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        drop(conn);

        assert_eq!(state, "deferred", "a missing body ended the delivery");
        assert_eq!(code, None, "a local failure was given an SMTP code");
        assert!(
            response.unwrap_or_default().contains("local integrity"),
            "the failure was not recorded as a local one"
        );
        assert!(
            !transcript.saw("MAIL FROM"),
            "a message with no body was transmitted anyway"
        );

        deliverer.stop();
    }

    #[tokio::test]
    async fn a_delivered_message_becomes_terminal_and_is_not_retried() {
        let tmp = TempDir::new("delivered");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;

        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;

        for _ in 0..60 {
            if states(&queue).await.iter().any(|s| s == "delivered") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(states(&queue).await, vec!["delivered"]);
        assert!(
            transcript.saw("MAIL FROM:<SRS0="),
            "the stored return path was not used: {:?}",
            transcript.lines()
        );
        assert!(
            transcript.saw("RCPT TO:<a@example.net>"),
            "the claim's destination was not used: {:?}",
            transcript.lines()
        );

        deliverer.stop();
    }

    /// A peer that answers the end of DATA with `code`.
    fn peer_answering(code: &str) -> pigeon_testkit::Peer {
        pigeon_testkit::Peer::new()
            .send("220 test.invalid ESMTP")
            .read_line()
            .send("250 test.invalid")
            .read_line() // MAIL FROM
            .send("250 Ok")
            .read_line() // RCPT TO
            .send("250 Ok")
            .read_line() // DATA
            .send("354 Go ahead")
            .read_body()
            .send(code)
            .read_line() // QUIT
            .send("221 Bye")
            .close()
    }

    async fn wait_for_state(queue: &Queue, wanted: &str) -> Vec<String> {
        for _ in 0..80 {
            let s = states(queue).await;
            if s.iter().any(|state| state == wanted) {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        states(queue).await
    }

    #[tokio::test]
    async fn a_temporary_refusal_is_retried_not_bounced() {
        // 4xx means "not now". Recording it as a failure would bounce mail the
        // destination never refused, and Pigeon keeps no copy after that.
        let tmp = TempDir::new("temp-refusal");
        let (peer_addr, _t) = peer_answering("451 4.3.0 try later").spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;

        assert_eq!(wait_for_state(&queue, "deferred").await, vec!["deferred"]);

        let conn = queue.conn.lock().await;
        let (notification, next): (String, Option<i64>) = conn
            .query_row(
                "SELECT notification, next_attempt_at FROM delivery",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        drop(conn);
        assert_eq!(notification, "none", "a deferral owes the sender a report");
        assert!(next.is_some(), "a deferred delivery has no next attempt");

        deliverer.stop();
    }

    #[tokio::test]
    async fn a_permanent_refusal_fails_and_owes_a_report() {
        // 5xx is the destination's final answer, and the sender has to be told.
        let tmp = TempDir::new("perm-refusal");
        let (peer_addr, _t) = peer_answering("550 5.1.1 No such user").spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;

        assert_eq!(wait_for_state(&queue, "failed").await, vec!["failed"]);

        let conn = queue.conn.lock().await;
        let (notification, response): (String, String) = conn
            .query_row(
                "SELECT notification, last_response FROM delivery",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        drop(conn);
        assert_eq!(notification, "owed", "a permanent failure owes no report");
        assert!(
            response.contains("550") || response.contains("No such user"),
            "the remote's answer was not recorded: {response}"
        );

        deliverer.stop();
    }

    #[tokio::test]
    async fn admission_writes_the_graph_the_dsn_will_need() {
        // The envelope moved from a sidecar into rows, so what used to be a
        // string in a file is now a graph: the return path, the address the
        // sender actually used, every recipient they named, and which of them
        // reaches each destination.
        let tmp = TempDir::new("admit");
        let (s, db) = queued_sink(tmp.path());
        let id = s.next_id();
        let spool_id = pigeon_spool::SpoolId::new(&id).unwrap();

        let envelope = Envelope {
            // Already rewritten by the time admission runs.
            sender: "SRS0=tag=AAA=remote.test=alice@pigeon.test".into(),
            recipients: vec!["hello@example.com".into(), "sales@example.com".into()],
        };

        s.admit(
            s.queue.as_ref().unwrap(),
            &spool_id,
            &envelope,
            "alice@remote.test",
            1234,
            "mailbox@provider.example",
        )
        .await
        .expect("admit");

        let conn = pigeon_db::open(&db).unwrap();
        let (return_path, original, size): (String, String, i64) = conn
            .query_row(
                "SELECT return_path, original_sender, size_bytes FROM message WHERE spool_id = ?1",
                [spool_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(return_path, "SRS0=tag=AAA=remote.test=alice@pigeon.test");
        assert_eq!(original, "alice@remote.test");
        assert_eq!(size, 1234);

        // Both recipients, and both mapped to the destination — the mapping is
        // what lets a report name the address the sender wrote rather than the
        // mailbox they have never heard of.
        let mut stmt = conn
            .prepare(
                "SELECT o.address FROM original_recipient o
                   JOIN recipient_delivery rd ON rd.original_recipient_id = o.id
                   JOIN delivery d ON d.id = rd.delivery_id
                  WHERE d.destination = ?1 ORDER BY o.address",
            )
            .unwrap();
        let mapped: Vec<String> = stmt
            .query_map(["mailbox@provider.example"], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(mapped, vec!["hello@example.com", "sales@example.com"]);
    }

    #[tokio::test]
    async fn a_bounce_is_admitted_with_an_empty_return_path() {
        // The null sender is a fact the queue has to carry: §9 owes no report
        // for a message that is itself a bounce, and that rule reads
        // `return_path`.
        let tmp = TempDir::new("bounce");
        let (s, db) = queued_sink(tmp.path());
        let id = s.next_id();
        let spool_id = pigeon_spool::SpoolId::new(&id).unwrap();

        let envelope = Envelope {
            sender: String::new(),
            recipients: vec!["a@example.net".into()],
        };

        s.admit(
            s.queue.as_ref().unwrap(),
            &spool_id,
            &envelope,
            "",
            10,
            "mailbox@provider.example",
        )
        .await
        .expect("admit");

        let conn = pigeon_db::open(&db).unwrap();
        let return_path: String = conn
            .query_row(
                "SELECT return_path FROM message WHERE spool_id = ?1",
                [spool_id.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(return_path.is_empty(), "a bounce gained a return path");
    }

    #[tokio::test]
    async fn an_admission_that_cannot_commit_says_whether_the_file_may_go() {
        // The rule the acceptance path turns on. A collision is established
        // non-commit, so the spool file is an orphan and may be removed.
        let tmp = TempDir::new("collide");
        let (s, _db) = queued_sink(tmp.path());
        let id = s.next_id();
        let spool_id = pigeon_spool::SpoolId::new(&id).unwrap();
        let envelope = Envelope {
            sender: "SRS0=x@pigeon.test".into(),
            recipients: vec!["a@example.net".into()],
        };
        let queue = s.queue.as_ref().unwrap();

        s.admit(
            queue,
            &spool_id,
            &envelope,
            "a@remote.test",
            10,
            "m@provider.example",
        )
        .await
        .expect("first admission");

        let (why, removable) = s
            .admit(
                queue,
                &spool_id,
                &envelope,
                "a@remote.test",
                10,
                "m@provider.example",
            )
            .await
            .expect_err("a second admission of the same spool id should fail");
        assert!(
            removable,
            "a collision was not established as non-commit: {why}"
        );
    }

    #[test]
    fn identifiers_do_not_repeat_within_a_run() {
        let tmp = TempDir::new("ids");
        let s = sink(tmp.path(), &[]);
        let ids: HashSet<String> = (0..1000).map(|_| s.next_id()).collect();
        assert_eq!(ids.len(), 1000, "identifier collision within one run");
    }

    #[test]
    fn the_accept_list_folds_the_domain_and_not_the_local_part() {
        let tmp = TempDir::new("accept");
        let s = sink(tmp.path(), &["Bob@Example.com"]);

        assert!(
            s.accepts_recipient_inner("Bob@example.com"),
            "domain not folded"
        );
        assert!(
            s.accepts_recipient_inner("Bob@EXAMPLE.COM"),
            "domain not folded"
        );
        // A different mailbox, and one the operator never listed. RFC 5321
        // §2.4 reserves the local part to the destination host.
        assert!(
            !s.accepts_recipient_inner("bob@example.com"),
            "folded the local part"
        );
    }

    #[test]
    fn an_empty_accept_list_accepts_anything() {
        let tmp = TempDir::new("accept-any");
        let s = sink(tmp.path(), &[]);
        assert!(s.accepts_recipient_inner("whoever@example.com"));
    }

    #[test]
    fn malformed_recipients_are_not_accepted_by_a_configured_list() {
        let tmp = TempDir::new("accept-bad");
        let s = sink(tmp.path(), &["a@example.com"]);
        assert!(!s.accepts_recipient_inner("not-an-address"));
        assert!(!s.accepts_recipient_inner("x@."));
    }

    #[tokio::test]
    async fn preparing_the_spool_creates_it_and_leaves_no_probe_behind() {
        let tmp = TempDir::new("prepare");
        let spool = tmp.path().join("nested").join("spool");

        prepare_spool(&spool).await.expect("prepare");
        assert!(spool.is_dir());
        assert_eq!(
            survey_spool(&spool).await.unwrap().messages,
            0,
            "the probe was counted as stranded mail"
        );
        assert!(
            !spool.join(".pigeon-writable-probe").exists(),
            "probe left behind"
        );

        // Running twice must be fine: the daemon restarts.
        prepare_spool(&spool).await.expect("prepare again");
    }

    // ------------------------------------------------- the whole path, once
    //
    // Every other test here stops at a function boundary, and the integration
    // tests in `pigeon-smtp` stop at a synthetic sink. Nothing walked
    // listener → session → spool → resolver → delivery client → receiving
    // server in one run, which is the path a real message actually takes.

    /// Drive the real server with the real sink against a scripted peer.
    ///
    /// The resolver is fake and the port is injected, so no DNS is consulted
    /// and nothing leaves the loopback interface — but every other component
    /// is the production one.
    async fn spawn_daemon(
        dir: &Path,
        accept: &[&str],
        peer_addr: SocketAddr,
    ) -> (SocketAddr, Arc<PathBuf>) {
        spawn_daemon_with_budget(dir, accept, peer_addr, TOTAL_FORWARD_BUDGET).await
    }

    async fn spawn_daemon_with_budget(
        dir: &Path,
        accept: &[&str],
        peer_addr: SocketAddr,
        budget: Duration,
    ) -> (SocketAddr, Arc<PathBuf>) {
        use pigeon_dns::{FakeResolver, MxRecord};

        let spool = Arc::new(dir.to_path_buf());
        let resolver = FakeResolver::new().with(
            "example.net",
            vec![MxRecord::new(10, peer_addr.ip().to_string())],
        );

        let sink = SpoolSink {
            queue: None,
            auth: None,
            spool: pigeon_spool::Spool::new(spool.as_path()),
            dir: Arc::clone(&spool),
            accept: Arc::new(accept.iter().map(|s| s.to_string()).collect()),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x0bad_cafe,
            forwarding: Some(Forwarding {
                resolver: Arc::new(resolver),
                ehlo_name: "pigeon.test".into(),
                destination: "dest@example.net".into(),
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: peer_addr.port(),
                budget,
            }),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = ServerConfig {
            hostname: "pigeon.test".into(),
            ..ServerConfig::default()
        };
        tokio::spawn(async move {
            let _ = pigeon_smtp::serve(listener, config, sink).await;
        });
        (addr, spool)
    }

    /// Send one message through a real SMTP conversation.
    async fn submit(addr: SocketAddr, from: &str, to: &str, body: &str) -> Vec<(u16, String)> {
        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        let mut replies = Vec::new();
        replies.push(c.read_reply().await.expect("banner"));

        for line in [
            "EHLO sender.test\r\n".to_string(),
            format!("MAIL FROM:<{from}>\r\n"),
            format!("RCPT TO:<{to}>\r\n"),
            "DATA\r\n".to_string(),
        ] {
            c.send(line.as_bytes()).await.expect("send");
            replies.push(c.read_reply().await.expect("reply"));
        }

        c.send(body.as_bytes()).await.expect("body");
        c.send(b".\r\n").await.expect("terminator");
        replies.push(c.read_reply().await.expect("data ack"));

        c.send(b"QUIT\r\n").await.expect("quit");
        replies.push(c.read_reply().await.expect("bye"));
        replies
    }

    /// Poll until the spool is empty or the wait is unreasonable.
    ///
    /// Forwarding happens on a detached task after the `250`, so there is no
    /// handle to await. Polling a real condition beats sleeping a fixed time,
    /// which is either flaky or slow and usually both.
    async fn wait_until_spool_is_empty(dir: &Path) -> bool {
        for _ in 0..200 {
            if survey_spool(dir).await.map(|s| s.messages).unwrap_or(1) == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    // ------------------------------------------------------- authenticated e2e

    static RING_SEQ: AtomicU64 = AtomicU64::new(0);

    /// One RSA key for every authenticated test: generation dominates the run
    /// otherwise.
    fn e2e_key() -> &'static str {
        static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            pigeon_auth::dkim::KeyPair::generate(2048)
                .unwrap()
                .private_pem()
                .to_string()
        })
    }

    /// Build the authentication machinery a wired daemon would build at
    /// startup, without a database: the snapshot is constructed directly, which
    /// is the same type `load` produces.
    ///
    /// `with_key` false is how the "signing fails at runtime" case is reached —
    /// startup validation makes it unreachable in production, so a test has to
    /// assemble it deliberately.
    fn e2e_auth(domain: &str, policy: pigeon_types::ForwardPolicy, with_key: bool) -> Auth {
        use pigeon_route::snapshot::{DkimIdentity, DomainInput, Forwarding as RouteForwarding};

        let snapshot = pigeon_route::Snapshot::build(vec![DomainInput {
            name: domain.into(),
            gate: pigeon_types::DomainGate {
                status: pigeon_types::DomainStatus::Active,
                inbound_enabled: true,
                outbound_enabled: false,
            },
            plus_addressing: true,
            forwarding: RouteForwarding {
                policy,
                dkim: Some(DkimIdentity {
                    selector: "sel".into(),
                    private_key_path: "unused-in-test".into(),
                    algorithm: "rsa2048".into(),
                }),
            },
            default_destination: Some(pigeon_route::snapshot::Destination {
                local: "me".into(),
                domain: "example.net".into(),
            }),
            aliases: vec![pigeon_route::snapshot::AliasInput {
                pattern: "hello".into(),
                reject: false,
                destinations: vec![],
            }],
            catchall: None,
        }])
        .expect("the fixture configuration should build")
        .snapshot;

        // The fixture ring, written to a real file so the reconciliation path
        // has something to hash and a rotation test has something to replace.
        let ring_path = std::env::temp_dir().join(format!(
            "pigeon-ring-{}-{}.key",
            std::process::id(),
            RING_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &ring_path,
            "1 2026-01-01T00:00:00Z - AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n",
        )
        .expect("write the fixture ring");

        let derive_path = ring_path.clone();
        let derive: Deriver = Box::new(move |snapshot| {
            let mut keys = HashMap::new();
            if with_key {
                for domain in snapshot.domains() {
                    keys.insert(
                        domain.to_string(),
                        pigeon_auth::pipeline::SigningKey::from_pkcs8_pem(e2e_key(), domain, "sel")
                            .unwrap(),
                    );
                }
            }
            let ring = pigeon_auth::KeyRing::load(&derive_path)
                .map_err(|e| format!("fixture ring: {e}"))?;
            Ok(Derived {
                keys,
                srs: Arc::new(pigeon_auth::Srs::new(ring, "pigeon.test")),
            })
        });

        let derived = derive(&snapshot).expect("the fixture should derive");

        Auth {
            pipeline: Arc::new(pigeon_auth::pipeline::Pipeline::new(
                pigeon_auth::verify::Verifier::from_system().unwrap(),
                "pigeon.test",
            )),
            runtime: Arc::new(RuntimeState {
                current: std::sync::RwLock::new(Arc::new(Runtime {
                    snapshot: Arc::new(snapshot),
                    keys: derived.keys,
                    srs: derived.srs,
                })),
                ring_fingerprint: std::sync::Mutex::new(ring_fingerprint(&ring_path)),
                ring_path,
                derive,
            }),
        }
    }

    /// Publish a new table for the same domain, with a different policy.
    fn republish(runtime: &Arc<RuntimeState>, policy: pigeon_types::ForwardPolicy) {
        use pigeon_route::Publish;
        use pigeon_route::snapshot::{DkimIdentity, DomainInput, Forwarding as RouteForwarding};

        let inputs = vec![DomainInput {
            name: "example.com".into(),
            gate: pigeon_types::DomainGate {
                status: pigeon_types::DomainStatus::Active,
                inbound_enabled: true,
                outbound_enabled: false,
            },
            plus_addressing: true,
            forwarding: RouteForwarding {
                policy,
                dkim: Some(DkimIdentity {
                    selector: "sel".into(),
                    private_key_path: "unused-in-test".into(),
                    algorithm: "rsa2048".into(),
                }),
            },
            default_destination: Some(pigeon_route::snapshot::Destination {
                local: "me".into(),
                domain: "example.net".into(),
            }),
            aliases: vec![pigeon_route::snapshot::AliasInput {
                pattern: "hello".into(),
                reject: false,
                destinations: vec![],
            }],
            catchall: None,
        }];

        runtime
            .publish(pigeon_route::Snapshot::build(inputs).unwrap().snapshot)
            .expect("the fixture should publish");
    }

    /// Add a second managed domain to a fixture runtime.
    ///
    /// Built by republishing through the same path production uses, so the keys
    /// for both domains come from the same derivation.
    fn second_domain(auth: Auth, domain: &str) -> Auth {
        use pigeon_route::Publish;
        use pigeon_route::snapshot::{DkimIdentity, DomainInput, Forwarding as RouteForwarding};

        let existing: Vec<String> = auth
            .runtime
            .pin()
            .snapshot
            .domains()
            .map(str::to_string)
            .collect();

        let inputs = existing
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(domain))
            .map(|name| DomainInput {
                name: name.into(),
                gate: pigeon_types::DomainGate {
                    status: pigeon_types::DomainStatus::Active,
                    inbound_enabled: true,
                    outbound_enabled: false,
                },
                plus_addressing: true,
                forwarding: RouteForwarding {
                    policy: pigeon_types::ForwardPolicy::Preserve,
                    dkim: Some(DkimIdentity {
                        selector: "sel".into(),
                        private_key_path: "unused-in-test".into(),
                        algorithm: "rsa2048".into(),
                    }),
                },
                default_destination: Some(pigeon_route::snapshot::Destination {
                    local: "me".into(),
                    domain: "example.net".into(),
                }),
                aliases: vec![pigeon_route::snapshot::AliasInput {
                    pattern: "hello".into(),
                    reject: false,
                    destinations: vec![],
                }],
                catchall: None,
            })
            .collect();

        auth.runtime
            .publish(pigeon_route::Snapshot::build(inputs).unwrap().snapshot)
            .expect("the fixture should publish");
        auth
    }

    async fn spawn_two_domain_daemon(
        dir: &Path,
        peer_addr: SocketAddr,
        auth: Auth,
    ) -> (SocketAddr, Arc<PathBuf>) {
        spawn_with_accept(
            dir,
            peer_addr,
            auth,
            &["hello@example.com", "hello@other.example"],
        )
        .await
    }

    async fn spawn_authenticated(
        dir: &Path,
        peer_addr: SocketAddr,
        auth: Auth,
    ) -> (SocketAddr, Arc<PathBuf>) {
        spawn_with_accept(dir, peer_addr, auth, &["hello@example.com"]).await
    }

    async fn spawn_with_accept(
        dir: &Path,
        peer_addr: SocketAddr,
        auth: Auth,
        accept: &[&str],
    ) -> (SocketAddr, Arc<PathBuf>) {
        use pigeon_dns::{FakeResolver, MxRecord};

        let spool = Arc::new(dir.to_path_buf());
        let resolver = FakeResolver::new().with(
            "example.net",
            vec![MxRecord::new(10, peer_addr.ip().to_string())],
        );

        let sink = SpoolSink {
            queue: None,
            auth: Some(auth),
            spool: pigeon_spool::Spool::new(spool.as_path()),
            dir: Arc::clone(&spool),
            accept: Arc::new(accept.iter().map(|a| a.to_string()).collect()),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x0bad_cafe,
            forwarding: Some(Forwarding {
                resolver: Arc::new(resolver),
                ehlo_name: "pigeon.test".into(),
                destination: "dest@example.net".into(),
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: peer_addr.port(),
                budget: TOTAL_FORWARD_BUDGET,
            }),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = ServerConfig {
            hostname: "pigeon.test".into(),
            ..ServerConfig::default()
        };
        tokio::spawn(async move {
            let _ = pigeon_smtp::serve(listener, config, sink).await;
        });
        (addr, spool)
    }

    /// The single line the peer recorded that carries the message body.
    fn delivered(transcript: &pigeon_testkit::Transcript) -> String {
        transcript
            .lines()
            .into_iter()
            .find(|l| l.contains("body line"))
            .expect("the message never reached the peer")
    }

    #[tokio::test]
    async fn preserve_forwards_signed_by_nobody_and_sealed_by_pigeon() {
        // The whole path: listener, pipeline, spool, scripted peer.
        let tmp = TempDir::new("e2e-preserve");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true),
        )
        .await;

        // Captured before the spool is cleaned, so the two can be compared.
        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;
        assert_eq!(replies[5].0, 250, "not accepted: {:?}", replies[5]);
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        let sent = delivered(&transcript);

        // The envelope sender is the SRS return path, not the original.
        assert!(
            transcript.saw("MAIL FROM:<SRS0="),
            "the envelope sender was not rewritten: {:?}",
            transcript.lines()
        );
        assert!(
            !transcript.saw("MAIL FROM:<sender@remote.test>"),
            "the original sender went out unrewritten"
        );

        // Everything the pipeline is supposed to have added.
        assert!(sent.contains("Received: from"), "no trace header:\n{sent}");
        assert!(
            sent.contains("Authentication-Results: pigeon.test"),
            "no authentication results:\n{sent}"
        );
        assert!(sent.contains("ARC-Seal:"), "not sealed:\n{sent}");
        assert!(sent.contains("ARC-Message-Signature:"), "no AMS:\n{sent}");
        assert!(
            sent.contains("ARC-Authentication-Results:"),
            "no AAR:\n{sent}"
        );

        // Preserve does not add a DKIM signature of Pigeon's own: DMARC is
        // supposed to pass on the *author's* signature, and adding one here
        // would be an unaligned pass that changes nothing.
        assert!(
            !sent.contains("DKIM-Signature:"),
            "Preserve signed the message:\n{sent}"
        );

        // And the original message is still under it all.
        assert!(sent.contains("From: <sender@remote.test>"), "{sent}");
        assert!(sent.contains("Subject: hi"), "{sent}");
    }

    /// A peer that takes the whole transaction and then refuses at the end, so
    /// the spooled copy survives for comparison.
    fn refusing_peer() -> pigeon_testkit::Peer {
        pigeon_testkit::Peer::new()
            .send("220 test.invalid ESMTP")
            .read_line() // EHLO
            .send("250 test.invalid")
            .read_line() // MAIL FROM
            .send("250 Ok")
            .read_line() // RCPT TO
            .send("250 Ok")
            .read_line() // DATA
            .send("354 Go ahead")
            .read_body()
            .send("451 4.3.0 try later")
            .read_line() // QUIT
            .send("221 Bye")
            .close()
    }

    /// Verify the ARC set and any DKIM signature on a message the daemon sent.
    ///
    /// Header *presence* is not the property: a wiring bug that seals the wrong
    /// buffer produces headers that look right and do not validate. This checks
    /// them against the fixture key, offline, through the same library a
    /// receiver would use.
    async fn validate(message: &str) -> (mail_auth::DkimResult, Vec<mail_auth::DkimResult>) {
        use mail_auth::{AuthenticatedMessage, MessageAuthenticator, Parameters};
        use pigeon_testkit::dns::DnsStub;

        let stub = DnsStub::with_dkim_record(
            &pigeon_auth::dkim::public_from_private_pem(e2e_key())
                .map(|public| pigeon_auth::dkim::txt_record(&public))
                .expect("the fixture key has a public half"),
        );

        let authenticator = MessageAuthenticator::new_system_conf().expect("resolver");
        let parsed =
            AuthenticatedMessage::parse(message.as_bytes()).expect("the sent message parses");

        let arc = authenticator
            .verify_arc(Parameters {
                params: &parsed,
                cache_txt: Some(&stub),
                cache_mx: None::<&DnsStub>,
                cache_ptr: None::<&DnsStub>,
                cache_ipv4: None::<&DnsStub>,
                cache_ipv6: None::<&DnsStub>,
            })
            .await;

        let dkim = authenticator
            .verify_dkim(Parameters {
                params: &parsed,
                cache_txt: Some(&stub),
                cache_mx: None::<&DnsStub>,
                cache_ptr: None::<&DnsStub>,
                cache_ipv4: None::<&DnsStub>,
                cache_ipv6: None::<&DnsStub>,
            })
            .await;

        (
            arc.result().clone(),
            dkim.iter().map(|d| d.result().clone()).collect(),
        )
    }

    #[tokio::test]
    async fn the_arc_set_the_daemon_sent_actually_validates() {
        // The end-to-end claim, checked rather than assumed. Every step between
        // the pipeline and the socket — spooling, re-reading, dot-stuffing —
        // can corrupt what was signed, and nothing about a header's presence
        // would say so.
        let tmp = TempDir::new("e2e-arc-valid");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true),
        )
        .await;

        submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        // What the peer received, with the end-of-data marker removed.
        let sent = delivered(&transcript);
        let sent = sent.strip_suffix(".\r\n").unwrap_or(&sent).to_string();

        let (arc, _) = validate(&sent).await;
        assert_eq!(
            arc,
            mail_auth::DkimResult::Pass,
            "the ARC set the daemon transmitted does not validate: {arc:?}"
        );
    }

    #[tokio::test]
    async fn the_rewritten_from_the_daemon_sent_is_validly_signed() {
        // The same, for the signature that carries the DMARC pass under
        // rewrite_from. A signature over the wrong buffer is a header that
        // looks correct and fails at the receiver.
        let tmp = TempDir::new("e2e-dkim-valid");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            e2e_auth(
                "example.com",
                pigeon_types::ForwardPolicy::RewriteFrom,
                true,
            ),
        )
        .await;

        submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        let sent = delivered(&transcript);
        let sent = sent.strip_suffix(".\r\n").unwrap_or(&sent).to_string();

        let (arc, dkim) = validate(&sent).await;
        assert_eq!(
            arc,
            mail_auth::DkimResult::Pass,
            "the ARC set does not validate"
        );
        assert!(
            dkim.contains(&mail_auth::DkimResult::Pass),
            "the rewritten From: is not validly signed: {dkim:?}"
        );
    }

    #[tokio::test]
    async fn what_is_spooled_is_what_is_transmitted() {
        // A retry must send the same bytes, and the ARC set signs exactly one
        // of the two forms — so if the spooled copy and the transmitted copy
        // can differ, one of them is unverifiable and nothing says which.
        //
        // The peer refuses at the end of DATA, which leaves the spool file in
        // place to compare against what it recorded.
        let tmp = TempDir::new("e2e-spooled");
        let (peer_addr, transcript) = refusing_peer().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true),
        )
        .await;

        submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;

        // Wait for the peer to have seen the body.
        let sent = {
            let mut found = None;
            for _ in 0..200 {
                if let Some(line) = transcript
                    .lines()
                    .into_iter()
                    .find(|l| l.contains("body line"))
                {
                    found = Some(line);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            found.expect("the message never reached the peer")
        };

        let spooled = {
            let mut entries = tokio::fs::read_dir(spool.as_path()).await.expect("spool");
            let mut eml = None;
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.path().extension().is_some_and(|e| e == "eml") {
                    eml = Some(tokio::fs::read(entry.path()).await.expect("read spooled"));
                }
            }
            String::from_utf8(eml.expect("the message was not spooled")).expect("utf8")
        };

        // The wire form is the spooled form, dot-stuffed, plus the end-of-data
        // marker — which the peer's scan records along with the body, since it
        // reads *through* the delimiter. Nothing in this message begins a line
        // with a dot, so stuffing is the identity here and the comparison is
        // byte-for-byte.
        assert_eq!(
            sent,
            format!("{spooled}.\r\n"),
            "the transmitted bytes differ from the spooled bytes"
        );
        assert!(
            spooled.ends_with("\r\n"),
            "the spooled form is unterminated"
        );
    }

    #[tokio::test]
    async fn a_reload_installs_the_table_and_its_keys_together() {
        // The property the combined runtime exists for. Publishing a snapshot
        // whose keys cannot be derived must install *neither*: a table without
        // its keys leaves a rewrite_from domain unable to sign, and keys
        // without their table sign under a policy no longer in force.
        use pigeon_route::Publish;

        let good = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        let before = good.runtime.pin();
        assert_eq!(before.keys.len(), 1);

        // A state whose key derivation always fails, standing in for a key
        // file that has been removed between reloads.
        let broken = Arc::new(RuntimeState {
            current: std::sync::RwLock::new(Arc::clone(&before)),
            derive: Box::new(|_| Err("the key file is gone".into())),
            ring_fingerprint: std::sync::Mutex::new(None),
            ring_path: PathBuf::from("/nonexistent/ring.key"),
        });

        let published = broken.publish(pigeon_route::Snapshot::default());
        assert!(published.is_err(), "a keyless snapshot was installed");

        let after = broken.pin();
        assert!(
            Arc::ptr_eq(&before, &after),
            "the previous runtime was replaced by one that could not be completed"
        );
        assert_eq!(after.keys.len(), 1, "the keys were dropped");
    }

    #[tokio::test]
    async fn sealing_that_fails_degrades_rather_than_losing_the_message() {
        // §7's split, end to end. A missing ARC set drops a recovery path —
        // the pre-ARC status quo, which most forwarded mail lives with — so
        // the message still goes. Refusing here would turn a local key problem
        // into refused mail, which is the trade the design refuses to make.
        //
        // The opposite rule, for an unsignable rewrite, is asserted separately:
        // that one is never written and never sent.
        let tmp = TempDir::new("e2e-unsealed");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            // Preserve with no key: nothing can seal, and nothing needs to sign.
            e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, false),
        )
        .await;

        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;
        assert_eq!(replies[5].0, 250, "an unsealable message was refused");
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        let sent = delivered(&transcript);
        assert!(!sent.contains("ARC-Seal:"), "sealed after all:\n{sent}");
        // Everything that does not need a key is still there, which is what
        // makes this a degradation rather than a bypass.
        assert!(sent.contains("Received: from"), "no trace header:\n{sent}");
        assert!(
            sent.contains("Authentication-Results: pigeon.test"),
            "no authentication results:\n{sent}"
        );
        assert!(sent.contains("From: <sender@remote.test>"), "{sent}");
    }

    #[tokio::test]
    async fn a_rotated_ring_reaches_a_running_daemon() {
        // `pigeon srs rotate` writes a new ring while the daemon runs. A daemon
        // holding the one it started with would keep issuing return paths under
        // the displaced key — which verify today and stop verifying the moment
        // an operator deletes it, so the failure arrives weeks later as bounces
        // that cannot be routed home.
        let auth = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        let runtime = Arc::clone(&auth.runtime);

        // Nothing to reconcile until the file changes.
        assert!(
            runtime.reconcile_ring().is_none(),
            "an unchanged ring was republished"
        );

        let before = runtime
            .pin()
            .srs
            .forward("alice", "remote.test", pigeon_auth::Day::now())
            .expect("the fixture ring signs");

        // A rotation: a new key first, the old one kept for verification.
        std::fs::write(
            &runtime.ring_path,
            "2 2026-06-01T00:00:00Z - //79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA=\n\
             1 2026-01-01T00:00:00Z 2026-06-01T00:00:00Z AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n",
        )
        .expect("write the rotated ring");

        assert!(
            matches!(runtime.reconcile_ring(), Some(Ok(()))),
            "the rotated ring was not picked up"
        );

        let after = runtime
            .pin()
            .srs
            .forward("alice", "remote.test", pigeon_auth::Day::now())
            .expect("the rotated ring signs");
        assert_ne!(
            before, after,
            "the daemon is still signing with the displaced key"
        );

        // And the address issued under the old key still reverses, which is the
        // whole point of keeping it in the ring.
        let local = before.rsplit_once('@').unwrap().0;
        let reversed = runtime
            .pin()
            .srs
            .reverse(local, pigeon_auth::Day::now())
            .expect("an address issued before the rotation stopped reversing");
        assert_eq!(reversed.address, "alice@remote.test");
        assert_eq!(reversed.key_id, 1, "the wrong key verified it");
    }

    #[tokio::test]
    async fn a_ring_that_cannot_be_read_keeps_the_previous_one() {
        // The same rule the table follows: a state that will not load does not
        // replace one that works. Signing return paths is the last thing that
        // should stop because somebody mistyped a file.
        let auth = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        let runtime = Arc::clone(&auth.runtime);
        let before = runtime.pin();

        std::fs::write(&runtime.ring_path, "not a key ring at all\n").expect("write");
        match runtime.reconcile_ring() {
            Some(Err(e)) => assert!(e.contains("ring"), "{e}"),
            other => panic!("an unusable ring was accepted: {other:?}"),
        }

        assert!(
            Arc::ptr_eq(&before, &runtime.pin()),
            "the previous ring was replaced by one that could not be loaded"
        );
    }

    #[tokio::test]
    async fn the_return_path_on_the_wire_reverses_to_the_original_sender() {
        // What SRS is *for*: a bounce sent to the address the receiver was
        // given has to find its way back. Asserted on the address the daemon
        // actually transmitted rather than on one the test computed, so a
        // wiring bug between the rewrite and the socket is caught.
        //
        // Delivering that bounce is Milestone 3's job — it needs the queue to
        // be safe. Reversing it is Milestone 2's, and it is what makes the
        // Milestone 3 work possible.
        let tmp = TempDir::new("e2e-srs-reverse");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let auth = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        let srs = Arc::clone(&auth.runtime.pin().srs);
        let (addr, spool) = spawn_authenticated(tmp.path(), peer_addr, auth).await;

        submit(
            addr,
            "Original.Sender@remote.test",
            "hello@example.com",
            "From: <Original.Sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        let mail_from = transcript
            .lines()
            .into_iter()
            .find(|l| l.to_ascii_uppercase().starts_with("MAIL FROM:"))
            .expect("no MAIL FROM reached the peer");
        let address = mail_from
            .trim_start_matches(|c| c != '<')
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string();
        let local = address.rsplit_once('@').expect("a full address").0;

        let reversed = srs
            .reverse(local, pigeon_auth::Day::now())
            .expect("the address this host issued does not reverse");

        // Case preserved on the local part: `Original.Sender` and
        // `original.sender` are different mailboxes, and only the original
        // domain gets to say whether they are the same.
        assert_eq!(reversed.address, "Original.Sender@remote.test");
    }

    #[tokio::test]
    async fn a_reload_between_rcpt_and_data_does_not_change_the_policy() {
        // The pin, made falsifiable. The recipient is accepted under Preserve;
        // the configuration then changes to rewrite_from before the body
        // arrives. The message must be forwarded under the policy that
        // accepted it — reading the policy at DATA would rewrite and sign a
        // message that was admitted on different terms, and the sender would
        // have no way to know which one applied.
        let tmp = TempDir::new("e2e-pinned");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let auth = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        let runtime = Arc::clone(&auth.runtime);
        let (addr, spool) = spawn_authenticated(tmp.path(), peer_addr, auth).await;

        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        c.read_reply().await.expect("banner");
        c.send(b"EHLO client.test\r\n").await.expect("ehlo");
        c.read_reply().await.expect("ehlo reply");
        c.send(b"MAIL FROM:<sender@remote.test>\r\n")
            .await
            .expect("mail");
        c.read_reply().await.expect("mail reply");
        c.send(b"RCPT TO:<hello@example.com>\r\n")
            .await
            .expect("rcpt");
        assert_eq!(c.read_reply().await.expect("rcpt reply").0, 250);

        // The reload lands here: after the recipient was accepted, before the
        // body exists.
        republish(&runtime, pigeon_types::ForwardPolicy::RewriteFrom);

        c.send(b"DATA\r\n").await.expect("data");
        assert_eq!(c.read_reply().await.expect("data reply").0, 354);
        c.send(b"From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n.\r\n")
            .await
            .expect("body");
        assert_eq!(c.read_reply().await.expect("accepted").0, 250);
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        let sent = delivered(&transcript);
        assert!(
            sent.contains("From: <sender@remote.test>"),
            "the message was rewritten under a policy that did not accept it:\n{sent}"
        );
        assert!(
            !sent.contains("DKIM-Signature:"),
            "the message was signed under a policy that did not accept it:\n{sent}"
        );

        // And the new policy is in force for the *next* transaction, so the
        // test cannot pass by the reload having done nothing.
        assert_eq!(
            runtime
                .pin()
                .snapshot
                .forwarding("example.com")
                .unwrap()
                .policy,
            pigeon_types::ForwardPolicy::RewriteFrom
        );
    }

    #[tokio::test]
    async fn a_second_managed_domain_is_deferred_rather_than_refused() {
        // Recipient order would otherwise choose the forwarding policy and the
        // signing identity, which is a decision belonging to the sender.
        //
        // Deferred, not rejected: the address is deliverable on its own, so a
        // permanent answer would tell the sender to give up on a working
        // mailbox.
        let tmp = TempDir::new("e2e-two-domains");
        let (peer_addr, _transcript) = pigeon_testkit::Peer::accepting().spawn().await;

        let mut auth = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        // A second managed domain in the same table.
        auth = second_domain(auth, "other.example");

        let (addr, _spool) = spawn_two_domain_daemon(tmp.path(), peer_addr, auth).await;

        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        c.read_reply().await.expect("banner");
        c.send(b"EHLO client.test\r\n").await.expect("ehlo");
        c.read_reply().await.expect("ehlo reply");
        c.send(b"MAIL FROM:<sender@remote.test>\r\n")
            .await
            .expect("mail");
        assert_eq!(c.read_reply().await.expect("mail reply").0, 250);

        c.send(b"RCPT TO:<hello@example.com>\r\n")
            .await
            .expect("rcpt 1");
        assert_eq!(
            c.read_reply().await.expect("rcpt 1 reply").0,
            250,
            "the first recipient was not accepted"
        );

        c.send(b"RCPT TO:<hello@other.example>\r\n")
            .await
            .expect("rcpt 2");
        let (code, text) = c.read_reply().await.expect("rcpt 2 reply");
        assert_eq!(
            code / 100,
            4,
            "a second managed domain was not deferred: {code} {text}"
        );

        // And the same address on its own is fine, which is what makes the
        // refusal about the combination rather than the recipient.
        c.send(b"RSET\r\n").await.expect("rset");
        c.read_reply().await.expect("rset reply");
        c.send(b"MAIL FROM:<sender@remote.test>\r\n")
            .await
            .expect("mail 2");
        c.read_reply().await.expect("mail 2 reply");
        c.send(b"RCPT TO:<hello@other.example>\r\n")
            .await
            .expect("rcpt 3");
        assert_eq!(
            c.read_reply().await.expect("rcpt 3 reply").0,
            250,
            "the deferred address is not deliverable on its own either"
        );
    }

    #[tokio::test]
    async fn rewrite_from_replaces_the_sender_and_signs_with_the_domains_key() {
        // The other policy, end to end. The rewritten address is in the domain
        // that signs it — that alignment is the entire point, since an
        // unaligned pass changes nothing for DMARC.
        let tmp = TempDir::new("e2e-rewrite");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            e2e_auth(
                "example.com",
                pigeon_types::ForwardPolicy::RewriteFrom,
                true,
            ),
        )
        .await;

        submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;
        assert!(wait_until_spool_is_empty(&spool).await, "never forwarded");

        let sent = delivered(&transcript);

        // Exactly one From:, and it is Pigeon's.
        assert_eq!(
            sent.matches("\r\nFrom:").count() + usize::from(sent.starts_with("From:")),
            1,
            "the relayed message has more than one From:\n{sent}"
        );
        assert!(
            sent.contains("From: <srs@example.com>"),
            "the From: was not rewritten:\n{sent}"
        );
        assert!(
            !sent.contains("From: <sender@remote.test>"),
            "the author's From: survived:\n{sent}"
        );

        // Signed by the domain the rewritten address is in, and sealed above
        // that signature.
        assert!(
            sent.contains("DKIM-Signature:") && sent.contains("d=example.com"),
            "the rewrite was not signed by the domain:\n{sent}"
        );
        let seal = sent.find("ARC-Seal:").expect("not sealed");
        let dkim = sent.find("DKIM-Signature:").expect("not signed");
        assert!(seal < dkim, "the seal does not cover Pigeon's signature");
    }

    #[tokio::test]
    async fn a_rewrite_that_cannot_be_signed_reaches_neither_the_spool_nor_the_peer() {
        // R-8's runtime half. Startup validation refuses a `rewrite_from`
        // domain with no usable key, so this state is unreachable in
        // production — which is exactly why a test has to assemble it: the
        // rule is that an unsigned rewrite is never written and never sent,
        // and a rule with no failing case is an assumption.
        let tmp = TempDir::new("e2e-unsigned");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_authenticated(
            tmp.path(),
            peer_addr,
            e2e_auth(
                "example.com",
                pigeon_types::ForwardPolicy::RewriteFrom,
                false,
            ),
        )
        .await;

        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n",
        )
        .await;

        // Refused at end-of-data, transiently: the key is a local problem and
        // the sender may usefully retry once an operator has fixed it.
        assert_eq!(
            replies[5].0 / 100,
            4,
            "an unsignable rewrite was not refused: {:?}",
            replies[5]
        );

        // Nothing was written.
        let mut entries = tokio::fs::read_dir(spool.as_path()).await.expect("spool");
        let mut spooled = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            spooled.push(entry.file_name());
        }
        assert!(
            spooled.is_empty(),
            "an unsignable rewrite reached the spool: {spooled:?}"
        );

        // And nothing was sent. Given a moment, in case the delivery task was
        // spawned before the refusal.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !transcript.lines().iter().any(|l| l.contains("body line")),
            "an unsignable rewrite reached the peer: {:?}",
            transcript.lines()
        );
    }

    #[tokio::test]
    async fn a_message_travels_from_the_listener_to_a_receiving_server() {
        let tmp = TempDir::new("e2e");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_daemon(tmp.path(), &["hello@example.com"], peer_addr).await;

        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "Subject: hi\r\n\r\nbody line\r\n",
        )
        .await;

        // Banner, EHLO, MAIL, RCPT, DATA, end-of-data, QUIT.
        assert_eq!(replies[0].0, 220, "banner: {:?}", replies[0]);
        assert_eq!(replies[5].0, 250, "message not accepted: {:?}", replies[5]);

        assert!(
            wait_until_spool_is_empty(&spool).await,
            "the message was never forwarded, or the spool was not cleaned"
        );

        // The receiving end saw a real SMTP transaction, not just a connection.
        assert!(transcript.saw("EHLO"), "{:?}", transcript.lines());
        assert!(
            transcript.saw("MAIL FROM:<sender@remote.test>"),
            "envelope sender not passed through: {:?}",
            transcript.lines()
        );
        assert!(
            transcript.saw("RCPT TO:<dest@example.net>"),
            "not readdressed to the configured destination: {:?}",
            transcript.lines()
        );

        // The body that arrived, with the trace header Pigeon prepended.
        let body = transcript
            .lines()
            .into_iter()
            .find(|l| l.contains("body line"))
            .expect("body never reached the peer");
        assert!(
            body.starts_with("Received: from sender.test"),
            "no trace header, or not first: {body:?}"
        );
        assert!(body.contains("Subject: hi"));
    }

    #[tokio::test]
    async fn a_refused_recipient_never_reaches_the_spool() {
        let tmp = TempDir::new("e2e-refused");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_daemon(tmp.path(), &["hello@example.com"], peer_addr).await;

        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        c.read_reply().await.expect("banner");
        c.send(b"EHLO sender.test\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"MAIL FROM:<sender@remote.test>\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"RCPT TO:<nobody@example.com>\r\n").await.unwrap();
        let (code, text) = c.read_reply().await.expect("rcpt reply");

        // Refused during the conversation, so the sender keeps responsibility.
        // Accepting and then discarding is never acceptable.
        assert_eq!(code, 550, "{text}");
        assert_eq!(survey_spool(&spool).await.unwrap().messages, 0);
        assert!(
            !transcript.saw("MAIL FROM"),
            "a refused recipient still triggered an outbound delivery"
        );
    }

    #[tokio::test]
    async fn a_message_the_receiver_rejects_stays_in_the_spool() {
        let tmp = TempDir::new("e2e-rejected");

        // A receiving server that refuses the recipient outright.
        let (peer_addr, _transcript) = pigeon_testkit::Peer::new()
            .send("220 strict.test ESMTP")
            .read_line() // EHLO
            .send("250 strict.test")
            .read_line() // MAIL FROM
            .send("250 Ok")
            .read_line() // RCPT TO
            .send("550 No such user")
            .close()
            .spawn()
            .await;

        let (addr, spool) = spawn_daemon(tmp.path(), &["hello@example.com"], peer_addr).await;
        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "Subject: hi\r\n\r\nbody\r\n",
        )
        .await;
        assert_eq!(replies[5].0, 250, "acceptance is independent of forwarding");

        // With no retry queue, the spool copy is the only thing between a
        // failed forward and a lost message. It must survive.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            survey_spool(&spool).await.unwrap().messages,
            1,
            "a message that could not be delivered was deleted anyway"
        );
    }

    #[tokio::test]
    async fn the_forward_budget_bounds_the_whole_delivery_not_one_connection() {
        // A peer that answers its door and then says nothing. `deliver` has
        // its own 30-minute budget, so without an outer deadline this task
        // would hold one of 32 delivery permits for 30 minutes per MX host.
        let (peer_addr, _t) = pigeon_testkit::Peer::new()
            .send("220 slow.test ESMTP")
            .stall(Duration::from_secs(60))
            .close()
            .spawn()
            .await;

        let f = Forwarding {
            resolver: Arc::new(pigeon_dns::FakeResolver::new().with(
                "example.net",
                vec![
                    // Three hosts. The bound is on the sum, so a per-connection
                    // budget would take three times as long to give up.
                    pigeon_dns::MxRecord::new(10, peer_addr.ip().to_string()),
                    pigeon_dns::MxRecord::new(20, peer_addr.ip().to_string()),
                    pigeon_dns::MxRecord::new(30, peer_addr.ip().to_string()),
                ],
            )),
            ehlo_name: "pigeon.test".into(),
            destination: "dest@example.net".into(),
            limit: Arc::new(Semaphore::new(1)),
            port: peer_addr.port(),
            budget: Duration::from_millis(400),
        };

        let envelope = Envelope {
            sender: "s@remote.test".into(),
            recipients: vec!["hello@example.com".into()],
        };

        let started = Instant::now();
        let err = forward(&f, 0, "dest@example.net", &envelope.sender, b"body\r\n")
            .await
            .expect_err("a stalled peer somehow delivered");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the budget did not bound the delivery: took {:?}",
            started.elapsed()
        );
        // Transient: a peer that stopped talking says nothing about whether
        // the recipient exists, and bouncing on it would lose deliverable mail.
        assert!(
            !err.is_permanent(),
            "a stall was reported as permanent: {err}"
        );
    }

    #[tokio::test]
    async fn a_null_mx_is_permanent_and_a_resolver_fault_is_not() {
        // The distinction `forward` used to flatten into a String. Milestone
        // 3's queue chooses between retry and dead-letter on exactly this.
        let envelope = Envelope {
            sender: "s@remote.test".into(),
            recipients: vec!["hello@example.com".into()],
        };

        let f = |resolver| Forwarding {
            resolver: Arc::new(resolver),
            ehlo_name: "pigeon.test".into(),
            destination: "dest@example.net".into(),
            limit: Arc::new(Semaphore::new(1)),
            port: 1,
            budget: Duration::from_millis(400),
        };

        // RFC 7505: the domain has published that it accepts no mail.
        let null_mx = f(pigeon_dns::FakeResolver::new()
            .with("example.net", vec![pigeon_dns::MxRecord::new(0, ".")]));
        let err = forward(
            &null_mx,
            0,
            "dest@example.net",
            &envelope.sender,
            b"body\r\n",
        )
        .await
        .expect_err("null MX delivered");
        assert!(err.is_permanent(), "null MX treated as retryable: {err}");

        // A resolver that is merely failing says nothing about the domain.
        let broken = f(pigeon_dns::FakeResolver::new().failing(
            "example.net",
            pigeon_dns::LookupError::Resolver("SERVFAIL".into()),
        ));
        let err = forward(
            &broken,
            0,
            "dest@example.net",
            &envelope.sender,
            b"body\r\n",
        )
        .await
        .expect_err("a broken resolver delivered");
        assert!(
            !err.is_permanent(),
            "a resolver fault would have bounced deliverable mail: {err}"
        );

        // A name that genuinely does not exist is permanent.
        let gone = f(pigeon_dns::FakeResolver::new().failing(
            "example.net",
            pigeon_dns::LookupError::NoSuchDomain("example.net".into()),
        ));
        let err = forward(&gone, 0, "dest@example.net", &envelope.sender, b"body\r\n")
            .await
            .expect_err("NXDOMAIN delivered");
        assert!(err.is_permanent(), "NXDOMAIN treated as retryable: {err}");
    }

    #[tokio::test]
    async fn the_spool_survey_separates_messages_from_abandoned_temporaries() {
        let tmp = TempDir::new("survey");
        pigeon_spool::Spool::new(tmp.path().to_path_buf())
            .install(&pigeon_spool::SpoolId::new("a").unwrap(), &[b"one"])
            .await
            .unwrap();
        // What a crash between create and link leaves.
        tokio::fs::write(tmp.path().join(".b.eml.partial"), b"half")
            .await
            .unwrap();

        let survey = survey_spool(tmp.path()).await.unwrap();
        assert_eq!(
            survey,
            SpoolSurvey {
                messages: 1,
                partials: 1
            },
            "an envelope was counted as a message, or a partial was invisible"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preparing_an_unwritable_spool_fails_before_the_listener_binds() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new("readonly");
        let spool = tmp.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o500)).unwrap();

        // `create_dir_all` succeeds on a directory that already exists, so
        // without the probe this is the case that starts cleanly, binds, and
        // answers 451 to every message instead of refusing to run.
        let result = prepare_spool(&spool).await;
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            // Root ignores the mode bits, so the probe legitimately succeeds
            // and there is nothing here to assert. Skipping is honest; a
            // `geteuid` binding to detect it is more machinery than the check
            // is worth.
            Ok(()) => eprintln!("skipped: the permission bits did not apply (running as root?)"),
        }
    }
}
