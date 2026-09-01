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
//! # What one message goes through
//!
//! ```text
//! MAIL FROM  ->  pin the runtime: the table, the keys and the SRS ring
//! RCPT TO    ->  route once, record where the address goes
//! DATA       ->  split by managed domain (R-2), sign each group, spool each
//!            ->  one transaction inserting every group -> 250
//! ```
//!
//! Configuration comes from `PIGEON_CONFIG` and nowhere else. The Milestone 0
//! environment runtime — `PIGEON_ACCEPT` deciding recipients, `PIGEON_FORWARD_TO`
//! naming one destination, and a forward attempted inline after the `250` — is
//! retired: routing decides both questions now, and a second path that answered
//! them differently would be an unrouted way to accept and forward mail.

mod delivery;
mod health;
mod metrics;
mod notify;
mod reload;
mod routing;
mod scanner;
mod startup;
mod submission;

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pigeon_dns::SystemResolver;
use pigeon_smtp::relay::{ForwardError, Forwarding, SelfIdentity, forward};
use pigeon_smtp::{DataError, Envelope, Message, MessageSink, Recipient, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Where a receiving MTA listens. Overridden only by tests.
const SUBMISSION_PORT: u16 = 25;

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

/// How long a settled message's rows are kept after its body is released.
///
/// The body goes when Pigeon is finished with the message; the record of what
/// happened outlives it, because "what happened to this message?" is asked days
/// later and answering it from the log alone is guesswork.
///
/// Fixed rather than configurable, like the horizon: nothing about correctness
/// depends on it, and it is the kind of knob that is set once and then explains
/// a surprise years later. If it is ever exposed it must stay well clear of
/// [`GIVE_UP_AFTER`] plus the time a DSN takes to deliver — a message whose own
/// record is collected before its bounce is sent is a failure nobody can
/// explain afterwards.
const RETAIN_RECORDS_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How much room the spool filesystem must keep.
///
/// Acceptance stops below this, with a `452`, so the sender keeps the message
/// and retries. The alternative is accepting mail and then failing to write it,
/// which is the same outage with a lost message on the end.
///
/// A fixed floor rather than a percentage: a percentage of a 4TB volume is a
/// number nobody chose, and what matters is whether the next message fits.
const DISK_FLOOR: u64 = 256 * 1024 * 1024;

/// How long shutdown waits for work already in progress.
///
/// Bounded because one delivery may legitimately run for the whole
/// [`TOTAL_FORWARD_BUDGET`] — half an hour against a slow receiver — and a
/// shutdown that waited for that is one nobody will use. What is left running
/// is safe: an unacknowledged session's sender retries, and an abandoned
/// attempt holds a fenced claim whose row returns to the queue when the lease
/// expires.
const DRAIN_DEADLINE: Duration = Duration::from_secs(20);

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
        // Read once, then hashed and parsed from the same bytes. Hashing the
        // file separately would leave a window where the recorded fingerprint
        // belongs to a ring that was never loaded, and a rotation landing in it
        // would be recorded as already published and never republished.
        let text = std::fs::read_to_string(&ring_for_derive)
            .map_err(|e| format!("SRS key ring {}: {e}", ring_for_derive.display()))?;
        let ring = pigeon_auth::KeyRing::parse(&text)
            .map_err(|e| format!("SRS key ring {}: {e}", ring_for_derive.display()))?;
        Ok(Derived {
            keys: load_keys(snapshot, &checked)?,
            srs: Arc::new(pigeon_auth::Srs::new(ring, host.clone())),
            ring: Some(digest(text.as_bytes())),
        })
    });

    // The first publication happens here rather than through the reload path,
    // and it fails startup: a key that will not load at boot will not load at
    // the first message either, and the operator should hear about it once,
    // now, rather than per message.
    let derived = derive(&snapshot).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let ring_seen = derived.ring;
    tracing::info!(domains = derived.keys.len(), "loaded DKIM signing keys");

    // Seeded from what the database says now, so the first tick after startup
    // is `Unchanged` rather than a spurious rebuild of the table just loaded.
    let seed = pigeon_route::revision::read(&started.db)
        .ok()
        .flatten()
        .unwrap_or(0);

    Ok(Auth {
        pipeline: Arc::new(pipeline),
        runtime: Arc::new(RuntimeState {
            // Seeded with what is being published right here, so the first
            // reconciliation compares against a recorded value rather than
            // against "nothing published yet" and republishes the table the
            // daemon just installed.
            coordinator: std::sync::Mutex::new({
                let mut baseline = pigeon_route::Baseline::new(seed);
                baseline.published(snapshot.fingerprint());
                baseline
            }),
            current: std::sync::RwLock::new(Arc::new(Runtime::assemble(snapshot, derived, seed))),
            ring_fingerprint: std::sync::Mutex::new(ring_seen),
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
    Some(digest(&std::fs::read(path).ok()?))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
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
) -> Result<HashMap<String, Vec<pigeon_auth::pipeline::SigningKey>>, String> {
    use pigeon_auth::pipeline::SigningKey;

    let mut keys: HashMap<String, Vec<SigningKey>> = HashMap::new();
    for domain in snapshot.domains() {
        let Some(forwarding) = snapshot.forwarding(domain) else {
            continue;
        };
        if forwarding.dkim.is_empty() {
            if forwarding.policy == pigeon_types::ForwardPolicy::RewriteFrom {
                return Err(format!(
                    "domain {domain} is set to rewrite_from and has no active DKIM key; \
                     a rewritten From: that cannot be signed fails DMARC on a domain \
                     Pigeon controls"
                ));
            }
            continue;
        }

        // Every active identity, in the loader's order: RSA first, because the
        // first key is the one that seals the ARC set and RSA is what every
        // receiver verifies.
        let mut loaded = Vec::with_capacity(forwarding.dkim.len());
        for identity in &forwarding.dkim {
            // The stored path is operator-editable, so it is resolved against
            // the configured root and refused if it escapes.
            let path = checked
                .resolve_key(&identity.private_key_path)
                .map_err(|e| format!("DKIM key for {domain}: {e}"))?;

            let key = if identity.algorithm == "ed25519" {
                let der = std::fs::read(&path)
                    .map_err(|e| format!("DKIM key for {domain} at {}: {e}", path.display()))?;
                SigningKey::from_ed25519_pkcs8(&der, domain, &identity.selector)
            } else {
                let pem = std::fs::read_to_string(&path)
                    .map_err(|e| format!("DKIM key for {domain} at {}: {e}", path.display()))?;
                SigningKey::from_pkcs8_pem(&pem, domain, &identity.selector)
            }
            .map_err(|e| format!("DKIM key for {domain}: {e}"))?;

            loaded.push(key);
        }
        keys.insert(domain.to_string(), loaded);
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
    keys: HashMap<String, Vec<pigeon_auth::pipeline::SigningKey>>,
    /// The SRS ring, as of this publication.
    ///
    /// In here rather than beside it because rotation is the same kind of event
    /// as a key change: `pigeon srs rotate` writes a new ring, and a daemon
    /// holding the old one would keep signing return paths with the key that
    /// was just displaced — which verifies today and stops verifying when the
    /// operator eventually deletes it.
    srs: Arc<pigeon_auth::Srs>,
    /// The identity of everything published here, as one hash.
    ///
    /// The snapshot's own fingerprint covers the database; this extends it with
    /// what the runtime is assembled from outside it — the key material
    /// actually loaded, and the SRS ring. Recorded on every accepted message,
    /// so "which configuration decided this" is answerable afterwards even
    /// across a restore that rewound the revision counter.
    fingerprint: [u8; 32],
    /// The routing revision this was published at.
    ///
    /// Beside the fingerprint rather than looked up separately: an accepted
    /// message records both, and a reader that took the number from the
    /// coordinator and the hash from the runtime could catch a publication
    /// between the two and record a pair that never existed.
    revision: i64,
}

impl Runtime {
    /// Combine a table with what was derived from it, and hash the result.
    fn assemble(snapshot: pigeon_route::Snapshot, derived: Derived, revision: i64) -> Self {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();
        h.update(snapshot.fingerprint());

        // Sorted, because a `HashMap`'s order is not a property of the
        // configuration and would make one runtime hash differently per run.
        let mut keys: Vec<(&String, Vec<[u8; 32]>)> = derived
            .keys
            .iter()
            .map(|(domain, keys)| (domain, keys.iter().map(|k| k.identity()).collect()))
            .collect();
        keys.sort_by(|a, b| a.0.cmp(b.0));
        h.update((keys.len() as u64).to_be_bytes());
        for (domain, identities) in keys {
            h.update((domain.len() as u64).to_be_bytes());
            h.update(domain.as_bytes());
            // Ordered, not sorted: the order decides which key seals the ARC
            // set, so two domains signing with the same pair in a different
            // order are two different runtimes.
            h.update((identities.len() as u64).to_be_bytes());
            for identity in identities {
                h.update(identity);
            }
        }

        // An unreadable ring hashes as its own state rather than as any
        // particular ring: it is a runtime that could not be assembled from
        // one, which is not the same as a runtime assembled from an empty one.
        match derived.ring {
            Some(ring) => {
                h.update(b"ring");
                h.update(ring);
            }
            None => h.update(b"no-ring"),
        }

        Self {
            snapshot: Arc::new(snapshot),
            keys: derived.keys,
            srs: derived.srs,
            fingerprint: h.finalize().into(),
            revision,
        }
    }
}

/// The published [`Runtime`], and what it takes to build one.
///
/// Implements [`pigeon_route::Publish`], so the reload worker installs the
/// combined state through the same path a snapshot would have taken — and a
/// key that will not load fails the publication rather than being discovered
/// one message later.
struct RuntimeState {
    /// The coordinator's critical section (R-6, `M1-RELOAD.md` C-1).
    ///
    /// Everything that can decide what is served happens inside it: observing
    /// the revision, loading and validating a snapshot, publishing, and
    /// reconciling. One lock rather than a compare-and-set on a version number,
    /// because ordering then comes from the lock — and a candidate built
    /// outside it cannot exist, which is what makes "a stale candidate may only
    /// lose publication" true by construction rather than by argument.
    ///
    /// Held across a SQLite read, which is affordable here for the reason
    /// measured in `M3-DESIGN.md` §11: mutations are operator actions, not
    /// traffic.
    coordinator: std::sync::Mutex<pigeon_route::Baseline>,
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
    keys: HashMap<String, Vec<pigeon_auth::pipeline::SigningKey>>,
    srs: Arc<pigeon_auth::Srs>,
    /// The hash of the ring bytes these keys were parsed from.
    ///
    /// Produced by the deriver rather than read again here, so what is recorded
    /// as published is exactly what was loaded.
    ring: Option<[u8; 32]>,
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
    /// Observe the routing revision and act on it, all inside the coordinator.
    ///
    /// Returns `None` when there is nothing to do. Queue commits cannot bring
    /// us here at all: the counter has triggers on the routing tables only.
    fn tick_routing(&self, conn: &rusqlite::Connection) -> Option<Result<(), String>> {
        let mut baseline = self.coordinator.lock().expect("coordinator lock poisoned");

        let observed = match pigeon_route::revision::read(conn) {
            Ok(v) => v,
            Err(e) => return Some(Err(format!("cannot read the routing revision: {e}"))),
        };

        match baseline.observe(observed) {
            pigeon_route::Observation::Unchanged => None,
            pigeon_route::Observation::Unknown => Some(Err(
                "the routing revision cannot be read; nothing was published".into(),
            )),
            // Both rebuild. A regression has already reset the lineage inside
            // `observe`, which is what makes the table built here beat whatever
            // the previous lineage published.
            pigeon_route::Observation::Advanced | pigeon_route::Observation::Regressed => {
                Some(self.rebuild(conn, &mut baseline))
            }
        }
    }

    /// Load, validate and publish, with the coordinator already held.
    fn rebuild(
        &self,
        conn: &rusqlite::Connection,
        baseline: &mut pigeon_route::Baseline,
    ) -> Result<(), String> {
        let inputs = pigeon_route::load(conn).map_err(|e| e.to_string())?;
        let built = pigeon_route::Snapshot::build(inputs).map_err(|e| e.to_string())?;
        self.publish_recording(baseline, built.snapshot)
    }

    /// Publish, and record in the baseline what was published.
    ///
    /// One place, so the recorded fingerprint cannot be the one a *failed*
    /// publication would have installed: a snapshot whose keys will not load
    /// leaves both the served runtime and the baseline's record on the previous
    /// state, and the next reconciliation still sees a difference and retries.
    fn publish_recording(
        &self,
        baseline: &mut pigeon_route::Baseline,
        snapshot: pigeon_route::Snapshot,
    ) -> Result<(), String> {
        let fingerprint = snapshot.fingerprint();
        self.install(snapshot, baseline.revision)?;
        baseline.published(fingerprint);
        Ok(())
    }

    /// Reconcile: load and compare the rows themselves, whatever the counter
    /// says.
    ///
    /// This is C-2's safety net. A restore can present the same revision over
    /// different rows — the counter cannot see it, and neither can anything
    /// that only compares numbers. When the rows differ from what is published,
    /// the lineage advances so the rebuilt table wins, and the revision is left
    /// alone because it has not moved.
    fn reconcile_routing(&self, conn: &rusqlite::Connection) -> Option<Result<(), String>> {
        let mut baseline = self.coordinator.lock().expect("coordinator lock poisoned");

        let inputs = match pigeon_route::load(conn) {
            Ok(i) => i,
            Err(e) => return Some(Err(format!("reconciliation could not load: {e}"))),
        };
        let built = match pigeon_route::Snapshot::build(inputs) {
            Ok(b) => b,
            Err(e) => return Some(Err(format!("reconciliation could not build: {e}"))),
        };

        // The whole comparison, not a cheaper proxy for it. Counts would agree
        // across a restore that swaps one destination for another, and once
        // `RCPT` answers from this table that is misdelivered mail rather than
        // stale metadata (`M1-RELOAD.md` C-2).
        //
        // Compared against what the coordinator recorded publishing, not
        // against the served runtime: they are the same thing while every
        // publication goes through here, and the recorded value is the one this
        // lock owns.
        if baseline.published_fingerprint() == Some(built.snapshot.fingerprint()) {
            return None;
        }

        // Rows differing at an unmoved revision is exactly what the revision
        // counter cannot express, so the lineage advances instead: the table
        // built here has to beat anything the previous lineage published.
        baseline.diverged();
        Some(self.publish_recording(&mut baseline, built.snapshot))
    }

    fn reconcile_ring(&self) -> Option<Result<(), String>> {
        // Under the coordinator like every other publication: a second path
        // that can install a runtime is a second thing whose ordering against
        // the first has to be argued about (C-1).
        let mut baseline = self.coordinator.lock().expect("coordinator lock poisoned");

        let current = ring_fingerprint(&self.ring_path);
        if current == *self.ring_fingerprint.lock().expect("ring lock poisoned") {
            return None;
        }

        // The table is republished as it stands: what has to be rebuilt is what
        // is *derived* from it, which now includes the ring.
        let snapshot = (*self.pin().snapshot).clone();
        Some(self.publish_recording(&mut baseline, snapshot))
    }
}

impl reload::RoutingSource for RuntimeState {
    fn tick(&self, conn: &rusqlite::Connection) -> Option<Result<(), String>> {
        self.tick_routing(conn)
    }

    fn reconcile_rows(&self, conn: &rusqlite::Connection) -> Option<Result<(), String>> {
        self.reconcile_routing(conn)
    }

    fn reconcile(&self) -> Option<Result<(), String>> {
        self.reconcile_ring()
    }
}

impl pigeon_route::Publish for RuntimeState {
    /// Publishes at the revision already in force.
    ///
    /// Correct for the two callers that reach it: republishing for a changed
    /// SRS ring, where the routing has not moved, and tests that install a
    /// table directly. Everything the coordinator publishes goes through
    /// `publish_recording`, which supplies the revision it observed.
    fn publish(&self, snapshot: pigeon_route::Snapshot) -> Result<(), String> {
        let revision = self.pin().revision;
        self.install(snapshot, revision)
    }
}

impl RuntimeState {
    fn install(&self, snapshot: pigeon_route::Snapshot, revision: i64) -> Result<(), String> {
        // Keys first: a snapshot whose keys will not load is not installed at
        // all. The previous runtime keeps serving, which is the same rule the
        // detector applies to a configuration that will not build.
        let derived = (self.derive)(&snapshot)?;

        // Recorded from what the deriver actually loaded, and only once the
        // derivation succeeded: a ring recorded as published after a failed
        // publication would never be republished, and the daemon would keep
        // signing return paths with the displaced key.
        let ring = derived.ring;
        let runtime = Arc::new(Runtime::assemble(snapshot, derived, revision));

        *self.current.write().expect("runtime lock poisoned") = runtime;
        *self.ring_fingerprint.lock().expect("ring lock poisoned") = ring;
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

/// Everything acceptance needs, and nothing delivery does.
///
/// No resolver and no destination: where a message goes is decided by routing
/// at `RCPT TO` and recorded in the queue, and sending it is the delivery
/// worker's job. The sink writes bytes and rows.
#[derive(Clone)]
struct SpoolSink {
    spool: pigeon_spool::Spool,
    queue: Queue,
    auth: Auth,
    counter: Arc<AtomicU64>,
    /// Distinguishes identifiers from different runs of the process.
    boot: u32,
    /// What is refused during the conversation, and to whom it does not apply.
    abuse: Arc<Abuse>,
    /// The spool filesystem, watched so acceptance stops before it fills.
    disk: Arc<Disk>,
}

/// Whether there is room to accept another message.
///
/// Refusing at `MAIL FROM` with a `452` is the honest failure: the sender keeps
/// the message and retries, and a host that is out of disk gets quiet rather
/// than accepting mail it cannot write. Accepting and then failing to spool is
/// the same outage with a lost message on the end of it.
///
/// Sampled rather than checked per message: `statvfs` on every `MAIL FROM`
/// would put a syscall on the hot path to answer a question whose answer
/// changes over minutes.
#[derive(Debug)]
struct Disk {
    path: PathBuf,
    /// Bytes that must remain free.
    floor: u64,
    /// The last reading, and when it was taken.
    seen: std::sync::Mutex<(std::time::Instant, u64)>,
}

impl Disk {
    /// How often the filesystem is asked. Long enough not to be a per-message
    /// cost, short enough that a filling disk is noticed inside one retry.
    const SAMPLE: Duration = Duration::from_secs(30);

    fn new(path: PathBuf, floor: u64) -> Self {
        let free = free_space(&path).unwrap_or(u64::MAX);
        Self {
            path,
            floor,
            seen: std::sync::Mutex::new((std::time::Instant::now(), free)),
        }
    }

    /// Whether there is room. A filesystem that cannot be read is treated as
    /// having room: refusing every message because `statvfs` failed would be a
    /// self-inflicted outage, and the spool write itself still fails honestly.
    fn has_room(&self) -> bool {
        let mut seen = match self.seen.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };
        if seen.0.elapsed() >= Self::SAMPLE {
            *seen = (
                std::time::Instant::now(),
                free_space(&self.path).unwrap_or(u64::MAX),
            );
        }
        seen.1 > self.floor
    }
}

/// Free bytes on the filesystem holding `path`.
#[cfg(unix)]
fn free_space(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: `statvfs` fills the struct and reads a NUL-terminated path. Both
    // hold here, and the return code is checked before the struct is read.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_space(_path: &Path) -> std::io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "free space is only read on unix",
    ))
}

/// The reputation controls, resolved once.
///
/// Held by the sink rather than read from configuration per connection: these
/// are consulted on every connection and every recipient, and re-reading a file
/// there would put an I/O error on the acceptance path.
struct Abuse {
    /// Blocklist zones, in the order they are consulted.
    blocklists: Vec<String>,
    /// Addresses no control applies to.
    trusted: std::collections::HashSet<std::net::IpAddr>,
    /// Zero disables greylisting.
    greylist_seconds: i64,
    /// The external content scanner, if one is configured.
    scanner: Option<scanner::Scanner>,
    /// The resolver the blocklists are asked through. The same one delivery
    /// uses: one DNS stack, one set of answers.
    resolver: Arc<SystemResolver>,
}

impl Abuse {
    fn trusts(&self, peer: std::net::IpAddr) -> bool {
        self.trusted.contains(&peer.to_canonical())
    }
}

/// The message as it arrived, minus the routing that decides what happens to
/// it.
///
/// One struct because these five travel together everywhere: the pipeline
/// authenticates against the envelope the body came with, and separating them
/// would let a caller pass one message's body with another's envelope.
struct Incoming<'a> {
    peer: std::net::IpAddr,
    helo: &'a str,
    envelope: &'a Envelope,
    received: &'a str,
    body: &'a [u8],
}

/// Run the authentication pipeline for one domain group.
///
/// The forwarding policy and the signing key come from the snapshot the
/// routing decision was made against, selected by the domain Pigeon accepted
/// the mail *for* — the identity it forwards under and the one an ARC seal
/// carries.
///
/// One group, one identity: a submission addressed to two managed domains is
/// two messages with different signed bytes (R-2), so the domain is a
/// parameter here rather than something guessed from the first recipient.
async fn authenticate(
    auth: &Auth,
    runtime: &Runtime,
    recipient_domain: &str,
    message: Incoming<'_>,
) -> Result<pigeon_auth::pipeline::Outbound, pigeon_auth::pipeline::PipelineError> {
    let Incoming {
        peer,
        helo,
        envelope,
        received,
        body,
    } = message;

    use pigeon_auth::pipeline::Rewrite;

    // Pinned at `MAIL FROM`, not read here: the policy that decides how this
    // message is signed must be the one that accepted its recipients. Reading
    // it now would let a reload between `RCPT TO` and the end of `DATA` sign
    // under a configuration that never accepted the message.
    let snapshot = &runtime.snapshot;

    let forwarding = snapshot.forwarding(recipient_domain);
    // Every key the domain publishes: one signature each, and the first seals.
    let signing: &[pigeon_auth::pipeline::SigningKey] = runtime
        .keys
        .get(recipient_domain)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

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

/// What one mail transaction pins and decides.
///
/// The runtime is pinned at `MAIL FROM` so a reload landing mid-transaction
/// cannot accept a recipient under one configuration and sign under another.
/// The plan is filled in at `RCPT TO` and read at `DATA`: routing happens once.
#[derive(Debug)]
struct Transaction {
    runtime: Arc<Runtime>,
    plan: routing::Plan,
    /// The client's address, normalised, and the sender it gave. Both are part
    /// of the greylist key, and both are fixed for the transaction.
    peer: std::net::IpAddr,
    sender: String,
}

impl MessageSink for SpoolSink {
    type Transaction = Transaction;

    fn begin(
        &self,
        peer: std::net::SocketAddr,
        sender: &str,
        // Nobody authenticates on port 25: mail from strangers is the job.
        _principal: Option<&str>,
    ) -> Self::Transaction {
        Transaction {
            runtime: self.auth.runtime.pin(),
            plan: routing::Plan::default(),
            peer: peer.ip().to_canonical(),
            sender: sender.to_string(),
        }
    }

    /// Consult the blocklists, before the banner.
    ///
    /// A listing refuses the connection outright: forwarding what a blocklist
    /// refuses is how a forwarder's own address ends up on one, because the
    /// receiving provider attributes it to the machine that relayed it rather
    /// than to whoever wrote it.
    ///
    /// Everything else serves the peer. A list that cannot be reached has said
    /// nothing, and treating silence as a listing would turn somebody else's
    /// DNS outage into a total mail outage here.
    async fn accepts_connection(&self, peer: std::net::SocketAddr) -> pigeon_smtp::Connection {
        use pigeon_dns::dnsbl::Listing;

        // Before anything else: a host with no room for the message should say
        // so now rather than after the sender has transmitted it.
        if !self.disk.has_room() {
            tracing::error!(
                spool = %self.disk.path.display(),
                "refusing connections: the spool filesystem is nearly full"
            );
            return pigeon_smtp::Connection::Refuse("insufficient storage".into());
        }

        if self.abuse.blocklists.is_empty() || self.abuse.trusts(peer.ip()) {
            return pigeon_smtp::Connection::Accept;
        }

        match pigeon_dns::dnsbl::check(
            self.abuse.resolver.as_ref(),
            peer.ip(),
            &self.abuse.blocklists,
        )
        .await
        {
            Listing::Listed { zone, codes } => {
                tracing::info!(%peer, %zone, ?codes, "refusing a listed address");
                // The zone is logged and not sent: reply text is
                // attacker-visible, and naming the list is a hint about which
                // delisting form to fill in to come back.
                pigeon_smtp::Connection::Refuse("your address is listed".into())
            }
            Listing::NotListed => pigeon_smtp::Connection::Accept,
            Listing::Unknown { reason } => {
                tracing::warn!(%peer, %reason, "no blocklist could answer; serving the connection");
                pigeon_smtp::Connection::Accept
            }
        }
    }

    /// Route the recipient, and record where it goes.
    ///
    /// Everything predictable is decided here, at the last moment refusing is
    /// still the upstream MTA's problem rather than Pigeon's: whether the
    /// domain is carried, whether it is accepting, whether a rule matches, and
    /// where the address resolves to. After the `250` the only remaining answer
    /// is a bounce Pigeon has to generate itself.
    async fn accepts_recipient(
        &self,
        transaction: &mut Self::Transaction,
        address: &str,
        _accepted: &[String],
    ) -> Recipient {
        match transaction
            .plan
            .route(&transaction.runtime.snapshot, address)
        {
            // Routed, so the address is real and deliverable. Greylisting is
            // asked last, deliberately: an address that does not exist should
            // be told so rather than asked to come back and be told so.
            Ok(()) => self.greylisted(transaction, address).await,
            Err(routing::Refusal::NoSuchUser) => Recipient::Reject,
            // The address is real and the gate is expected to open, so the
            // sender is told to try again rather than to give up.
            Err(routing::Refusal::NotAccepting) => {
                tracing::debug!(%address, "refusing a recipient: the domain is not accepting");
                Recipient::Defer
            }
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

/// One domain group's finished bytes, ready to be queued.
///
/// Built before the acceptance transaction opens and consumed inside it: every
/// group's body is durable before a single row is written, so the transaction
/// only inserts (R-2, `M3-DESIGN.md` §4).
struct Prepared {
    id: String,
    spool_id: pigeon_spool::SpoolId,
    group: routing::Group,
    size: usize,
    /// What the pipeline reported, for the log.
    outcome: Option<pigeon_auth::pipeline::Outbound>,
}

impl SpoolSink {
    async fn deliver_inner(
        &self,
        transaction: Transaction,
        message: Message,
    ) -> Result<String, DataError> {
        let id = self.next_id();
        let Transaction { runtime, plan, .. } = transaction;
        let Message {
            mut envelope,
            peer,
            helo,
            received,
            body,
        } = message;

        // What `RCPT TO` decided, read back. Not re-resolved: routing happens
        // once per transaction, and a second lookup — even against this same
        // pinned runtime — would be a second answer that can differ from the
        // one the recipients were accepted on.
        let groups = match plan.groups(&envelope.recipients) {
            Ok(g) if !g.is_empty() => g,
            Ok(_) => {
                // No recipients: the session does not reach `DATA` without one,
                // so this is a wiring bug rather than a client.
                tracing::error!(%id, "a message reached DATA with no routed recipients");
                return Err(DataError::Temporary);
            }
            Err(e) => {
                tracing::error!(%id, error = %e, "a recipient was acknowledged without being routed");
                return Err(DataError::Temporary);
            }
        };

        // What the sender used, kept before SRS replaces it: the DSN and the
        // log need the address a person would recognise, and the envelope no
        // longer holds it after the rewrite.
        let original_sender = envelope.sender.clone();

        // The envelope sender is rewritten **once**, here, and carried. Deriving
        // it again at delivery would let a key rotation or a date change between
        // the two produce a return path that differs from the one a receiver was
        // given. One rewrite for every group, because the return path is a
        // property of the sender rather than of the domain the mail was
        // accepted for.
        if !envelope.sender.is_empty() {
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

        // Content filtering, before anything is written. The last moment a
        // message can be refused while it is still the sender's problem — and
        // scanning the received bytes rather than each group's relay form,
        // because the groups differ only in Pigeon's own headers and signature,
        // and a scanner asked the same question twice would answer it twice.
        if let Some(s) = &self.abuse.scanner {
            match s.scan(&body).await {
                scanner::Verdict::Accept => {}
                scanner::Verdict::Reject { reason } => {
                    tracing::info!(%id, %reason, "refusing a message the scanner rejected");
                    return Err(DataError::Rejected);
                }
                scanner::Verdict::Unavailable { reason } => {
                    // Not "clean". A scanner that cannot answer has said
                    // nothing, and reading that as acceptance turns a broken
                    // scanner into no scanner at all, silently.
                    tracing::error!(%id, %reason, "the content scanner could not be consulted");
                    return Err(DataError::Temporary);
                }
            }
        }

        // Every group's bytes, finished and durable, before any row is written.
        //
        // Authentication happens here, before anything is written, because the
        // spooled bytes must be the bytes that go on the wire: a retry that
        // re-derived the relay form would be a second chance to derive it
        // differently, and the ARC set signs one of the two.
        //
        // `received` comes from the SMTP layer, which already built it for this
        // hop — trace headers are the only cross-system loop guard there is,
        // and a second generator here would be a second answer to "which host
        // handled this?".
        let mut prepared: Vec<Prepared> = Vec::with_capacity(groups.len());
        for (n, group) in groups.into_iter().enumerate() {
            let group_id = format!("{id}-g{n}");
            let spool_id = match pigeon_spool::SpoolId::new(&group_id) {
                Ok(s) => s,
                Err(e) => {
                    // Generated a few lines above, so this is a bug rather than
                    // an input problem, and one to fail loudly at.
                    tracing::error!(%id, error = %e, "generated an unusable spool identifier");
                    self.discard(&prepared).await;
                    return Err(DataError::Temporary);
                }
            };

            let processed = match authenticate(
                &self.auth,
                &runtime,
                &group.domain,
                Incoming {
                    peer,
                    helo: &helo,
                    envelope: &envelope,
                    received: &received,
                    body: &body,
                },
            )
            .await
            {
                Ok(out) => out,
                Err(e) => {
                    // R-8. A rewritten `From:` that cannot be signed fails DMARC
                    // on a domain Pigeon controls, which is worse than not
                    // rewriting — so it is never written or sent. 451: the key
                    // is a local problem and the sender may usefully retry once
                    // an operator has fixed it.
                    tracing::error!(%id, domain = %group.domain, error = %e, "refusing a message that cannot be signed");
                    self.discard(&prepared).await;
                    return Err(DataError::Temporary);
                }
            };

            // One buffer: the pipeline's output already carries the trace
            // header, the authentication results and the ARC set.
            let payload = processed.payload.as_bytes().to_vec();
            if let Err(e) = self.install(&spool_id, "", &payload).await {
                // A 451 tells the sender to try again later. Answering 250 for
                // a message that never reached disk would silently lose it,
                // since the sender then considers it delivered.
                tracing::error!(%id, error = %e, "could not spool message");
                self.discard(&prepared).await;
                return Err(DataError::Temporary);
            }

            prepared.push(Prepared {
                id: group_id,
                spool_id,
                size: payload.len(),
                group,
                outcome: Some(processed),
            });
        }

        // Queue admission is the acceptance boundary. Every spool file is
        // durable by the time this runs, so the only remaining question is
        // whether the rows that refer to them exist — and on a failed commit
        // that question is answered by reading the database back, never by
        // assuming.
        match self
            .admit(Admission {
                prepared: &prepared,
                envelope: &envelope,
                original_sender: &original_sender,
                routing: &runtime,
            })
            .await
        {
            Ok(()) => {}
            Err((why, removable)) => {
                if removable {
                    // Established non-commit: the files are orphans and removing
                    // them costs a sweep nothing.
                    self.discard(&prepared).await;
                    tracing::error!(%id, error = %why, "nothing was queued");
                } else {
                    // Unknown: the rows may exist and the bodies must stay.
                    // Orphan recovery resolves it later; a duplicate on retry is
                    // survivable and losing the body is not.
                    tracing::error!(
                        %id,
                        error = %why,
                        "keeping the spooled message: the queue transaction's outcome is unknown"
                    );
                }
                return Err(DataError::Temporary);
            }
        }

        for group in &prepared {
            let sealed = group.outcome.as_ref().map(|p| p.sealed);
            let signed = group.outcome.as_ref().map(|p| p.signed);
            tracing::info!(
                id = %group.id,
                from = %display_sender(&envelope),
                domain = %group.group.domain,
                to = ?group.group.recipients,
                destinations = group.group.destinations.len(),
                bytes = group.size,
                sealed,
                signed,
                "accepted"
            );

            if let Some(out) = &group.outcome
                && let Some(reason) = out.seal_skipped
            {
                // A missing ARC set degrades to the pre-ARC status quo, which is
                // survivable — but silently, which is why it is an error and not
                // a debug line. `ChainAlreadyFailed` is the exception: that one
                // is correct behaviour, not a fault.
                match reason {
                    pigeon_auth::pipeline::SealSkipped::ChainAlreadyFailed => {
                        tracing::debug!(id = %group.id, "not extending a chain that arrived cv=fail");
                    }
                    other => {
                        tracing::error!(id = %group.id, reason = ?other, "forwarded without an ARC seal")
                    }
                }
            }
        }

        // Acknowledged once the rows are committed. Delivery is the worker's
        // job: holding the SMTP session open for the length of an onward
        // delivery would make Pigeon's response time hostage to the slowest
        // receiving server in the world.
        Ok(id)
    }

    /// Whether this recipient waits, because the sender has not been seen
    /// before.
    ///
    /// A database failure passes the recipient. The alternative is refusing
    /// mail because a local write failed, which is a self-inflicted outage —
    /// and greylisting is a heuristic that is allowed to fail open, unlike
    /// anything that decides where mail goes.
    async fn greylisted(&self, transaction: &Transaction, address: &str) -> Recipient {
        use pigeon_spool::greylist::Verdict;

        if self.abuse.greylist_seconds <= 0 || self.abuse.trusts(transaction.peer) {
            return Recipient::Accept;
        }

        let conn = self.queue.conn.lock().await;
        match pigeon_spool::greylist::check(
            &conn,
            transaction.peer,
            &transaction.sender,
            address,
            self.abuse.greylist_seconds,
            unix_now(),
        ) {
            Ok(Verdict::Pass) => Recipient::Accept,
            Ok(Verdict::Wait { seconds }) => {
                tracing::debug!(%address, seconds, "greylisting a recipient");
                Recipient::Defer
            }
            Err(e) => {
                tracing::error!(error = %e, "the greylist could not be consulted; accepting");
                Recipient::Accept
            }
        }
    }

    /// Remove spool files that no committed row refers to.
    ///
    /// Only ever called where non-commit is established — a failure before the
    /// transaction opened, or a rollback the database reported. Never on an
    /// uncertain commit, where rows may already point at these files.
    async fn discard(&self, prepared: &[Prepared]) {
        for group in prepared {
            if let Err(e) = self.spool.remove(&group.spool_id).await {
                tracing::warn!(id = %group.id, error = %e, "could not remove an orphaned spool file");
            }
        }
    }
}

/// What acceptance records about one submission.
///
/// A struct rather than four more parameters: these travel together, and
/// `routing` in particular is only meaningful paired with the envelope it was
/// pinned for — the point of recording it is that this message was accepted
/// under *that* configuration.
struct Admission<'a> {
    prepared: &'a [Prepared],
    envelope: &'a Envelope,
    original_sender: &'a str,
    /// The runtime pinned at `MAIL FROM`.
    routing: &'a Runtime,
}

impl SpoolSink {
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
    /// Queue every group in one transaction, and decide what the sender is told.
    ///
    /// The acceptance boundary: `250` means these rows are committed, not that
    /// a forward was attempted. One transaction for all groups, never one each
    /// — a `250` covers the whole submission, so a crash between two commits
    /// would leave the sender told that everything was accepted while half of
    /// it existed, and their retry would duplicate the half that survived.
    ///
    /// Returns whether the spool files may be removed on failure, which only an
    /// *established* non-commit permits.
    async fn admit(&self, message: Admission<'_>) -> Result<(), (String, bool)> {
        use pigeon_spool::accept::{Acceptance, Destination};

        let Admission {
            prepared,
            envelope,
            original_sender,
            routing,
        } = message;

        let acceptances: Vec<Acceptance> = prepared
            .iter()
            .map(|group| Acceptance {
                spool_id: group.spool_id.clone(),
                return_path: envelope.sender.clone(),
                original_sender: original_sender.to_string(),
                size_bytes: group.size as i64,
                // Recorded, never re-resolved: what decided these rows, taken
                // from the runtime this transaction was pinned to at `MAIL
                // FROM`. Both halves come from that one pinned value, so the
                // pair is one the daemon actually served.
                routing_revision: routing.revision,
                routing_fingerprint: routing.fingerprint.to_vec(),
                // This group's recipients, not the whole envelope: the indices
                // below are into *this* list, and a DSN for a failure here must
                // name the addresses that led to this message.
                original_recipients: group.group.recipients.clone(),
                destinations: group
                    .group
                    .destinations
                    .iter()
                    .map(|d| Destination {
                        address: d.address.clone(),
                        from_recipients: d.from_recipients.clone(),
                    })
                    .collect(),
            })
            .collect();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut conn = self.queue.conn.lock().await;
        match pigeon_spool::accept(&mut conn, &self.queue.path, &acceptances, now) {
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

    // Configuration comes from a file. There is no environment fallback: the
    // Milestone 0 runtime — `PIGEON_ACCEPT` deciding recipients and
    // `PIGEON_FORWARD_TO` naming one destination — is retired, because routing
    // now decides both and a fallback that answers those questions differently
    // is a second, unrouted way to accept and forward mail.
    let config_path = std::env::var("PIGEON_CONFIG")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PIGEON_CONFIG is unset. pigeond needs a configuration file: it holds the \n\
                 database that carries the routing table, the spool directory and the SRS \n\
                 key ring. See docs/CONFIG.md.",
            )
        })?;

    let mut started = startup::start(Path::new(&config_path), |dir| async move {
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

    let domains = started.snapshot.domain_names().count();
    let schema = pigeon_db::schema_version(&started.db).unwrap_or(0);
    let db_path = started.config.config().database.clone();
    tracing::info!(schema, "control plane open");
    tracing::info!(domains, "routing table serving");

    // The pieces the reload worker needs, carried forward. It is deliberately
    // **not** started here: everything between this point and the listener
    // binding can fail, and a worker started before them would be left running
    // by an early return.
    //
    // The snapshot rather than a `Router`: the daemon publishes a combined
    // runtime — the table *and* the keys derived from it — and a `Router` here
    // would be a second place a table could be installed.
    let snapshot = started.snapshot.clone();
    let watcher = std::mem::take(&mut started.watcher);
    let _ = watcher;

    let listen = started.config.config().smtp.inbound.listen.to_string();
    let hostname = started.config.config().hostname.clone();
    // The listener config takes `hostname` by value below.
    let hostname_for_worker = hostname.clone();
    let spool = started.config.config().spool.clone();
    let sink_dir = spool.clone();

    // Loaded here rather than at the first `STARTTLS`: a certificate that
    // cannot be read is local misconfiguration, and discovering it per
    // connection means discovering it while somebody's mail is in flight.
    //
    // Absent is a supported configuration, not a degraded one. Inbound TLS
    // between mail servers is opportunistic, and an MX that refused to serve
    // without a certificate would refuse mail rather than protect it.
    let inbound = &started.config.config().smtp.inbound;
    let tls = match (&inbound.tls_certificate, &inbound.tls_private_key) {
        (Some(cert), Some(key)) => {
            let loaded = pigeon_smtp::tls::load(cert, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

            // Said at startup, because a certificate that expires next week is
            // something to hear about now rather than at the handshake that
            // fails.
            match pigeon_smtp::tls::expires_at(cert) {
                Ok(at) => {
                    let days = (at - unix_now()) / 86_400;
                    tracing::info!(certificate = %cert.display(), expires_in_days = days, "STARTTLS enabled");
                }
                Err(e) => tracing::warn!(error = %e, "cannot read the certificate's expiry"),
            }
            Some(pigeon_smtp::tls::Serving::new(loaded))
        }
        // Validation refuses half a pair, so this is genuinely "not
        // configured" rather than "misconfigured".
        _ => {
            tracing::warn!(
                "no inbound TLS certificate is configured: STARTTLS will not be offered and \
                 mail from senders that would have encrypted arrives in the clear"
            );
            None
        }
    };

    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {listen}: {e}")))?;

    tracing::info!(
        %listen,
        %hostname,
        spool = %spool.display(),
        domains,
        "pigeond listening"
    );

    // Where mail goes is decided by routing and recorded in the queue, so what
    // is built here is only *how* it is sent: the resolver, the EHLO name and
    // the concurrency bound. A resolver that cannot be built is local
    // misconfiguration and stops startup. A resolver that later fails to
    // answer is not, and must not.
    let forwarding = Forwarding {
        resolver: Arc::new(
            SystemResolver::from_system()
                .map_err(|e| io::Error::other(format!("cannot build resolver: {e}")))?,
        ),
        tls: pigeon_smtp::tls::outbound(),
        // What this host is, for refusing to deliver to itself. The listener's
        // own address, plus whatever the operator had to tell us because a
        // wildcard bind cannot reveal a NAT'd or multi-homed address.
        identity: SelfIdentity::new(
            started.config.config().smtp.inbound.listen,
            &started.config.config().smtp.inbound.self_addresses,
        ),
        ehlo_name: hostname.clone(),
        limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
        port: SUBMISSION_PORT,
        budget: TOTAL_FORWARD_BUDGET,
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
    let auth = build_auth(&started, snapshot, &hostname)?;

    // Cloned before the sink takes ownership: the reload worker publishes into
    // the same state the sink reads from, which is the point.
    let auth_runtime = Arc::clone(&auth.runtime);

    // R-4: a sender whose rewritten return path would not fit in a 64-octet
    // local part cannot be forwarded, and the last moment at which refusing is
    // still the *upstream* MTA's problem is `RCPT`. After `250` there is a
    // message that can neither be forwarded nor bounced, and generating a DSN
    // for it would be Pigeon owning a failure it could have declined.
    let return_path = {
        // The published runtime rather than a captured ring: a rotation must
        // change what this refuses as well as what the pipeline signs, and both
        // read the same state.
        let runtime = Arc::clone(&auth.runtime);
        Some(Arc::new(move |sender: &str| {
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
        })
            as Arc<pigeon_smtp::server::SharedReturnPathCheck>)
    };

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
    let queue = {
        let conn = pigeon_db::open(&db_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot open {} for queueing: {e}", db_path.display()),
            )
        })?;
        Queue {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            path: Arc::new(db_path.clone()),
        }
    };

    let abuse = {
        let a = &started.config.config().abuse;
        if !a.blocklists.is_empty() {
            tracing::info!(zones = ?a.blocklists, "consulting blocklists at connect time");
        }
        if a.greylist_seconds > 0 {
            tracing::info!(seconds = a.greylist_seconds, "greylisting new senders");
        }
        if let Some(path) = &a.scanner {
            tracing::info!(scanner = %path.display(), "content scanning enabled");
        }
        Arc::new(Abuse {
            blocklists: a.blocklists.clone(),
            trusted: a.trusted.iter().map(|ip| ip.to_canonical()).collect(),
            greylist_seconds: a.greylist_seconds,
            scanner: a.scanner.as_ref().map(|path| scanner::Scanner {
                command: path.clone(),
                args: a.scanner_args.clone(),
                timeout: Duration::from_secs(a.scanner_timeout_seconds),
            }),
            // The resolver delivery already built: one DNS stack, one set of
            // answers, and one place a resolver failure is classified.
            resolver: Arc::clone(&forwarding.resolver),
        })
    };

    let sink = SpoolSink {
        queue: queue.clone(),
        spool: pigeon_spool::Spool::new(sink_dir.clone()),
        auth: auth.clone(),
        counter: Arc::new(AtomicU64::new(0)),
        boot: std::process::id(),
        abuse,
        disk: Arc::new(Disk::new(sink_dir.clone(), DISK_FLOOR)),
    };

    let config = ServerConfig {
        hostname,
        // Cloned: the health worker holds the same handle so a renewed
        // certificate reaches the listener without a restart.
        tls: tls.clone(),
        return_path,
        ..Default::default()
    };

    // The submission listener, when one is configured. Its own listener and
    // its own sink: the two ports ask opposite questions — the MX asks whether
    // it carries the recipient, submission asks whether the principal may use
    // the sender — and one sink answering both would be one place to get the
    // difference wrong.
    let submission = match started.config.config().smtp.submission.listen {
        Some(addr) => {
            let s = &started.config.config().smtp.submission;
            let (Some(cert), Some(key)) = (&s.tls_certificate, &s.tls_private_key) else {
                // Validation refuses this, so reaching it means the check was
                // bypassed. Refused again here rather than served without TLS:
                // credentials in the clear are credentials given away.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "submission is configured with no TLS certificate",
                ));
            };

            let tls = pigeon_smtp::tls::load(cert, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

            let listener = TcpListener::bind(addr).await.map_err(|e| {
                io::Error::new(e.kind(), format!("cannot bind {addr} for submission: {e}"))
            })?;

            let sink = submission::SubmissionSink {
                spool: pigeon_spool::Spool::new(sink_dir.clone()),
                queue: queue.clone(),
                auth: auth.clone(),
                counter: Arc::new(AtomicU64::new(0)),
                boot: std::process::id(),
                limits: Arc::new(submission::Limits::new(s.messages_per_hour, s.burst)),
            };

            let config = ServerConfig {
                hostname: hostname_for_worker.clone(),
                tls: Some(pigeon_smtp::tls::Serving::new(tls)),
                // The flag that separates a submission service from an open
                // relay: no transaction may begin without authentication.
                require_auth: true,
                ..Default::default()
            };

            tracing::info!(%addr, "submission listening");
            Some(tokio::spawn(async move {
                let _ = pigeon_smtp::serve(listener, config, sink).await;
            }))
        }
        None => None,
    };

    // The delivery loop. Started after every fallible step, for the reason the
    // reload worker is: an early `?` between the start and the listener bind
    // would drop the handle and leave the task running.
    let worker = worker_identity(&hostname_for_worker);
    tracing::info!(%worker, concurrency = MAX_CONCURRENT_DELIVERIES, "delivery worker starting");
    let stop_delivery = delivery::Deliverer::start(delivery::DeliveryConfig {
        queue: queue.clone(),
        // The ring as published, so a rotation reaches the notifier the same
        // way it reaches signing.
        srs: Arc::clone(&auth.runtime.pin().srs),
        hostname: hostname_for_worker.clone(),
        spool: sink.spool.clone(),
        forwarding: forwarding.clone(),
        concurrency: MAX_CONCURRENT_DELIVERIES,
        lease_seconds: CLAIM_LEASE.as_secs() as i64,
        horizon_seconds: GIVE_UP_AFTER.as_secs() as i64,
        retain_seconds: RETAIN_RECORDS_FOR.as_secs() as i64,
        worker,
    });

    // The metrics endpoint, when one is configured. Started before the
    // workers so a scraper sees the host coming up rather than seeing nothing
    // and concluding it is down.
    let stop_metrics = match started.config.config().metrics.listen {
        Some(listen) => Some(
            metrics::Metrics::start(listen, db_path.clone())
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {listen}: {e}")))?,
        ),
        None => None,
    };

    // Periodic DNS checks, gating and alerts. Started here with the others,
    // and after every fallible step for the same reason.
    let alerts = &started.config.config().alerts;
    let alert_delivery = match (alerts.enabled, &alerts.identity, &alerts.to) {
        (true, Some(identity), Some(to)) => {
            // The identity must not be on a domain this host carries: an alert
            // about a broken domain cannot be sent *from* that domain, because
            // it is destroyed by the fault it exists to report and the operator
            // sees silence — which looks exactly like health.
            let identity_domain = identity
                .rsplit_once('@')
                .map(|(_, d)| d.to_ascii_lowercase())
                .unwrap_or_default();
            let carried = pigeon_db::repo::list_domains(&started.db)
                .map(|ds| ds.iter().any(|d| d.name == identity_domain))
                .unwrap_or(false);

            if carried {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "alerts.identity is {identity}, which is on a domain this host carries. \n\
                         An alert about that domain would be sent from the domain it is \n\
                         reporting on, and the operator would see silence instead."
                    ),
                ));
            }

            tracing::info!(%to, "alerts enabled");
            Some(health::AlertDelivery {
                identity: identity.clone(),
                to: to.clone(),
                forwarding: forwarding.clone(),
            })
        }
        (true, _, _) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alerts.enabled is set but alerts.identity or alerts.to is missing",
            ));
        }
        _ => {
            tracing::info!("alerts are disabled; `pigeon domains check` is the source of truth");
            None
        }
    };

    let stop_health = health::Health::start(health::HealthConfig {
        db: db_path.clone(),
        hostname: hostname_for_worker.clone(),
        addresses: started.config.config().smtp.inbound.self_addresses.clone(),
        resolver: Arc::clone(&forwarding.resolver),
        policy: pigeon_alert::Policy {
            confirm_checks: alerts.confirm_checks,
            cooldown: alerts.cooldown,
            breaker_threshold: alerts.breaker_threshold,
        },
        alerts: alert_delivery,
        certificate: match (
            &started.config.config().smtp.inbound.tls_certificate,
            &started.config.config().smtp.inbound.tls_private_key,
            &tls,
        ) {
            (Some(certificate), Some(private_key), Some(serving)) => Some(health::Certificate {
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                serving: serving.clone(),
            }),
            _ => None,
        },
    });

    // Supervised from here rather than left to a dropped handle. A panicking
    // task cannot report its own death, and an unpolled `JoinHandle` holds the
    // result silently — a daemon that spawned the worker and forgot it would
    // keep serving the last published table forever with routing frozen and
    // nothing saying why.
    //
    // The reload worker publishes into the combined runtime, so a reload that
    // adds or rotates a key installs the table and the key together or neither.
    // Publishing the table alone would leave a `rewrite_from` domain with no
    // key, or one still signing with the key that was just retired.
    let stop_reload = {
        let r = reload::Reloader::start(db_path, auth_runtime);
        // `supervise` consumes the handle and becomes the only join, so the
        // stopper is taken first. Two ways to stop one worker would be two
        // orderings to keep straight.
        let stopper = r.stopper();
        (stopper, r.supervise())
    };

    // The two halves of shutdown, in this order:
    //
    //   1. stop accepting and stop claiming
    //   2. drain what is already in progress, within a bound
    //
    // Reversing them does not converge: a drain that runs while connections
    // are still being accepted and rows still being claimed is waiting on work
    // the daemon is still taking on.
    //
    // Both are signalled by the same future, so the listener and the delivery
    // worker stop at the same instant rather than in whatever order the
    // shutdown code happens to be written in.
    let (stopping, listener_stops) = tokio::sync::watch::channel(false);
    let mut delivery_stops = stopping.subscribe();

    let served = tokio::spawn(async move {
        let mut listener_stops = listener_stops;
        pigeon_smtp::serve_with_shutdown(
            listener,
            config,
            sink,
            async move {
                // `changed` only resolves on a *new* value, which is exactly
                // the signal — the channel starts at false.
                let _ = listener_stops.changed().await;
            },
            DRAIN_DEADLINE,
        )
        .await
    });

    signalled().await;
    tracing::info!("shutting down: no new connections will be accepted");
    let _ = stopping.send(true);
    let _ = delivery_stops.changed().await;

    // Concurrently: the listener drains its sessions while the delivery worker
    // drains its attempts. Serially would double the worst case for no reason —
    // they wait on different things.
    let (served, drained) = tokio::join!(served, stop_delivery.drain(DRAIN_DEADLINE));
    match drained {
        delivery::Drained::Complete => tracing::info!("delivery worker idle"),
        delivery::Drained::Abandoned { in_flight } => tracing::warn!(
            in_flight,
            "shutting down with deliveries in flight; their claims are fenced and \
             the rows return to the queue when the leases expire"
        ),
    }

    // Signalled *and* joined, through the supervisor. Last, because it is the
    // one worker whose work is instantaneous: it publishes a table or it does
    // not.
    let (stopper, supervisor) = stop_reload;
    stopper.stop_and_join(supervisor).await;

    // Supervised so a panic in the loop is reported rather than swallowed.
    drop(stop_delivery.supervise());

    // The health worker holds nothing durable: a cycle interrupted mid-check
    // has written at most a status the next cycle recomputes, so it is stopped
    // rather than drained.
    stop_health.stop();
    drop(stop_health.supervise());

    // The submission listener stops with the runtime: it holds nothing durable
    // of its own, and a message it was mid-way through accepting has no `250`
    // and will be retried by the client.
    if let Some(handle) = submission {
        handle.abort();
    }

    if let Some(m) = stop_metrics {
        m.stop();
        drop(m.supervise());
    }

    served.unwrap_or(Ok(()))
}

/// Resolve when the process is asked to stop.
///
/// `SIGTERM` as well as `Ctrl-C`, because the former is what an init system
/// sends and the latter is what a terminal sends: a daemon that only handled
/// the second would be killed uncleanly by every restart in production, which
/// is the case this whole path exists for.
async fn signalled() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                // Without it, `Ctrl-C` still works and a `SIGTERM` still kills
                // the process — uncleanly, which is worth saying out loud.
                tracing::error!(error = %e, "cannot listen for SIGTERM; shutdown will not be graceful");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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

    /// No blocklist and no greylist, which is the default configuration and
    /// what every test that is about something else wants.
    ///
    /// The resolver is real but never asked: with no zones configured the
    /// blocklist check returns before touching it, and with a zero delay the
    /// greylist writes nothing.
    fn no_abuse_controls() -> Arc<Abuse> {
        Arc::new(Abuse {
            blocklists: Vec::new(),
            trusted: std::collections::HashSet::new(),
            greylist_seconds: 0,
            scanner: None,
            // Offline: these tests are about what the daemon does with an
            // answer, not about what this machine's resolver says.
            resolver: Arc::new(pigeon_dns::SystemResolver::offline()),
        })
    }

    /// One managed domain, with a catch-all so every local part routes.
    ///
    /// Aliases are the router's own subject; what these tests need is a table
    /// that accepts and resolves, so the fixture is deliberately plain.
    fn test_domain(name: &str, destination: &str) -> pigeon_route::snapshot::DomainInput {
        let (local, host) = destination.rsplit_once('@').expect("a destination address");
        pigeon_route::snapshot::DomainInput {
            name: name.into(),
            gate: pigeon_types::DomainGate {
                status: pigeon_types::DomainStatus::Active,
                inbound_enabled: true,
                outbound_enabled: false,
            },
            plus_addressing: true,
            forwarding: pigeon_route::snapshot::Forwarding {
                policy: pigeon_types::ForwardPolicy::Preserve,
                dkim: Vec::new(),
            },
            default_destination: Some(pigeon_route::snapshot::Destination {
                local: local.into(),
                domain: host.into(),
            }),
            aliases: Vec::new(),
            catchall: Some(pigeon_route::snapshot::CatchAllInput { destination: None }),
        }
    }

    /// A sink with a real database and a real routing table behind it.
    ///
    /// Both are required now: there is no configuration under which the daemon
    /// accepts mail without a queue to put it in or a table to route it with.
    fn queued_sink(dir: &Path) -> (SpoolSink, PathBuf) {
        queued_sink_for(
            dir,
            vec![test_domain("example.com", "mailbox@provider.example")],
        )
    }

    fn queued_sink_for(
        dir: &Path,
        domains: Vec<pigeon_route::snapshot::DomainInput>,
    ) -> (SpoolSink, PathBuf) {
        let db = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&db).unwrap();
        pigeon_db::migrate(&mut conn, &db).unwrap();

        let sink = SpoolSink {
            queue: Queue {
                conn: Arc::new(tokio::sync::Mutex::new(conn)),
                path: Arc::new(db.clone()),
            },
            spool: pigeon_spool::Spool::new(dir.to_path_buf()),
            auth: auth_for(domains, false),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x1234_5678,
            abuse: no_abuse_controls(),
            // A floor of zero: these tests are about acceptance, and a test
            // host that happens to be short of disk should not fail them.
            disk: Arc::new(Disk::new(dir.to_path_buf(), 0)),
        };
        (sink, db)
    }

    /// Route one address the way `RCPT TO` does, and hand back the transaction.
    async fn transaction_for(sink: &SpoolSink, recipients: &[&str]) -> Transaction {
        let mut txn = sink.begin(
            "192.0.2.10:2525".parse().unwrap(),
            "alice@remote.test",
            None,
        );
        for r in recipients {
            assert_eq!(
                sink.accepts_recipient(&mut txn, r, &[]).await,
                Recipient::Accept,
                "the fixture should accept {r}"
            );
        }
        txn
    }

    /// One accepted message, through the whole acceptance path.
    async fn accept_message(
        sink: &SpoolSink,
        from: &str,
        recipients: &[&str],
    ) -> Result<String, DataError> {
        let txn = transaction_for(sink, recipients).await;
        sink.deliver_inner(
            txn,
            Message {
                envelope: Envelope {
                    sender: from.into(),
                    recipients: recipients.iter().map(|r| r.to_string()).collect(),
                },
                peer: "192.0.2.10".parse().unwrap(),
                helo: "sender.example".into(),
                received: "Received: from sender.example\r\n".into(),
                body: b"From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody\r\n".to_vec(),
            },
        )
        .await
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
            srs: Arc::new(pigeon_auth::Srs::new(
                pigeon_auth::KeyRing::parse(
                    "1 2026-01-01T00:00:00Z - AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                )
                .unwrap(),
                "pigeon.test",
            )),
            hostname: "pigeon.test".into(),
            spool,
            forwarding: Forwarding {
                tls: pigeon_smtp::tls::outbound(),
                identity: SelfIdentity::default(),
                resolver: Arc::new(FakeResolver::new().with(
                    "example.net",
                    vec![MxRecord::new(10, peer_addr.ip().to_string())],
                )),
                ehlo_name: "pigeon.test".into(),
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: peer_addr.port(),
                budget: Duration::from_secs(5),
            },
            concurrency,
            lease_seconds: 2400,
            horizon_seconds: 5 * 24 * 60 * 60,
            retain_seconds: RETAIN_RECORDS_FOR.as_secs() as i64,
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
    async fn draining_an_idle_worker_completes() {
        // Nothing in flight, so shutdown does not have to wait at all. The
        // useful half of this is what it proves about the loop: the stop signal
        // wakes it out of its idle sleep rather than being noticed a poll
        // later.
        let tmp = TempDir::new("drain-idle");
        let (peer_addr, _transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (_queue, deliverer) = delivery_fixture(tmp.path(), peer_addr, &[], 1, false).await;

        let drained = tokio::time::timeout(
            Duration::from_secs(2),
            deliverer.drain(Duration::from_secs(1)),
        )
        .await
        .expect("the drain did not return within its own bound");

        assert_eq!(drained, delivery::Drained::Complete);
    }

    #[tokio::test]
    async fn a_drained_worker_stops_claiming_rather_than_carrying_on() {
        // The ordering rule from the other side. Draining first and stopping
        // afterwards would wait on work the worker is still taking on: the
        // queue refills the moment a permit frees, so the drain either returns
        // by luck or never converges.
        let tmp = TempDir::new("drain-stops-claiming");

        // One connection, then nothing: every attempt after the first fails to
        // connect immediately, so the worker gets through the backlog fast if
        // it is still running.
        let (peer_addr, _transcript) = pigeon_testkit::Peer::new().close().spawn().await;

        let destinations: Vec<String> = (0..20).map(|i| format!("d{i}@example.net")).collect();
        let refs: Vec<&str> = destinations.iter().map(String::as_str).collect();
        let (queue, deliverer) = delivery_fixture(tmp.path(), peer_addr, &refs, 1, true).await;

        async fn attempted(queue: &Queue) -> i64 {
            let conn = queue.conn.lock().await;
            conn.query_row("SELECT coalesce(sum(attempts), 0) FROM delivery", [], |r| {
                r.get(0)
            })
            .unwrap()
        }

        // Let it get going, so the test is about a worker with a backlog.
        for _ in 0..100 {
            if attempted(&queue).await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        deliverer.drain(Duration::from_secs(2)).await;
        let settled = attempted(&queue).await;

        // Nothing further is claimed or attempted after the drain returns.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            attempted(&queue).await,
            settled,
            "the worker kept claiming after it was drained"
        );
    }

    #[tokio::test]
    async fn a_delivery_in_flight_is_abandoned_at_the_bound_and_left_fenced() {
        // The other half of the rule: one attempt may legitimately run for the
        // whole forward budget, so shutdown is bounded rather than patient. The
        // row it abandons is not lost — the claim is fenced by a token nothing
        // else can produce, and the lease returns the row to the queue.
        let tmp = TempDir::new("drain-inflight");

        // A peer that answers the greeting and then says nothing, so the
        // attempt is still running when the bound expires.
        let (peer_addr, _transcript) = pigeon_testkit::Peer::new()
            .send("220 peer.test ESMTP")
            .stall(Duration::from_secs(30))
            .close()
            .spawn()
            .await;

        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;

        // Wait until the row is actually claimed, or the test would be about
        // an idle worker again.
        let mut claimed = false;
        for _ in 0..100 {
            let conn = queue.conn.lock().await;
            let n: i64 = conn
                .query_row(
                    "SELECT count(*) FROM delivery WHERE claimed_by IS NOT NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            drop(conn);
            if n > 0 {
                claimed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(claimed, "the worker never claimed the row");

        let drained = deliverer.drain(Duration::from_millis(200)).await;
        assert_eq!(
            drained,
            delivery::Drained::Abandoned { in_flight: 1 },
            "the drain waited for an attempt it should have abandoned"
        );

        // Still claimed, with a token and a lease: reclaimable, not lost.
        let conn = queue.conn.lock().await;
        let (claimed_by, token, lease): (Option<String>, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT claimed_by, claim_token, lease_expires_at FROM delivery",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(claimed_by.is_some(), "the abandoned claim was released");
        assert!(token.is_some(), "the abandoned claim carries no fence");
        assert!(
            lease.is_some(),
            "the abandoned claim has no lease to expire"
        );
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
    async fn a_released_body_is_marked_before_the_file_goes() {
        // SQLite cannot commit an unlink, so one of two crash windows has to
        // be chosen. Marking first leaves an orphan the sweep collects;
        // unlinking first leaves a row claiming a body that is gone, which
        // every reader treats — correctly — as an integrity failure.
        //
        // Driven by making the removal fail: the row must still be marked.
        let tmp = TempDir::new("release-order");
        let (peer_addr, _t) = pigeon_testkit::Peer::accepting().spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;
        deliverer.stop();

        // A delivered message, so its body is releasable.
        {
            let conn = queue.conn.lock().await;
            conn.execute(
                "UPDATE delivery SET state='delivered', terminal_at=1, next_attempt_at=NULL",
                [],
            )
            .unwrap();
        }

        // A directory the process cannot unlink from.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        }

        let spool = pigeon_spool::Spool::new(tmp.path().to_path_buf());
        let released = notify::release_bodies(&queue, &spool, unix_now()).await;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        assert_eq!(released, 1);
        let conn = queue.conn.lock().await;
        let marked: Option<i64> = conn
            .query_row("SELECT body_deleted_at FROM message", [], |r| r.get(0))
            .unwrap();
        assert!(
            marked.is_some(),
            "the row was not marked, so a crash here would claim a body that may be gone"
        );
    }

    #[tokio::test]
    async fn a_body_is_not_released_while_a_report_is_owed() {
        // The report quotes the original headers, so the body outlives the
        // deliveries by as long as the reports take.
        let tmp = TempDir::new("release-owed");
        let (peer_addr, _t) = pigeon_testkit::Peer::accepting().spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;
        deliverer.stop();

        {
            let conn = queue.conn.lock().await;
            conn.execute(
                "UPDATE delivery SET state='failed', terminal_at=1, next_attempt_at=NULL,
                                     notification='owed'",
                [],
            )
            .unwrap();
        }

        let spool = pigeon_spool::Spool::new(tmp.path().to_path_buf());
        assert_eq!(
            notify::release_bodies(&queue, &spool, unix_now()).await,
            0,
            "a body was released while its report was still owed"
        );
    }

    #[tokio::test]
    async fn an_unreadable_listing_does_not_authorise_sweeping() {
        // An empty set is a claim that nothing is referenced. Returning one
        // because a query failed would delete every queued message on the
        // host, so an unknown listing has to be its own answer.
        let tmp = TempDir::new("sweep-unknown");
        let (peer_addr, _t) = pigeon_testkit::Peer::accepting().spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;
        deliverer.stop();

        assert!(
            notify::referenced(&queue).await.is_some(),
            "a healthy database reported an unknown listing"
        );

        // With the table gone, the listing cannot be produced.
        {
            let conn = queue.conn.lock().await;
            // Dropped in dependency order; `delivery` refers to `message`.
            conn.execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DROP TABLE recipient_delivery;
                 DROP TABLE delivery_event;
                 DROP TABLE delivery;
                 DROP TABLE original_recipient;
                 DROP TABLE message;",
            )
            .unwrap();
        }
        assert!(
            notify::referenced(&queue).await.is_none(),
            "a failed listing was reported as `nothing is referenced`"
        );
    }

    #[tokio::test]
    async fn a_permanent_failure_produces_a_report_addressed_to_the_real_sender() {
        // End to end: the destination refuses permanently, the failure is
        // owed, the notifier reverses the stored SRS return path and queues a
        // report to the address a person would recognise — not to the SRS
        // address, which would deliver the bounce back into Pigeon.
        let tmp = TempDir::new("dsn-e2e");
        let (peer_addr, _t) = peer_answering("550 5.1.1 No such user").spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;

        // The fixture's ring, so the return path below reverses.
        let srs = pigeon_auth::Srs::new(
            pigeon_auth::KeyRing::parse(
                "1 2026-01-01T00:00:00Z - AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            )
            .unwrap(),
            "pigeon.test",
        );
        let return_path = srs
            .forward("alice", "remote.test", pigeon_auth::Day::now())
            .unwrap();
        {
            let conn = queue.conn.lock().await;
            conn.execute("UPDATE message SET return_path = ?1", [&return_path])
                .unwrap();
        }

        // Wait for the report to be queued: a second message, with a null
        // return path.
        let mut reported = None;
        for _ in 0..80 {
            let conn = queue.conn.lock().await;
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT m.return_path, d.destination
                       FROM message m JOIN delivery d ON d.message_id = m.id
                      WHERE m.spool_id LIKE 'dsn-%'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();
            drop(conn);
            if row.is_some() {
                reported = row;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let (report_return_path, report_to) = reported.expect("no failure report was queued");
        assert!(
            report_return_path.is_empty(),
            "the report has an envelope sender, so a bounce of it would bounce again"
        );
        assert_eq!(
            report_to, "alice@remote.test",
            "the report was not addressed to the original sender"
        );

        // And the failure is no longer owed.
        let conn = queue.conn.lock().await;
        let notification: String = conn
            .query_row(
                "SELECT notification FROM delivery WHERE destination = 'a@example.net'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(notification, "enqueued");
        drop(conn);

        deliverer.stop();
    }

    #[tokio::test]
    async fn a_return_path_that_will_never_verify_is_abandoned_not_retried_forever() {
        // Permanent: the stored address is not something this host issued, so
        // no amount of waiting produces a recipient. Recorded as `abandoned`,
        // which is durably distinct from "no report was required".
        let tmp = TempDir::new("dsn-abandon");
        let (peer_addr, _t) = peer_answering("550 5.1.1 No such user").spawn().await;
        let (queue, deliverer) =
            delivery_fixture(tmp.path(), peer_addr, &["a@example.net"], 1, true).await;

        {
            let conn = queue.conn.lock().await;
            conn.execute(
                "UPDATE message SET return_path = 'not-an-srs-address@pigeon.test'",
                [],
            )
            .unwrap();
        }

        let mut notification = String::new();
        for _ in 0..80 {
            let conn = queue.conn.lock().await;
            notification = conn
                .query_row(
                    "SELECT notification FROM delivery WHERE destination = 'a@example.net'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or_default();
            drop(conn);
            if notification == "abandoned" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            notification, "abandoned",
            "an unreportable failure was not abandoned, or was recorded as needing no report"
        );

        // The reason is in the delivery log, not only in a process log.
        let conn = queue.conn.lock().await;
        let response: String = conn
            .query_row(
                "SELECT response FROM delivery_event WHERE kind = 'notify'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(response.contains("not reported"), "{response}");
        drop(conn);

        deliverer.stop();
    }

    /// A runtime with a stated revision, a fixed ring, and optionally a key.
    ///
    /// Assembled directly rather than published, because what is under test is
    /// the identity a runtime carries — not how it came to be installed.
    fn runtime_for(revision: i64, ring: &str, key: Option<&str>) -> Runtime {
        let mut keys = HashMap::new();
        if let Some(pem) = key {
            keys.insert(
                "example.com".to_string(),
                vec![
                    pigeon_auth::pipeline::SigningKey::from_pkcs8_pem(pem, "example.com", "sel")
                        .unwrap(),
                ],
            );
        }
        Runtime::assemble(
            pigeon_route::Snapshot::default(),
            Derived {
                keys,
                srs: Arc::new(pigeon_auth::Srs::new(
                    pigeon_auth::KeyRing::parse(ring).unwrap(),
                    "pigeon.test",
                )),
                ring: Some(digest(ring.as_bytes())),
            },
            revision,
        )
    }

    const RING_A: &str = "1 2026-01-01T00:00:00Z - AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const RING_B: &str = "2 2026-02-01T00:00:00Z - HxwdHhkaGxwVFhcYERITFA0ODxAJCgsMBQYHCAECAwQ=";

    #[test]
    fn the_runtime_fingerprint_covers_what_is_published_outside_the_database() {
        // The table's own fingerprint answers for the database. It cannot
        // answer for the two things assembled around it: the key material that
        // signs, and the ring that issues return paths. A rotation of either
        // changes what the daemon does with a message, so it has to change the
        // identity a message is recorded under.
        let key = e2e_key();
        let other = pigeon_auth::dkim::KeyPair::generate(2048)
            .unwrap()
            .private_pem()
            .to_string();

        let base = runtime_for(1, RING_A, Some(key));

        assert_eq!(
            base.fingerprint,
            runtime_for(1, RING_A, Some(key)).fingerprint,
            "the same runtime hashed differently twice"
        );
        assert_ne!(
            base.fingerprint,
            runtime_for(1, RING_B, Some(key)).fingerprint,
            "a rotated SRS ring did not change the published identity"
        );
        assert_ne!(
            base.fingerprint,
            runtime_for(1, RING_A, Some(&other)).fingerprint,
            "new key material under the same selector did not change the \
             published identity"
        );
        assert_ne!(
            base.fingerprint,
            runtime_for(1, RING_A, None).fingerprint,
            "removing the signing key did not change the published identity"
        );
    }

    /// One group, as `DATA` would hand it to `admit`.
    fn prepared_group(id: &str, group: routing::Group) -> Prepared {
        Prepared {
            id: id.to_string(),
            spool_id: pigeon_spool::SpoolId::new(id).unwrap(),
            group,
            size: 10,
            outcome: None,
        }
    }

    fn one_destination(domain: &str, recipient: &str, destination: &str) -> routing::Group {
        routing::Group {
            domain: domain.into(),
            recipients: vec![recipient.into()],
            destinations: vec![routing::Destination {
                address: destination.into(),
                from_recipients: vec![0],
            }],
        }
    }

    #[tokio::test]
    async fn acceptance_records_the_runtime_it_was_pinned_to() {
        // What "recorded, never re-resolved" means at the boundary: the message
        // carries the revision *and* the fingerprint of the configuration that
        // decided its rows, both taken from the one runtime pinned at `MAIL
        // FROM`. A restore that rewinds the counter afterwards cannot make this
        // pair look like any other configuration's.
        let tmp = TempDir::new("admit-identity");
        let (s, db) = queued_sink(tmp.path());
        let pinned = s.auth.runtime.pin();

        accept_message(&s, "alice@remote.test", &["hello@example.com"])
            .await
            .expect("the message should be accepted");

        let conn = pigeon_db::open(&db).unwrap();
        let (revision, fingerprint): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT routing_revision, routing_fingerprint FROM message",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();

        assert_eq!(
            revision, pinned.revision,
            "the accepted message lost its routing revision"
        );
        assert_eq!(
            fingerprint,
            pinned.fingerprint.to_vec(),
            "the accepted message was not recorded under the pinned configuration"
        );
    }

    #[tokio::test]
    async fn acceptance_writes_the_graph_the_dsn_will_need() {
        // The envelope moved from a sidecar into rows, so what used to be a
        // string in a file is now a graph: the return path, the address the
        // sender actually used, every recipient they named, and which of them
        // reaches each destination.
        let tmp = TempDir::new("admit");
        let (s, db) = queued_sink(tmp.path());

        accept_message(
            &s,
            "alice@remote.test",
            &["hello@example.com", "sales@example.com"],
        )
        .await
        .expect("the message should be accepted");

        let conn = pigeon_db::open(&db).unwrap();
        let (return_path, original): (String, String) = conn
            .query_row(
                "SELECT return_path, original_sender FROM message",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // Rewritten by the time admission runs, and the address a person would
        // recognise is kept beside it.
        assert!(
            return_path.starts_with("SRS0="),
            "the return path was not rewritten: {return_path}"
        );
        assert_eq!(original, "alice@remote.test");

        // Both recipients reach one mailbox, so there is one delivery — and
        // both are mapped to it, which is what lets a report name the address
        // the sender wrote rather than the mailbox they have never heard of.
        let deliveries: i64 = conn
            .query_row("SELECT count(*) FROM delivery", [], |r| r.get(0))
            .unwrap();
        assert_eq!(deliveries, 1, "one mailbox became two deliveries");

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
    async fn a_greylisted_sender_is_deferred_and_admitted_on_the_retry() {
        // The whole bet, through the sink: a sender nobody has seen is asked to
        // come back, and when it does the mail is taken. A `4xx` at RCPT leaves
        // the message with the system that has a copy of it.
        let tmp = TempDir::new("greylist");
        let (mut s, db) = queued_sink(tmp.path());
        s.abuse = Arc::new(Abuse {
            blocklists: Vec::new(),
            trusted: std::collections::HashSet::new(),
            greylist_seconds: 300,
            scanner: None,
            resolver: Arc::new(pigeon_dns::SystemResolver::offline()),
        });

        let mut txn = s.begin(
            "192.0.2.10:2525".parse().unwrap(),
            "alice@remote.test",
            None,
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@example.com", &[])
                .await,
            Recipient::Defer,
            "a first-time sender was not greylisted"
        );

        // Nothing was accepted, so nothing is owed: the refusal happened while
        // the sender still had the message.
        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0);

        // The retry, once the delay has passed. Written directly rather than
        // waiting five minutes, which is the one thing a test cannot do.
        conn.execute("UPDATE greylist SET first_seen = first_seen - 600", [])
            .unwrap();
        drop(conn);

        let mut txn = s.begin(
            "192.0.2.10:2525".parse().unwrap(),
            "alice@remote.test",
            None,
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@example.com", &[])
                .await,
            Recipient::Accept,
            "the retry was refused as well"
        );
    }

    #[tokio::test]
    async fn a_trusted_address_is_never_greylisted() {
        // A backup MX or the operator's own machine. Delaying mail from a host
        // that was configured as trusted is a delay nobody asked for.
        let tmp = TempDir::new("greylist-trusted");
        let (mut s, _db) = queued_sink(tmp.path());
        s.abuse = Arc::new(Abuse {
            blocklists: Vec::new(),
            trusted: ["192.0.2.10".parse().unwrap()].into_iter().collect(),
            greylist_seconds: 300,
            scanner: None,
            resolver: Arc::new(pigeon_dns::SystemResolver::offline()),
        });

        let mut txn = s.begin(
            "192.0.2.10:2525".parse().unwrap(),
            "alice@remote.test",
            None,
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@example.com", &[])
                .await,
            Recipient::Accept
        );
    }

    #[tokio::test]
    async fn a_connection_is_served_when_no_blocklist_is_configured() {
        // The default. A blocklist is somebody else's opinion about who may
        // send mail here, and adopting one silently would be adopting it on the
        // operator's behalf.
        let tmp = TempDir::new("dnsbl-off");
        let (s, _db) = queued_sink(tmp.path());
        assert_eq!(
            s.accepts_connection("192.0.2.10:2525".parse().unwrap())
                .await,
            pigeon_smtp::Connection::Accept
        );
    }

    #[tokio::test]
    async fn a_full_spool_refuses_the_connection_rather_than_the_message() {
        // Refusing at connect is the honest failure: the sender keeps the
        // message and retries. Accepting and then failing to write it is the
        // same outage with a lost message on the end.
        let tmp = TempDir::new("disk-full");
        let (mut s, db) = queued_sink(tmp.path());

        // A floor no filesystem can be above.
        s.disk = Arc::new(Disk::new(tmp.path().to_path_buf(), u64::MAX - 1));

        assert!(
            matches!(
                s.accepts_connection("192.0.2.10:2525".parse().unwrap())
                    .await,
                pigeon_smtp::Connection::Refuse(_)
            ),
            "a full spool still accepted a connection"
        );

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0);
    }

    #[tokio::test]
    async fn an_unreadable_filesystem_does_not_stop_the_mail() {
        // Refusing every message because `statvfs` failed would be a
        // self-inflicted outage. The spool write itself still fails honestly if
        // there really is no room.
        let disk = Disk::new(PathBuf::from("/nonexistent/spool"), 0);
        assert!(disk.has_room(), "an unreadable filesystem refused mail");
    }

    #[tokio::test]
    async fn a_blocklist_that_cannot_answer_does_not_refuse() {
        // The rule the whole check turns on. A list that is down and treated as
        // "listed" refuses every message from everyone — a total mail outage
        // produced by somebody else's DNS server — while treating the same
        // silence as "not listed" forwards spam that would have been refused.
        // One is recoverable and visible; the other is not.
        //
        // The resolver here has no name servers, so every lookup fails without
        // a packet leaving the process. Which zone is named does not matter,
        // and that is the point.
        let tmp = TempDir::new("dnsbl-unreachable");
        let (mut s, _db) = queued_sink(tmp.path());

        s.abuse = Arc::new(Abuse {
            blocklists: vec!["blocklist.invalid".into()],
            trusted: std::collections::HashSet::new(),
            greylist_seconds: 0,
            scanner: None,
            resolver: Arc::new(pigeon_dns::SystemResolver::offline()),
        });

        // A list that cannot answer must never refuse: somebody else's DNS
        // outage is not a reason to stop taking mail.
        assert_eq!(
            s.accepts_connection("192.0.2.10:2525".parse().unwrap())
                .await,
            pigeon_smtp::Connection::Accept,
            "an unreachable blocklist refused a connection"
        );
    }

    /// Abuse controls with only a scanner configured.
    fn with_scanner(script: &str) -> Arc<Abuse> {
        Arc::new(Abuse {
            blocklists: Vec::new(),
            trusted: std::collections::HashSet::new(),
            greylist_seconds: 0,
            scanner: Some(scanner::Scanner {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), script.into()],
                timeout: Duration::from_secs(5),
            }),
            resolver: Arc::new(pigeon_dns::SystemResolver::offline()),
        })
    }

    #[tokio::test]
    async fn a_rejected_message_is_refused_permanently_and_never_queued() {
        // Refused at the end of DATA, before anything is written: the sender
        // still has the message, and the report goes to whoever wrote it rather
        // than being Pigeon's to generate.
        let tmp = TempDir::new("scanner-reject");
        let (mut s, db) = queued_sink(tmp.path());
        s.abuse = with_scanner("cat > /dev/null; exit 1");

        let outcome = accept_message(&s, "alice@remote.test", &["hello@example.com"]).await;
        assert!(
            matches!(outcome, Err(DataError::Rejected)),
            "a rejected message was not refused permanently: {outcome:?}"
        );

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0, "a rejected message reached the queue");

        // And nothing was spooled: the refusal happens before any bytes are
        // written, so there is no orphan for the sweep to collect.
        let spooled = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".eml"))
            .count();
        assert_eq!(spooled, 0, "a rejected message was written to the spool");
    }

    #[tokio::test]
    async fn a_broken_scanner_defers_rather_than_accepting() {
        // The asymmetry that decides this: a scanner failing open costs every
        // message that arrives while it is broken, because it is the only thing
        // looking at content at all.
        let tmp = TempDir::new("scanner-broken");
        let (mut s, db) = queued_sink(tmp.path());
        s.abuse = with_scanner("exit 42");

        let outcome = accept_message(&s, "alice@remote.test", &["hello@example.com"]).await;
        assert!(
            matches!(outcome, Err(DataError::Temporary)),
            "a broken scanner did not defer: {outcome:?}"
        );

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0);
    }

    #[tokio::test]
    async fn a_clean_message_passes_the_scanner_and_is_queued() {
        let tmp = TempDir::new("scanner-clean");
        let (mut s, db) = queued_sink(tmp.path());
        s.abuse = with_scanner("cat > /dev/null; exit 0");

        accept_message(&s, "alice@remote.test", &["hello@example.com"])
            .await
            .expect("a clean message should be accepted");

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 1);
    }

    #[tokio::test]
    async fn an_identical_second_submission_is_accepted_as_its_own_message() {
        // The duplicate-suppression policy, made falsifiable. Two submissions
        // with the same envelope, the same recipients and byte-identical
        // content are two messages, and both are delivered.
        //
        // Suppressing the second would be guessing that a sender who sent the
        // same thing twice meant to send it once. Senders legitimately resend:
        // a mailing list re-run, a monitoring alert that has not cleared, a
        // person pressing send again. The failure mode of guessing is silent
        // and unrecoverable — mail accepted with a `250` and then discarded —
        // while the failure mode of not guessing is a duplicate the recipient
        // can see and delete.
        //
        // Deduplication is safe in exactly two places: inside one accepted
        // transaction, where Pigeon knows the recipients belong to one
        // submission, and against an explicit idempotency identity, which
        // inbound SMTP does not carry.
        let tmp = TempDir::new("duplicate");
        let (s, db) = queued_sink(tmp.path());

        for _ in 0..2 {
            accept_message(&s, "alice@remote.test", &["hello@example.com"])
                .await
                .expect("both submissions should be accepted");
        }

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            messages, 2,
            "a repeated submission was suppressed; the sender was told 250 for a message \
             that will never arrive"
        );

        let deliveries: i64 = conn
            .query_row("SELECT count(*) FROM delivery", [], |r| r.get(0))
            .unwrap();
        assert_eq!(deliveries, 2, "the second submission got no delivery");
    }

    #[tokio::test]
    async fn each_managed_domain_is_accepted_as_its_own_message() {
        // R-2 through the real path: one submission, two managed domains, two
        // messages with their own bytes and their own delivery sets — and no
        // deduplication across them, because the sender addressed two
        // recipients and the two relay forms are signed under different
        // identities.
        let tmp = TempDir::new("split");
        let (s, db) = queued_sink_for(
            tmp.path(),
            vec![
                test_domain("one.example", "shared@provider.example"),
                test_domain("two.example", "shared@provider.example"),
            ],
        );

        accept_message(&s, "alice@remote.test", &["a@one.example", "b@two.example"])
            .await
            .expect("the message should be accepted");

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 2, "the submission did not split by domain");

        let deliveries: i64 = conn
            .query_row("SELECT count(*) FROM delivery", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            deliveries, 2,
            "one mailbox reached from two domains was deduplicated across messages"
        );

        // Each message carries only its own recipient.
        let mut stmt = conn
            .prepare(
                "SELECT m.id, o.address FROM message m
                   JOIN original_recipient o ON o.message_id = m.id
                  ORDER BY m.id, o.address",
            )
            .unwrap();
        let pairs: Vec<(i64, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            pairs,
            vec![
                (1, "a@one.example".to_string()),
                (2, "b@two.example".to_string())
            ]
        );

        // Two spool files, one per group: separate bytes, separately signed.
        let spooled = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".eml"))
            .count();
        assert_eq!(spooled, 2, "the two groups shared one set of bytes");
    }

    #[tokio::test]
    async fn a_bounce_is_admitted_with_an_empty_return_path() {
        // The null sender is a fact the queue has to carry: §9 owes no report
        // for a message that is itself a bounce, and that rule reads
        // `return_path`.
        let tmp = TempDir::new("bounce");
        let (s, db) = queued_sink(tmp.path());

        accept_message(&s, "", &["hello@example.com"])
            .await
            .expect("a bounce should be accepted");

        let conn = pigeon_db::open(&db).unwrap();
        let return_path: String = conn
            .query_row("SELECT return_path FROM message", [], |r| r.get(0))
            .unwrap();
        assert!(return_path.is_empty(), "a bounce gained a return path");
    }

    #[tokio::test]
    async fn an_admission_that_cannot_commit_says_whether_the_file_may_go() {
        // The rule the acceptance path turns on. A collision is established
        // non-commit, so the spool files are orphans and may be removed.
        let tmp = TempDir::new("collide");
        let (s, _db) = queued_sink(tmp.path());
        let id = s.next_id();
        let envelope = Envelope {
            sender: "SRS0=x@pigeon.test".into(),
            recipients: vec!["hello@example.com".into()],
        };
        let runtime = s.auth.runtime.pin();
        let prepared = vec![prepared_group(
            &id,
            one_destination("example.com", "hello@example.com", "m@provider.example"),
        )];

        let admission = || Admission {
            prepared: &prepared,
            envelope: &envelope,
            original_sender: "a@remote.test",
            routing: &runtime,
        };

        s.admit(admission()).await.expect("first admission");

        let (why, removable) = s
            .admit(admission())
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
        let (s, _db) = queued_sink(tmp.path());
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| s.next_id()).collect();
        assert_eq!(ids.len(), 1000, "identifier collision within one run");
    }

    #[tokio::test]
    async fn rcpt_is_answered_from_the_routing_table() {
        // The mapping the sink owns: what routing decides becomes what the
        // sender is told, and the difference between the two refusals matters.
        // A permanent refusal for a gated domain would tell a sender to give up
        // on a mailbox that is about to work.
        let tmp = TempDir::new("rcpt");
        let (s, _db) = queued_sink_for(
            tmp.path(),
            vec![
                test_domain("example.com", "mailbox@provider.example"),
                {
                    let mut gated = test_domain("gated.example", "mailbox@provider.example");
                    gated.gate.inbound_enabled = false;
                    gated
                },
                {
                    // A domain with no catch-all and no alias: carried, but
                    // nothing routes.
                    let mut empty = test_domain("empty.example", "mailbox@provider.example");
                    empty.catchall = None;
                    empty
                },
            ],
        );

        let mut txn = s.begin(
            "192.0.2.10:2525".parse().unwrap(),
            "alice@remote.test",
            None,
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@example.com", &[])
                .await,
            Recipient::Accept
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@unmanaged.example", &[])
                .await,
            Recipient::Reject,
            "an unmanaged domain was not refused permanently"
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@empty.example", &[])
                .await,
            Recipient::Reject,
            "an address nothing routes was not refused permanently"
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@gated.example", &[])
                .await,
            Recipient::Defer,
            "a gated domain was refused permanently"
        );
    }

    #[tokio::test]
    async fn a_gated_domain_is_refused_before_the_message_is_taken() {
        // Gating decides at `RCPT`, which is the last moment refusing is the
        // upstream MTA's problem. A domain switched off must never reach the
        // point where Pigeon owes a bounce for it.
        let tmp = TempDir::new("gate-before-250");
        let (s, db) = queued_sink_for(
            tmp.path(),
            vec![{
                let mut gated = test_domain("gated.example", "mailbox@provider.example");
                gated.gate.inbound_enabled = false;
                gated
            }],
        );

        let mut txn = s.begin(
            "192.0.2.10:2525".parse().unwrap(),
            "alice@remote.test",
            None,
        );
        assert_eq!(
            s.accepts_recipient(&mut txn, "hello@gated.example", &[])
                .await,
            Recipient::Defer
        );

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0, "a refused recipient reached the queue");
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

    /// Drive the real server, the real sink and the real delivery worker
    /// against a scripted peer.
    ///
    /// The resolver is fake and the port is injected, so no DNS is consulted
    /// and nothing leaves the loopback interface — but every other component is
    /// the production one, including the queue the message is accepted into and
    /// the worker that sends it. There is no configuration in which acceptance
    /// or forwarding happens any other way.
    async fn spawn_daemon(
        dir: &Path,
        peer_addr: SocketAddr,
    ) -> (SocketAddr, Arc<PathBuf>, delivery::Deliverer) {
        spawn_wired(
            dir,
            peer_addr,
            e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true),
            TOTAL_FORWARD_BUDGET,
        )
        .await
    }

    async fn spawn_authenticated(
        dir: &Path,
        peer_addr: SocketAddr,
        auth: Auth,
    ) -> (SocketAddr, Arc<PathBuf>, delivery::Deliverer) {
        spawn_wired(dir, peer_addr, auth, TOTAL_FORWARD_BUDGET).await
    }

    async fn spawn_wired(
        dir: &Path,
        peer_addr: SocketAddr,
        auth: Auth,
        budget: Duration,
    ) -> (SocketAddr, Arc<PathBuf>, delivery::Deliverer) {
        use pigeon_dns::{FakeResolver, MxRecord};

        let spool_dir = Arc::new(dir.to_path_buf());
        let db = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&db).expect("open");
        pigeon_db::migrate(&mut conn, &db).expect("migrate");
        let queue = Queue {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            path: Arc::new(db),
        };
        let spool = pigeon_spool::Spool::new(spool_dir.as_path());

        let sink = SpoolSink {
            queue: queue.clone(),
            auth: auth.clone(),
            spool: spool.clone(),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x0bad_cafe,
            abuse: no_abuse_controls(),
            disk: Arc::new(Disk::new(dir.to_path_buf(), 0)),
        };

        let deliverer = delivery::Deliverer::start(delivery::DeliveryConfig {
            queue,
            srs: Arc::clone(&auth.runtime.pin().srs),
            hostname: "pigeon.test".into(),
            spool,
            forwarding: Forwarding {
                tls: pigeon_smtp::tls::outbound(),
                identity: SelfIdentity::default(),
                resolver: Arc::new(FakeResolver::new().with(
                    "example.net",
                    vec![MxRecord::new(10, peer_addr.ip().to_string())],
                )),
                ehlo_name: "pigeon.test".into(),
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: peer_addr.port(),
                budget,
            },
            concurrency: MAX_CONCURRENT_DELIVERIES,
            lease_seconds: CLAIM_LEASE.as_secs() as i64,
            horizon_seconds: GIVE_UP_AFTER.as_secs() as i64,
            retain_seconds: RETAIN_RECORDS_FOR.as_secs() as i64,
            worker: "test-worker".into(),
        });

        // The same return-path check production installs (R-4): a sender whose
        // rewritten address will not fit is refused at `RCPT`, which is the
        // last moment that refusal is the upstream MTA's problem.
        let checked = Arc::clone(&auth.runtime);
        let return_path = Some(Arc::new(move |sender: &str| {
            let srs = Arc::clone(&checked.pin().srs);
            let (local, domain) = sender.rsplit_once('@').unwrap_or((sender, ""));
            match srs.forward(local, domain, pigeon_auth::Day::now()) {
                Err(pigeon_auth::SrsError::TooLong { octets }) => Err(octets),
                _ => Ok(()),
            }
        })
            as Arc<pigeon_smtp::server::SharedReturnPathCheck>);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = ServerConfig {
            hostname: "pigeon.test".into(),
            return_path,
            ..ServerConfig::default()
        };
        tokio::spawn(async move {
            let _ = pigeon_smtp::serve(listener, config, sink).await;
        });
        (addr, spool_dir, deliverer)
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

        auth_for(
            vec![DomainInput {
                name: domain.into(),
                gate: pigeon_types::DomainGate {
                    status: pigeon_types::DomainStatus::Active,
                    inbound_enabled: true,
                    outbound_enabled: false,
                },
                plus_addressing: true,
                forwarding: RouteForwarding {
                    policy,
                    dkim: vec![DkimIdentity {
                        selector: "sel".into(),
                        private_key_path: "unused-in-test".into(),
                        algorithm: "rsa2048".into(),
                    }],
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
            }],
            with_key,
        )
    }

    /// The authentication machinery a wired daemon builds at startup, over a
    /// snapshot constructed directly — the same type `load` produces.
    ///
    /// `with_key` false is how the "signing fails at runtime" case is reached:
    /// startup validation makes it unreachable in production, so a test has to
    /// assemble it deliberately.
    fn auth_for(domains: Vec<pigeon_route::snapshot::DomainInput>, with_key: bool) -> Auth {
        let snapshot = pigeon_route::Snapshot::build(domains)
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
                        vec![
                            pigeon_auth::pipeline::SigningKey::from_pkcs8_pem(
                                e2e_key(),
                                domain,
                                "sel",
                            )
                            .unwrap(),
                        ],
                    );
                }
            }
            let text =
                std::fs::read_to_string(&derive_path).map_err(|e| format!("fixture ring: {e}"))?;
            let ring =
                pigeon_auth::KeyRing::parse(&text).map_err(|e| format!("fixture ring: {e}"))?;
            Ok(Derived {
                keys,
                srs: Arc::new(pigeon_auth::Srs::new(ring, "pigeon.test")),
                ring: Some(digest(text.as_bytes())),
            })
        });

        let derived = derive(&snapshot).expect("the fixture should derive");

        Auth {
            pipeline: Arc::new(pigeon_auth::pipeline::Pipeline::new(
                // Offline: what these tests assert is what the daemon does with
                // a message, not what the machine's resolver says about one.
                pigeon_testkit::dns::offline_verifier(),
                "pigeon.test",
            )),
            runtime: Arc::new(RuntimeState {
                coordinator: std::sync::Mutex::new({
                    let mut baseline = pigeon_route::Baseline::new(0);
                    baseline.published(snapshot.fingerprint());
                    baseline
                }),
                ring_fingerprint: std::sync::Mutex::new(derived.ring),
                current: std::sync::RwLock::new(Arc::new(Runtime::assemble(snapshot, derived, 0))),
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
                dkim: vec![DkimIdentity {
                    selector: "sel".into(),
                    private_key_path: "unused-in-test".into(),
                    algorithm: "rsa2048".into(),
                }],
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
                    dkim: vec![DkimIdentity {
                        selector: "sel".into(),
                        private_key_path: "unused-in-test".into(),
                        algorithm: "rsa2048".into(),
                    }],
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
    ) -> (SocketAddr, Arc<PathBuf>, delivery::Deliverer) {
        spawn_wired(dir, peer_addr, auth, TOTAL_FORWARD_BUDGET).await
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
        let (addr, spool, _deliverer) = spawn_authenticated(
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
        let (addr, spool, _deliverer) = spawn_authenticated(
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
        let (addr, spool, _deliverer) = spawn_authenticated(
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
        let (addr, spool, _deliverer) = spawn_authenticated(
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
            coordinator: std::sync::Mutex::new(pigeon_route::Baseline::new(0)),
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
        let (addr, spool, _deliverer) = spawn_authenticated(
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
        let (addr, spool, _deliverer) = spawn_authenticated(tmp.path(), peer_addr, auth).await;

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
    async fn data_consumes_the_decisions_rcpt_made_and_makes_none_of_its_own() {
        // The boundary: `DATA` reads what `RCPT TO` decided. An envelope
        // carrying an address the sink never accepted is a wiring bug, and the
        // answer to a bug at the acceptance boundary is a transient failure —
        // never a fresh lookup, which would queue mail for a recipient that was
        // never acknowledged and could resolve differently from the decision
        // the sender was answered on.
        let tmp = TempDir::new("data-consumes");
        let (s, db) = queued_sink(tmp.path());

        // One recipient routed, two in the envelope.
        let txn = transaction_for(&s, &["hello@example.com"]).await;

        let outcome = s
            .deliver_inner(
                txn,
                Message {
                    envelope: Envelope {
                        sender: "alice@remote.test".into(),
                        recipients: vec![
                            "hello@example.com".into(),
                            "never-routed@example.com".into(),
                        ],
                    },
                    peer: "192.0.2.10".parse().unwrap(),
                    helo: "sender.example".into(),
                    received: "Received: from sender.example\r\n".into(),
                    body: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
                },
            )
            .await;

        assert!(
            matches!(outcome, Err(DataError::Temporary)),
            "an unrouted recipient was accepted: {outcome:?}"
        );

        let conn = pigeon_db::open(&db).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0, "a routing decision was invented at DATA");
    }

    #[tokio::test]
    async fn a_reload_between_rcpt_and_data_does_not_change_where_mail_goes() {
        // R-1 seen through the pin. The recipient is accepted against one
        // table; the destination then changes before the body arrives. The
        // message must go where the decision that accepted it said, because
        // re-resolving would deliver to a mailbox the sender was never told
        // about and make "where did this go?" unanswerable afterwards.
        let tmp = TempDir::new("pin-destination");
        let (s, db) = queued_sink(tmp.path());

        // Routed here, against the table in force now.
        let txn = transaction_for(&s, &["hello@example.com"]).await;

        // The reload lands between `RCPT TO` and `DATA`.
        pigeon_route::Publish::publish(
            s.auth.runtime.as_ref(),
            pigeon_route::Snapshot::build(vec![test_domain(
                "example.com",
                "somewhere-else@provider.example",
            )])
            .unwrap()
            .snapshot,
        )
        .expect("the fixture should publish");

        s.deliver_inner(
            txn,
            Message {
                envelope: Envelope {
                    sender: "alice@remote.test".into(),
                    recipients: vec!["hello@example.com".into()],
                },
                peer: "192.0.2.10".parse().unwrap(),
                helo: "sender.example".into(),
                received: "Received: from sender.example\r\n".into(),
                body: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
            },
        )
        .await
        .expect("the message should be accepted");

        let conn = pigeon_db::open(&db).unwrap();
        let destination: String = conn
            .query_row("SELECT destination FROM delivery", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            destination, "mailbox@provider.example",
            "the message was re-resolved against a table that never accepted it"
        );

        // And the new table is in force for the *next* transaction, so the test
        // cannot pass by the publication having done nothing.
        let next = transaction_for(&s, &["hello@example.com"]).await;
        let groups = next
            .plan
            .groups(&["hello@example.com".to_string()])
            .expect("routed");
        assert_eq!(
            groups[0].destinations[0].address,
            "somewhere-else@provider.example"
        );
    }

    #[test]
    fn nothing_is_accepted_or_forwarded_from_the_environment() {
        // The Milestone 0 runtime is retired, and this is what keeps it that
        // way. `SpoolSink` no longer *has* an optional queue, routing table or
        // destination, so a daemon that accepts mail without them cannot be
        // constructed — but a new environment variable could reintroduce a
        // second answer to "who is accepted?" or "where does this go?" without
        // touching those types.
        //
        // So the source is checked for what it reads: one variable, naming the
        // configuration file, and nothing else.
        let source = include_str!("main.rs");
        // Assembled rather than written out, so this check does not match
        // itself and pass by describing what it is looking for.
        let needle = format!("std::env::{}(", "var");
        let mut read: Vec<&str> = source
            .match_indices(needle.as_str())
            .map(|(at, _)| {
                let rest = &source[at + needle.len()..];
                rest.split('"').nth(1).unwrap_or("<not a literal>")
            })
            .collect();
        read.sort();
        read.dedup();
        assert_eq!(
            read,
            vec!["PIGEON_CONFIG"],
            "the daemon reads configuration from the environment beyond the config file"
        );
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
        let (addr, spool, _deliverer) = spawn_authenticated(tmp.path(), peer_addr, auth).await;

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
    async fn two_managed_domains_are_accepted_and_split() {
        // R-2, through a real SMTP conversation. The previous behaviour
        // deferred the second domain and asked the sender to send it again,
        // because one set of bytes cannot carry two signing identities. The
        // split removes the restriction rather than the reason: both
        // recipients are accepted, and each domain's mail becomes its own
        // message with its own bytes.
        let tmp = TempDir::new("e2e-two-domains");
        let (peer_addr, _transcript) = pigeon_testkit::Peer::accepting().spawn().await;

        let mut auth = e2e_auth("example.com", pigeon_types::ForwardPolicy::Preserve, true);
        // A second managed domain in the same table.
        auth = second_domain(auth, "other.example");

        let (addr, _spool, _deliverer) = spawn_two_domain_daemon(tmp.path(), peer_addr, auth).await;

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
            code, 250,
            "a second managed domain was not accepted: {code} {text}"
        );

        c.send(b"DATA\r\n").await.expect("data");
        assert_eq!(c.read_reply().await.expect("data reply").0, 354);
        c.send(b"From: <sender@remote.test>\r\nSubject: hi\r\n\r\nbody line\r\n.\r\n")
            .await
            .expect("body");
        assert_eq!(
            c.read_reply().await.expect("accept reply").0,
            250,
            "the split submission was not acknowledged"
        );

        let conn = pigeon_db::open(&tmp.path().join("pigeon.db")).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 2, "one submission did not become two messages");
    }

    #[tokio::test]
    async fn rewrite_from_replaces_the_sender_and_signs_with_the_domains_key() {
        // The other policy, end to end. The rewritten address is in the domain
        // that signs it — that alignment is the entire point, since an
        // unaligned pass changes nothing for DMARC.
        let tmp = TempDir::new("e2e-rewrite");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool, _deliverer) = spawn_authenticated(
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
        let (addr, spool, _deliverer) = spawn_authenticated(
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

        // No message was written. The database files share the directory, so
        // what is asserted is the absence of message bodies rather than of
        // everything.
        let mut entries = tokio::fs::read_dir(spool.as_path()).await.expect("spool");
        let mut spooled = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".eml") || name.ends_with(".tmp") {
                spooled.push(name);
            }
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
        let (addr, spool, _deliverer) = spawn_daemon(tmp.path(), peer_addr).await;

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
        // The return path is Pigeon's, not the sender's: SRS rewrites it once,
        // at acceptance, so the bounce comes back here and can be reversed.
        assert!(
            transcript
                .lines()
                .iter()
                .any(|l| l.starts_with("MAIL FROM:<SRS0=")),
            "the envelope sender was not rewritten: {:?}",
            transcript.lines()
        );
        // Readdressed to where *routing* sent it, which is the whole point:
        // the destination came from the table, not from configuration naming
        // one mailbox.
        assert!(
            transcript.saw("RCPT TO:<me@example.net>"),
            "not readdressed to the routed destination: {:?}",
            transcript.lines()
        );

        // The body that arrived, carrying the trace header Pigeon prepended
        // and the ARC set that seals it. The seal is written above the trace
        // header — newest first, which is the order every hop adds to.
        let body = transcript
            .lines()
            .into_iter()
            .find(|l| l.contains("body line"))
            .expect("body never reached the peer");
        assert!(
            body.starts_with("ARC-Seal:"),
            "the message was not sealed: {body:?}"
        );
        let trace = body
            .find("Received: from sender.test")
            .expect("no trace header");
        let subject = body
            .find("Subject: hi")
            .expect("the message lost its subject");
        assert!(
            trace < subject,
            "the trace header is not above the message it describes"
        );
    }

    #[tokio::test]
    async fn a_sender_that_cannot_be_rewritten_is_refused_at_rcpt() {
        // R-4. A return path that will not fit in a 64-octet local part is a
        // failure Pigeon can predict, so it is answered during the
        // conversation — where the refusal is still the upstream MTA's
        // problem. After the `250` the only remaining answer is a bounce
        // Pigeon has to generate and deliver itself.
        let tmp = TempDir::new("e2e-srs-length");
        let (peer_addr, _transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, _spool, _deliverer) = spawn_daemon(tmp.path(), peer_addr).await;

        let long = format!("{}@a-fairly-long-domain.example", "x".repeat(60));

        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        c.read_reply().await.expect("banner");
        c.send(b"EHLO sender.test\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(format!("MAIL FROM:<{long}>\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(
            c.read_reply().await.expect("mail reply").0,
            250,
            "the sender is only a problem for a recipient that would be forwarded"
        );
        c.send(b"RCPT TO:<hello@example.com>\r\n").await.unwrap();
        let (code, text) = c.read_reply().await.expect("rcpt reply");
        assert_eq!(
            code / 100,
            5,
            "an unrewritable sender was not refused at RCPT: {code} {text}"
        );

        // And nothing was taken on: no rows, so no obligation to report.
        let conn = pigeon_db::open(&tmp.path().join("pigeon.db")).unwrap();
        let messages: i64 = conn
            .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
            .unwrap();
        assert_eq!(messages, 0, "a refused sender still reached the queue");
    }

    #[tokio::test]
    async fn a_refused_recipient_never_reaches_the_spool() {
        let tmp = TempDir::new("e2e-refused");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool, _deliverer) = spawn_daemon(tmp.path(), peer_addr).await;

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

        let (addr, spool, _deliverer) = spawn_daemon(tmp.path(), peer_addr).await;
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

    // ------------------------------------------------- delivery-side loop check

    /// A forwarder that treats `127.0.0.1:port` as this host.
    fn looping_forwarder(
        port: u16,
        exchangers: Vec<pigeon_dns::MxRecord>,
    ) -> Forwarding<pigeon_dns::FakeResolver> {
        Forwarding {
            tls: pigeon_smtp::tls::outbound(),
            identity: SelfIdentity::new(format!("127.0.0.1:{port}").parse().unwrap(), &[]),
            resolver: Arc::new(pigeon_dns::FakeResolver::new().with("example.net", exchangers)),
            ehlo_name: "pigeon.test".into(),
            limit: Arc::new(Semaphore::new(1)),
            port,
            budget: Duration::from_secs(5),
        }
    }

    #[test]
    fn an_address_is_this_host_by_address_and_port() {
        // The comparison is on where the packets would go, and both halves
        // matter: `127.0.0.1:2526` is not this daemon when it serves
        // `127.0.0.1:2525`, and treating it as such would refuse to deliver to
        // a neighbouring service.
        let id = SelfIdentity::new("127.0.0.1:2525".parse().unwrap(), &[]);
        assert!(id.is_self("127.0.0.1:2525".parse().unwrap()));
        assert!(!id.is_self("127.0.0.1:2526".parse().unwrap()));
        assert!(!id.is_self("198.51.100.7:2525".parse().unwrap()));

        // IPv4-mapped IPv6 is the same host reached two ways. A resolver that
        // returned the mapped form would otherwise walk straight past the
        // check.
        assert!(
            id.is_self("[::ffff:127.0.0.1]:2525".parse().unwrap()),
            "an IPv4-mapped address was not recognised"
        );

        // And the same in the other direction: configured as mapped, seen as
        // plain.
        let mapped = SelfIdentity::new(
            "0.0.0.0:2525".parse().unwrap(),
            &["::ffff:198.51.100.7".parse().unwrap()],
        );
        assert!(mapped.is_self("198.51.100.7:2525".parse().unwrap()));
    }

    #[test]
    fn a_wildcard_listener_knows_only_loopback_and_what_it_was_told() {
        // Behind NAT, or on a multi-homed host, the address the world's DNS
        // points at cannot be inferred from a wildcard bind — which is the
        // whole reason `self_addresses` exists.
        let wildcard = SelfIdentity::new("0.0.0.0:25".parse().unwrap(), &[]);
        assert!(wildcard.is_self("127.0.0.1:25".parse().unwrap()));
        assert!(wildcard.is_self("[::1]:25".parse().unwrap()));
        assert!(
            !wildcard.is_self("198.51.100.7:25".parse().unwrap()),
            "a wildcard bind claimed an address it cannot know it has"
        );

        let told = SelfIdentity::new(
            "0.0.0.0:25".parse().unwrap(),
            &["198.51.100.7".parse().unwrap()],
        );
        assert!(told.is_self("198.51.100.7:25".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_self_exchanger_is_skipped_and_a_real_one_is_used() {
        // A domain whose MX list includes this host *and* a real one is an
        // ordinary secondary-MX arrangement. The mail belongs at the other
        // host, and refusing the whole delivery would bounce mail that has a
        // perfectly good place to go.
        //
        // The self entry is listed first, so the check has to skip it and carry
        // on rather than deciding on the primary alone.
        //
        // What this pins is the fallthrough: that one self exchanger does not
        // condemn the whole delivery. It cannot also pin the skip itself —
        // nothing is listening at the self address, so a delivery that tried it
        // anyway would fail and move on to the same place. The skip is pinned
        // by `every_exchanger_being_this_host_is_a_permanent_loop`, where
        // trying it is the difference between a loop and a connection.
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;

        let mut f = looping_forwarder(
            peer_addr.port(),
            vec![
                // Us: nothing is listening there, so a delivery that tried it
                // would fail rather than quietly succeed.
                pigeon_dns::MxRecord::new(10, "127.0.0.2".to_string()),
                // The real one.
                pigeon_dns::MxRecord::new(20, "127.0.0.1".to_string()),
            ],
        );
        f.identity = SelfIdentity::new(
            format!("127.0.0.2:{}", peer_addr.port()).parse().unwrap(),
            &[],
        );

        forward(&f, 0, "dest@example.net", "s@remote.test", b"body\r\n")
            .await
            .expect("the secondary exchanger should have taken the message");
        assert!(
            transcript.saw("MAIL FROM"),
            "the message never reached the exchanger that is not us"
        );
    }

    #[tokio::test]
    async fn a_self_address_is_removed_from_an_exchangers_address_set() {
        // One hostname, two addresses: this host first, a real server second.
        // The self address is *listening*, so a delivery that merely decided
        // "this exchanger is usable because one of its addresses is not us" and
        // then connected to the list in order would reach the wrong machine —
        // which is Pigeon itself, and the loop this check exists to prevent.
        //
        // The all-self test proves an exchanger can be skipped whole. This one
        // proves the filtering is per address.
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;

        // A second listener on the same port at a different address, standing
        // in for this daemon's own. It answers nothing: what is asserted is
        // that nobody knocks.
        let (self_ip, trap) = bind_beside(peer_addr.port()).await;
        let knocked = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&knocked);
        tokio::spawn(async move {
            while let Ok((stream, _)) = trap.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });

        let f = Forwarding {
            tls: pigeon_smtp::tls::outbound(),
            identity: SelfIdentity::new(std::net::SocketAddr::new(self_ip, peer_addr.port()), &[]),
            resolver: Arc::new(
                pigeon_dns::FakeResolver::new()
                    .with(
                        "example.net",
                        vec![pigeon_dns::MxRecord::new(10, "mx.example.net".to_string())],
                    )
                    // Self first, deliberately: a filter that only looked at
                    // the first address, or that connected in order once the
                    // set was judged usable, would take this one.
                    .with_addresses("mx.example.net", vec![self_ip, peer_addr.ip()]),
            ),
            ehlo_name: "pigeon.test".into(),
            limit: Arc::new(Semaphore::new(1)),
            port: peer_addr.port(),
            budget: Duration::from_secs(5),
        };

        forward(&f, 0, "dest@example.net", "s@remote.test", b"body\r\n")
            .await
            .expect("the external address should have taken the message");

        assert!(
            transcript.saw("MAIL FROM"),
            "the message never reached the address that is not us: {:?}",
            transcript.lines()
        );
        assert_eq!(
            knocked.load(Ordering::SeqCst),
            0,
            "a connection was made to this host's own address"
        );
    }

    /// A listener on `port` at an address that is not `127.0.0.1`.
    ///
    /// The IPv6 loopback first, since it is present on every machine this runs
    /// on and can share a port with the IPv4 one. `127.0.0.2` is the fallback:
    /// Linux routes the whole of `127/8` locally, though macOS does not bind it
    /// without an alias.
    async fn bind_beside(port: u16) -> (std::net::IpAddr, TcpListener) {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        for candidate in [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ] {
            if let Ok(l) = TcpListener::bind((candidate, port)).await {
                return (candidate, l);
            }
        }
        panic!("no second loopback address could be bound beside 127.0.0.1:{port}");
    }

    #[tokio::test]
    async fn every_exchanger_being_this_host_is_a_permanent_loop() {
        // The case the check exists for. Without it each pass is a real
        // delivery back into Pigeon's own listener, and the message goes round
        // until the inbound hop limit stops it a hundred deliveries later.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let f = looping_forwarder(
            port,
            vec![
                pigeon_dns::MxRecord::new(10, "127.0.0.1".to_string()),
                // A name for the same host: the comparison is on the resolved
                // address, so an alias does not get past it.
                pigeon_dns::MxRecord::new(20, "localhost".to_string()),
            ],
        );

        let err = forward(&f, 0, "dest@example.net", "s@remote.test", b"body\r\n")
            .await
            .expect_err("delivering to ourselves should not succeed");

        assert!(
            matches!(err, ForwardError::Loop(_)),
            "a loop was not reported as one: {err}"
        );
        assert!(err.is_permanent(), "a routing loop is not worth retrying");
    }

    #[tokio::test]
    async fn an_exchanger_that_cannot_be_resolved_is_transient_not_a_loop() {
        // Resolver uncertainty says nothing about whether a host is us.
        // Calling it a loop would bounce deliverable mail on the strength of a
        // DNS failure.
        let f = looping_forwarder(
            25,
            vec![pigeon_dns::MxRecord::new(
                10,
                "no-such-host.invalid".to_string(),
            )],
        );

        let err = forward(&f, 0, "dest@example.net", "s@remote.test", b"body\r\n")
            .await
            .expect_err("an unresolvable exchanger cannot deliver");

        assert!(
            !err.is_permanent(),
            "an unresolved name was treated as evidence of a loop: {err}"
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
            tls: pigeon_smtp::tls::outbound(),
            identity: SelfIdentity::default(),
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
            limit: Arc::new(Semaphore::new(1)),
            port: peer_addr.port(),
            budget: Duration::from_millis(400),
        };

        let envelope = Envelope {
            sender: "s@remote.test".into(),
            recipients: vec!["hello@example.com".into()],
        };

        let started = std::time::Instant::now();
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
            tls: pigeon_smtp::tls::outbound(),
            identity: SelfIdentity::default(),
            resolver: Arc::new(resolver),
            ehlo_name: "pigeon.test".into(),
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
