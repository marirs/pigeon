//! Sending one message to one destination.
//!
//! The delivery path itself: pick a mail exchanger, refuse to deliver to this
//! host, connect, and hand the message to the SMTP client. It lives here rather
//! than in the daemon so there is exactly one of it — the queue worker and
//! `pigeon alerts test` send mail the same way, and a second implementation
//! would be a second set of answers to "which host, and is it us?".
//!
//! Choosing *what* to send and *when* is not here. That is the queue's, and it
//! is deliberately on the other side of this boundary.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pigeon_dns::{LookupError, MxError, MxLookup, order_hosts};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::session::Envelope;

/// How long to wait for a TCP connection to one host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Where forwarded mail is sent, and who we claim to be when sending it.
///
/// Generic over the resolver so delivery can be driven by `FakeResolver` in
/// tests. `MxLookup` returns `impl Future`, so it is not dyn-compatible and a
/// type parameter is the way to get the seam.
pub struct Forwarding<R: MxLookup> {
    pub resolver: Arc<R>,
    /// How outbound `STARTTLS` is negotiated. Shared, and built once: see
    /// `pigeon_smtp::tls::outbound` for why the peer is not authenticated.
    pub tls: Arc<rustls::ClientConfig>,
    /// Which addresses are this host, so delivery can refuse to loop back to
    /// it.
    pub identity: SelfIdentity,
    /// Name given in EHLO. Its forward and reverse DNS must agree with the
    /// sending address or receivers will treat everything as suspect.
    pub ehlo_name: String,
    pub limit: Arc<Semaphore>,
    /// Always 25 in production. Injectable so a test can point the delivery
    /// path at a scripted peer on an ephemeral port instead of at the internet.
    pub port: u16,
    /// How long one message may spend being forwarded, across every host.
    ///
    /// A field rather than a constant for the same reason as `port`: a
    /// half-hour bound cannot be asserted against in a test suite, and a
    /// defence that is never exercised is one this project has repeatedly
    /// found to be broken.
    pub budget: Duration,
}

// Derived `Clone` would demand `R: Clone`, which the resolver need not be —
// every field is already shared behind an `Arc`.
impl<R: MxLookup> Clone for Forwarding<R> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            tls: Arc::clone(&self.tls),
            identity: self.identity.clone(),
            ehlo_name: self.ehlo_name.clone(),
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
pub enum ForwardError {
    /// Retrying will not help. Bounce rather than queue.
    Permanent(String),
    /// Worth trying again later.
    Transient(String),
    /// Every usable mail exchanger is this host.
    ///
    /// Permanent, and kept separate from [`Self::Permanent`] because the sender
    /// is told a different thing: a remote refusal is about their recipient,
    /// while this is about a configuration on *this* side that sends a domain's
    /// mail back to the machine that forwards it. RFC 3463 has a status for
    /// exactly that, and a report saying "no such user" would send the sender
    /// looking for a mailbox that is fine.
    Loop(String),
}

impl ForwardError {
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_) | Self::Loop(_))
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permanent(m) => write!(f, "permanent: {m}"),
            Self::Transient(m) => write!(f, "transient: {m}"),
            Self::Loop(m) => write!(f, "routing loop: {m}"),
        }
    }
}

/// Which socket addresses are this daemon.
///
/// Used to refuse delivering to ourselves. An MX that resolves back here means
/// the message would be accepted again, forwarded again, and go round until the
/// inbound hop limit stops it — one delivery attempt per pass, each one real
/// mail leaving and re-entering.
///
/// # Addresses, and the port with them
///
/// Compared against the addresses a connection would actually be made to —
/// never against reverse DNS or the peer's banner, both of which are the
/// remote's to write and neither of which says where the packets went.
///
/// The port is part of the identity because the question is "would this
/// connection be answered by us?", and the answer for `127.0.0.1:2526` when
/// this daemon serves `127.0.0.1:2525` is no. Delivery always goes to the MX
/// port, so in production this is the listener's port and the check is exactly
/// "is that MX us".
#[derive(Debug, Clone, Default)]
pub struct SelfIdentity {
    pub addresses: std::collections::HashSet<std::net::IpAddr>,
    pub port: u16,
}

impl SelfIdentity {
    /// What the daemon can work out about itself, plus what it was told.
    ///
    /// A wildcard listener means every local address reaches this process, and
    /// the loopback addresses are the ones it can name without asking the
    /// operating system for its interfaces. The address the world's DNS points
    /// at — behind NAT, or on a multi-homed host — cannot be inferred from a
    /// wildcard bind at all, which is why `self_addresses` exists.
    pub fn new(listen: std::net::SocketAddr, configured: &[std::net::IpAddr]) -> Self {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let mut addresses: std::collections::HashSet<IpAddr> =
            configured.iter().map(|a| a.to_canonical()).collect();

        if listen.ip().is_unspecified() {
            addresses.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
            addresses.insert(IpAddr::V6(Ipv6Addr::LOCALHOST).to_canonical());
        } else {
            addresses.insert(listen.ip().to_canonical());
        }

        Self {
            addresses,
            port: listen.port(),
        }
    }

    /// Whether a connection to this address would come back to us.
    ///
    /// `to_canonical` first: `::ffff:127.0.0.1` and `127.0.0.1` are the same
    /// host reached two ways, and a comparison that missed that would be
    /// defeated by a resolver returning the mapped form.
    pub fn is_self(&self, addr: std::net::SocketAddr) -> bool {
        addr.port() == self.port && self.addresses.contains(&addr.ip().to_canonical())
    }
}

/// Send one message onward.
///
/// Hosts are tried in preference order, but only for failures worth retrying.
/// A permanent rejection stops the attempt immediately: the backup MX for a
/// domain answers from the same mailbox database as the primary, so asking it
/// about a recipient the primary just refused only wastes time and makes the
/// sender look like it is probing.
pub async fn forward<R: MxLookup>(
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

    // Whether every candidate so far was *demonstrably* this host. A single
    // host that could not be resolved, or that has one address elsewhere,
    // clears it: "we could not reach anyone" and "everyone is us" are different
    // answers, and only the second is a loop.
    let mut all_self = true;

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

        // Resolved here rather than inside `connect`, for two reasons. The
        // addresses are what the loop check compares — not the name, not the
        // peer's reverse DNS, not its banner, none of which say where the
        // packets went. And resolving once means the address checked is the
        // address connected to: resolving again inside `connect` could land on
        // a different one.
        let resolved = tokio::time::timeout(
            CONNECT_TIMEOUT.min(remaining),
            f.resolver.lookup_addresses(host, f.port),
        )
        .await;

        let addresses: Vec<std::net::SocketAddr> = match resolved {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(e)) => {
                // Uncertainty is transient and is *not* evidence of a loop: a
                // resolver that cannot answer has said nothing about whether
                // this host is us.
                all_self = false;
                last = ForwardError::Transient(format!("{host}: {e}"));
                tracing::warn!(%host, error = %e, "cannot resolve, trying next host");
                continue;
            }
            Err(_) => {
                all_self = false;
                last = ForwardError::Transient(format!("{host}: resolution timed out"));
                tracing::warn!(%host, "resolution timed out, trying next host");
                continue;
            }
        };

        // Self addresses are skipped rather than fatal: a domain whose MX list
        // includes this host *and* a real one is a normal secondary-MX setup,
        // and the mail belongs at the other host.
        let elsewhere: Vec<std::net::SocketAddr> = addresses
            .iter()
            .copied()
            .filter(|a| !f.identity.is_self(*a))
            .collect();

        if elsewhere.is_empty() && !addresses.is_empty() {
            tracing::warn!(%host, "skipping a mail exchanger that resolves back to this host");
            last = ForwardError::Permanent(format!(
                "{host} resolves only to this host: mail for {destination} would loop"
            ));
            continue;
        }
        if addresses.is_empty() {
            all_self = false;
            last = ForwardError::Transient(format!("{host}: resolved to no addresses"));
            continue;
        }
        all_self = false;

        let connect = tokio::time::timeout(
            CONNECT_TIMEOUT.min(remaining),
            TcpStream::connect(&elsewhere[..]),
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
            crate::client::deliver(
                stream,
                &f.ehlo_name,
                &outgoing,
                &parts,
                // Encrypt whenever this host says it can. Built once at
                // startup and shared: a client configuration per delivery
                // would rebuild the cipher suite list for every message.
                Some(crate::client::Tls {
                    config: Arc::clone(&f.tls),
                    server_name: host.as_str(),
                }),
            ),
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

    // Every usable target was this host. Permanent, and reported as a routing
    // loop (RFC 3463 §3.5, 5.4.6): the configuration says this domain's mail
    // comes here and also that it goes there, and no retry resolves that — each
    // pass would be a real delivery back into Pigeon's own listener, stopped
    // only by the inbound hop limit a hundred passes later.
    //
    // The sender is owed a report, which the permanent classification is what
    // arranges.
    if all_self && !hosts.is_empty() {
        return Err(ForwardError::Loop(format!(
            "every mail exchanger for {destination} resolves to this host"
        )));
    }

    Err(last)
}
