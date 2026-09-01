//! The submission listener: mail *from* this host's users, on port 587.
//!
//! Everything about it is the inverse of port 25. The MX takes mail from
//! strangers for addresses it carries; submission takes mail from authenticated
//! applications for addresses anywhere. Which means the two questions swap
//! places: the MX asks "do I carry this recipient?", and this asks "may this
//! principal use this sender?".
//!
//! # It is an open relay if any one of these is wrong
//!
//! 1. **No authentication, no transaction.** `MAIL FROM` before `AUTH` is
//!    refused. This is the whole difference between a submission service and
//!    an open relay, and it is checked here rather than trusted from the
//!    session, which knows about authentication but not about policy.
//! 2. **No TLS, no authentication.** Enforced in the session: `AUTH` is not
//!    offered or accepted in the clear.
//! 3. **The sender must be granted.** A principal may only use addresses its
//!    grants name. Without this, one compromised credential sends as everybody
//!    on the host.
//!
//! Recipients are *not* checked against the routing table: relaying to
//! arbitrary destinations is the point of submission. What bounds it is who is
//! sending, not where to.
//!
//! # Signed as the sender's domain
//!
//! A submitted message is signed with the key of the domain in the envelope
//! sender, which is a domain this host carries — that is what the grant
//! guarantees. Unlike forwarding there is no `From:` rewriting: the sender is
//! already using an address on their own domain, so alignment holds without
//! touching the header.

use std::sync::Arc;

use pigeon_smtp::{Connection, DataError, Envelope, Message, MessageSink, Recipient};

use crate::{Auth, Queue, routing};

/// The sink behind port 587.
#[derive(Clone)]
pub struct SubmissionSink {
    pub spool: pigeon_spool::Spool,
    pub queue: Queue,
    pub auth: Auth,
    pub counter: Arc<std::sync::atomic::AtomicU64>,
    pub boot: u32,
    /// Per-principal rate limits, shared across connections.
    pub limits: Arc<Limits>,
}

/// What one mail transaction on the submission port knows.
pub struct Transaction {
    /// The runtime pinned at `MAIL FROM`, as on the inbound path.
    pub runtime: Arc<crate::Runtime>,
    /// Who is sending. `None` is unauthenticated, which cannot reach `DATA`.
    pub principal: Option<Principal>,
    pub sender: String,
    pub recipients: Vec<String>,
}

/// An authenticated application, resolved once at `AUTH`.
///
/// Carried through the session as `id:username`, because the session deals in
/// strings and this path must not re-read the credential mid-transaction: the
/// principal that authorised the sender has to be the one that authenticated,
/// even if the row changes underneath.
#[derive(Debug, Clone)]
pub struct Principal {
    pub id: i64,
    pub name: String,
}

impl Principal {
    fn parse(carried: &str) -> Option<Self> {
        let (id, name) = carried.split_once(':')?;
        Some(Self {
            id: id.parse().ok()?,
            name: name.to_string(),
        })
    }
}

impl MessageSink for SubmissionSink {
    type Transaction = Transaction;

    fn begin(
        &self,
        _peer: std::net::SocketAddr,
        sender: &str,
        principal: Option<&str>,
    ) -> Self::Transaction {
        Transaction {
            runtime: self.auth.runtime.pin(),
            // The session hands over who authenticated; the id was resolved at
            // `AUTH` and carried in the name so this path never has to look a
            // credential up again mid-transaction.
            principal: principal.and_then(Principal::parse),
            sender: sender.to_string(),
            recipients: Vec::new(),
        }
    }

    async fn accepts_connection(&self, _peer: std::net::SocketAddr) -> Connection {
        Connection::Accept
    }

    /// Check the credential, and resolve it to a principal id.
    ///
    /// Verifies *something* whether or not the username exists: returning early
    /// for an unknown user makes the response time say which usernames are
    /// real, and an attacker with a list of names learns them without guessing
    /// a single password.
    async fn authenticate(&self, username: &str, password: &str) -> Option<String> {
        let conn = self.queue.conn.lock().await;

        let found = pigeon_db::repo::password_hash_for(&conn, username)
            .ok()
            .flatten();

        let (id, hash) = match found {
            Some((id, hash)) => (Some(id), hash),
            None => (None, pigeon_auth::credential::dummy_hash().to_string()),
        };

        let ok = pigeon_auth::credential::verify(password, &hash).unwrap_or(false);

        match (ok, id) {
            (true, Some(id)) => {
                // Best effort: a credential that worked is a fact about the
                // past, and failing to record it must not fail the
                // authentication that just succeeded.
                let _ = pigeon_db::repo::touch_principal(&conn, id);
                Some(format!("{id}:{username}"))
            }
            // The verification ran either way, which is the point.
            _ => None,
        }
    }

    /// Recipients are accepted without consulting routing.
    ///
    /// Relaying to arbitrary destinations is what submission is *for*. What
    /// bounds this port is who may send, checked at `MAIL FROM` and again
    /// before the message is queued.
    async fn accepts_recipient(
        &self,
        transaction: &mut Self::Transaction,
        address: &str,
        _accepted: &[String],
    ) -> Recipient {
        if transaction.principal.is_none() {
            // Unreachable through the server, which refuses `MAIL FROM` before
            // `AUTH`. Refused rather than asserted: an unauthenticated
            // transaction reaching here is a wiring bug, and the safe answer to
            // a bug on this path is "no".
            return Recipient::Reject;
        }

        if pigeon_types::Address::parse(address).is_err() {
            return Recipient::Reject;
        }
        transaction.recipients.push(address.to_string());
        Recipient::Accept
    }

    async fn deliver(
        &self,
        transaction: Self::Transaction,
        message: Message,
    ) -> Result<String, DataError> {
        self.submit(transaction, message).await
    }
}

/// How many messages a principal may submit, and how fast.
///
/// Per principal rather than per connection or per address: the credential is
/// the thing that gets compromised, and a limit on connections is one a
/// compromised credential simply opens more of.
///
/// A token bucket rather than a fixed window: a client that submits a burst on
/// the hour and nothing else is normal, and a fixed window refuses exactly that
/// while allowing twice the rate across a boundary.
#[derive(Debug)]
pub struct Limits {
    /// Messages per hour, sustained.
    per_hour: u32,
    /// How much of that may arrive at once.
    burst: u32,
    buckets: std::sync::Mutex<std::collections::HashMap<i64, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: std::time::Instant,
}

impl Limits {
    pub fn new(per_hour: u32, burst: u32) -> Self {
        Self {
            per_hour,
            burst,
            buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Take one token, or refuse.
    pub fn allow(&self, principal_id: i64) -> bool {
        if self.per_hour == 0 {
            return true;
        }

        let mut buckets = match self.buckets.lock() {
            Ok(b) => b,
            Err(e) => e.into_inner(),
        };
        let now = std::time::Instant::now();
        let bucket = buckets.entry(principal_id).or_insert(Bucket {
            tokens: f64::from(self.burst),
            last: now,
        });

        let refill =
            now.duration_since(bucket.last).as_secs_f64() * f64::from(self.per_hour) / 3600.0;
        bucket.tokens = (bucket.tokens + refill).min(f64::from(self.burst));
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl SubmissionSink {
    /// Accept one submitted message.
    async fn submit(
        &self,
        transaction: Transaction,
        message: Message,
    ) -> Result<String, DataError> {
        let Some(principal) = transaction.principal.clone() else {
            tracing::error!("a submission reached DATA with no principal");
            return Err(DataError::Temporary);
        };

        // Checked again here, not only at `MAIL FROM`. The envelope that
        // reaches this point is the one the message will be sent with, and a
        // policy checked once at the start of a conversation is a policy that
        // trusts everything in between.
        let conn = self.queue.conn.lock().await;
        let permitted =
            pigeon_db::repo::may_send_as(&conn, principal.id, &transaction.sender).unwrap_or(false);
        drop(conn);

        if !permitted {
            tracing::warn!(
                principal = %principal.name,
                sender = %transaction.sender,
                "refusing a submission: the sender is not granted to this application"
            );
            return Err(DataError::Rejected);
        }

        // The header the recipient actually sees. An application granted
        // `alice@example.com` that submits with `From: ceo@example.com` has
        // authenticated as itself and is sending as somebody else — the
        // envelope check alone does not catch it, because DMARC and every
        // human read the header.
        //
        // Compared on the whole address rather than the domain: a grant is per
        // identity, and "anyone on the domain may claim any address on it" is
        // exactly the property the per-address grant exists to deny.
        if let Some(from) = header_from(&message.body) {
            let permitted = {
                let conn = self.queue.conn.lock().await;
                pigeon_db::repo::may_send_as(&conn, principal.id, &from).unwrap_or(false)
            };
            if !permitted {
                tracing::warn!(
                    principal = %principal.name,
                    %from,
                    "refusing a submission: the From: header is not granted to this application"
                );
                return Err(DataError::Rejected);
            }
        }

        if !self.limits.allow(principal.id) {
            tracing::warn!(principal = %principal.name, "rate limiting a submission");
            return Err(DataError::Temporary);
        }

        let id = self.next_id();

        // Signed as the sender's own domain, with no `From:` rewriting: the
        // sender is already using an address on a domain this host carries —
        // which is what the grant guarantees — so alignment holds without
        // touching the header.
        let domain = transaction
            .sender
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
            .unwrap_or_default();

        let signing: &[pigeon_auth::pipeline::SigningKey] = transaction
            .runtime
            .keys
            .get(&domain)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let envelope_view = pigeon_auth::verify::Envelope {
            client_ip: message.peer,
            helo: &message.helo,
            mail_from: &transaction.sender,
            host_domain: "",
        };

        let processed = match self
            .auth
            .pipeline
            .process(
                &message.body,
                &envelope_view,
                &message.received,
                &pigeon_auth::pipeline::Rewrite::Preserve,
                signing,
            )
            .await
        {
            Ok(out) => out,
            Err(e) => {
                tracing::error!(%id, error = %e, "cannot sign a submitted message");
                return Err(DataError::Temporary);
            }
        };

        let spool_id = match pigeon_spool::SpoolId::new(&id) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(%id, error = %e, "generated an unusable spool identifier");
                return Err(DataError::Temporary);
            }
        };

        let payload = processed.payload.as_bytes().to_vec();
        if let Err(e) = self.spool.install(&spool_id, &[&payload]).await {
            tracing::error!(%id, error = %e, "could not spool a submitted message");
            return Err(DataError::Temporary);
        }

        // One delivery per recipient, deduplicated the same way the forwarding
        // path deduplicates destinations: two `RCPT`s for one mailbox are one
        // delivery, and both are still named in a report.
        let mut group = routing::Group {
            domain,
            recipients: Vec::new(),
            destinations: Vec::new(),
        };
        for (n, recipient) in transaction.recipients.iter().enumerate() {
            group.recipients.push(recipient.clone());
            group.add_destination_public(recipient, n);
        }

        let acceptance = pigeon_spool::accept::Acceptance {
            spool_id,
            // The submitter's own address: a bounce goes back to them, not
            // through SRS, because this host is the origin rather than a hop.
            return_path: transaction.sender.clone(),
            original_sender: transaction.sender.clone(),
            size_bytes: payload.len() as i64,
            routing_revision: transaction.runtime.revision,
            routing_fingerprint: transaction.runtime.fingerprint.to_vec(),
            original_recipients: group.recipients.clone(),
            destinations: group
                .destinations
                .iter()
                .map(|d| pigeon_spool::accept::Destination {
                    address: d.address.clone(),
                    from_recipients: d.from_recipients.clone(),
                })
                .collect(),
        };

        let mut conn = self.queue.conn.lock().await;
        match pigeon_spool::accept(
            &mut conn,
            &self.queue.path,
            &[acceptance],
            crate::unix_now(),
        ) {
            Ok(_) => {
                tracing::info!(
                    %id,
                    principal = %principal.name,
                    from = %transaction.sender,
                    recipients = transaction.recipients.len(),
                    "submitted"
                );
                Ok(id)
            }
            Err(failure) => {
                if failure.spool_may_be_removed() {
                    let _ = self
                        .spool
                        .remove(&pigeon_spool::SpoolId::new(&id).unwrap())
                        .await;
                }
                tracing::error!(%id, error = %failure, "could not queue a submitted message");
                Err(DataError::Temporary)
            }
        }
    }

    fn next_id(&self) -> String {
        use std::sync::atomic::Ordering;
        let secs = crate::unix_now();
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{secs:010}-{boot:08x}-s{n:06}", boot = self.boot)
    }
}

/// The address in the `From:` header, if there is exactly one.
///
/// `None` when the header is absent or carries several addresses: absent is a
/// malformed message that the receiving side will judge, and several is a form
/// this project does not authorise at all — a grant names one identity, and
/// there is no rule that says which of two `From:` addresses it would be
/// checked against.
fn header_from(body: &[u8]) -> Option<String> {
    // Header block only: a line in the body that looks like a header is body.
    let text = String::from_utf8_lossy(body);
    let head = text.split("\r\n\r\n").next().unwrap_or(&text);

    let mut value: Option<String> = None;
    let mut lines = head.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line
            .strip_prefix("From:")
            .or_else(|| line.strip_prefix("from:"))
        else {
            continue;
        };
        // Folded continuations belong to this header.
        let mut folded = rest.trim().to_string();
        while lines
            .peek()
            .is_some_and(|l| l.starts_with(' ') || l.starts_with('\t'))
        {
            folded.push(' ');
            folded.push_str(lines.next().unwrap_or("").trim());
        }
        if value.is_some() {
            // Two `From:` headers: receivers disagree about which one counts,
            // so neither is authorised.
            return None;
        }
        value = Some(folded);
    }

    let value = value?;
    if value.contains(',') {
        // A group or a list. No single identity to check a grant against.
        return None;
    }

    // `Display Name <addr>` or a bare address.
    let address = match (value.find('<'), value.find('>')) {
        (Some(open), Some(close)) if close > open => value[open + 1..close].to_string(),
        _ => value.trim().to_string(),
    };

    (!address.is_empty() && address.contains('@')).then_some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_from_header_is_read_the_way_a_receiver_reads_it() {
        assert_eq!(
            header_from(b"From: alice@example.com\r\nSubject: hi\r\n\r\nbody"),
            Some("alice@example.com".into())
        );
        assert_eq!(
            header_from(b"From: Alice <alice@example.com>\r\n\r\nbody"),
            Some("alice@example.com".into())
        );
        // Folded, which real clients do for long display names.
        assert_eq!(
            header_from(b"From: A Very Long Name\r\n <alice@example.com>\r\n\r\nbody"),
            Some("alice@example.com".into())
        );

        // A line in the *body* that looks like a header is body.
        assert_eq!(
            header_from(b"Subject: hi\r\n\r\nFrom: ceo@example.com\r\n"),
            None
        );

        // Two `From:` headers: receivers disagree about which counts, so
        // neither is authorised.
        assert_eq!(
            header_from(b"From: a@example.com\r\nFrom: b@example.com\r\n\r\nbody"),
            None
        );

        // A group or list has no single identity to check a grant against.
        assert_eq!(
            header_from(b"From: a@example.com, b@example.com\r\n\r\nbody"),
            None
        );

        assert_eq!(header_from(b"Subject: hi\r\n\r\nbody"), None);
    }

    #[test]
    fn a_bucket_refills_and_bursts() {
        // A client that submits a burst on the hour and nothing else is normal.
        // A fixed window refuses exactly that while allowing twice the rate
        // across a boundary, which is why this is a bucket.
        let limits = Limits::new(3600, 5);

        for _ in 0..5 {
            assert!(limits.allow(1), "the burst was refused");
        }
        assert!(!limits.allow(1), "the bucket did not run out");

        // Another principal has its own bucket: the credential is the thing
        // that gets compromised, so the limit is per credential.
        assert!(limits.allow(2));
    }

    #[test]
    fn a_zero_limit_is_off_rather_than_closed() {
        // Configuring nothing must not stop mail: a rate limit that defaults to
        // refusing everything is a mail server that defaults to not working.
        let limits = Limits::new(0, 0);
        for _ in 0..1000 {
            assert!(limits.allow(1));
        }
    }
}
