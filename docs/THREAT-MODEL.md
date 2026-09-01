# Threat model

Who can attack a mail forwarder, what they want, and which of it Pigeon
actually defends against. The last part matters most: a threat model that lists
everything defends nothing, and the useful sentences here are the ones naming
what is *not* covered.

---

## What this system is

One host, reachable by anyone on the internet on port 25, that accepts mail for
domains it carries and forwards it to mailboxes elsewhere. Optionally it also
accepts authenticated submission on 587. It holds:

- **DKIM private keys** — the only state no backup of the database restores.
- **The SRS signing ring** — forging one lets an attacker have bounces accepted
  as though Pigeon issued the return path.
- **Application credentials** — Argon2id hashes, not passwords.
- **Mail in transit** — spooled bodies between acceptance and delivery.
- **Routing configuration** — who forwards where, which is a map of the
  operator's correspondents.

It does **not** hold mailboxes. Nothing is archived: a delivered message is
deleted, which bounds what a compromise yields to the queue's current contents.

---

## Adversaries

**A stranger on the internet.** The default. Can open connections, send
anything, and repeat. Wants an open relay, a way to make this host send spam
under its own reputation, or a crash.

**A sender whose mail is being forwarded.** Everything above, plus control of
the message content and headers that Pigeon signs and relays. Wants Pigeon's
signature on their bytes, or to smuggle a second message through it.

**A holder of one application credential.** Can authenticate. Wants to send as
identities they were not granted, or to send more than they should.

**A network position between Pigeon and a peer.** Can read, drop and modify.
Wants credentials, message content, or a downgrade to plaintext.

**Somebody who has the database file.** A stolen backup, a shared host, a
misconfigured volume. Wants credentials and keys.

**The operator, by accident.** Not an adversary, and the most common cause of
lost mail. Wants to not lose mail while making a mistake.

---

## What is defended, and how

| Threat | Defence | Where |
|---|---|---|
| Open relay | recipients must be carried; submission requires authentication and a grant | `pigeon-smtp/tests/relay.rs` |
| Sending as somebody else | per-identity grants, checked on the envelope **and** the `From:` header | `pigeond/src/submission.rs` |
| Credential guessing | Argon2id, a three-attempt budget per connection, unknown users cost a verification | `pigeon-auth/src/credential.rs` |
| Credential theft in transit | `AUTH` refused and unadvertised without TLS | `pigeon-smtp/src/session.rs` |
| Credential theft at rest | only Argon2id hashes are stored; relay secrets are files outside the database | schema, `pigeon-config` |
| Message smuggling | bare CR/LF converted once before signing; NUL refused | `pigeon-auth/src/normalize.rs` |
| Header injection | CRLF refused in every value that reaches a header | `pigeon-smtp/src/command.rs` |
| STARTTLS command injection | every buffered byte discarded and the session reset at upgrade | `pigeon-smtp/src/server.rs` |
| TLS downgrade, outbound | once a peer advertises STARTTLS, a failure defers rather than sending plaintext | `pigeon-smtp/src/client.rs` |
| Resource exhaustion | per-address connection cap, per-connection command cap, session lifetime, message size, recipient cap, disk floor | `pigeon-smtp/src/server.rs` |
| Directory harvesting | refusals counted cumulatively against a budget | `pigeon-smtp/src/session.rs` |
| Mail loops | trace-hop limit inbound, self-address detection at delivery | `pigeond/src/main.rs` |
| Bounce forgery | SRS tags compared in constant time | `pigeon-auth/src/srs.rs` |
| Lost mail through operator error | acceptance is durable before `250`; freezing does not stop the clock; backups verify themselves | `M3-DESIGN.md` |
| Root compromise through a parser | privilege dropped after binding | `pigeond/src/privilege.rs` |

---

## What is **not** defended

Written plainly, because each of these is a decision rather than an oversight.

**The contents of forwarded mail are not private from this host.** Pigeon reads,
signs and re-emits every message. Anyone with the spool directory has the mail
currently in flight. End-to-end encryption is the sender's business and Pigeon
neither adds nor removes it.

**Outbound TLS is unauthenticated.** Certificates are not verified on delivery:
without DANE or MTA-STS there is no authenticated name to check, and verifying
against public roots fails on a large share of real mail servers. What this buys
is protection from a passive observer, not from an active one. An attacker who
can redirect traffic *and* terminate TLS can read forwarded mail.

**Nothing defends against a hostile resolver.** DNSSEC validation is not
performed. A resolver that lies about MX records redirects mail; the loop check
and the queue's classification limit the damage but do not prevent it. Run a
resolver you trust.

**Spam filtering is not included.** The scanner hook runs whatever the operator
already has; with nothing configured, content is not examined at all.

**A compromised credential can send until it is noticed.** The rate limit bounds
volume per hour, and grants bound identity, but nothing detects that a
legitimate application has started behaving differently.

**The alert channel shares a failure domain with the thing it monitors.** Email
about broken email. If outbound port 25 is blocked or this host is listed,
alerts stop arriving and the silence looks exactly like health. `pigeon health`
and the exit codes are the authoritative signal.

**One host is one host.** A compromise of the machine is a compromise of every
domain on it, including the DKIM keys. Milestone 8's second node is about
availability and does not change this.

---

## Assumptions

- The operating system, filesystem and SQLite are trusted.
- The `keys` and `secrets` directories are readable only by Pigeon's user, which
  startup validation enforces (0700 / 0600).
- The resolver is trusted, as above.
- Clock skew is bounded. SRS tags, leases and the retry horizon are all times;
  a clock far in the past accepts expired return paths.
- The operator's own machine, from which the CLI is run, is trusted.

---

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).
