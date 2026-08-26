# Pigeon Roadmap

This roadmap prioritises correctness and mail reliability over feature breadth.

It is sequenced as a **vertical slice**: get one message from a real sender to a real mailbox early, then harden. Building complete horizontal layers first would mean not forwarding a single message until most of the work was already done, and the hardest question — does forwarded mail actually survive? — would go unanswered the longest.

---

## Milestone 0 — End-to-end skeleton

- [ ] Cargo workspace, CI, formatting, linting, dependency audit
- [ ] release profile
- [ ] structured logging
- [ ] SMTP listener on TCP/25
- [ ] EHLO / MAIL FROM / RCPT TO / DATA / QUIT
- [ ] hardcoded in-memory route
- [ ] MX resolution for the destination
- [ ] relay bytes to the recipient's MX
- [ ] scriptable SMTP peer in `pigeon-testkit`

Exit criteria:

A message sent to a test domain arrives in a real mailbox. No queue, no persistence, no authentication. Ugly and working.

Expect this to deliver to a permissive destination and be rejected by a strict one. That is the correct result at this stage — Milestone 0 proves the plumbing, Milestone 2 proves the product.

**Confirm outbound TCP/25 is permitted on the host before starting.** Everything downstream assumes it.

---

## Milestone 1 — Control plane

- [ ] SQLite schema and migration runner
- [ ] configuration loader
- [ ] domain add / remove / list / info
- [ ] domain lifecycle states
- [ ] aliases and multiple destinations
- [ ] per-domain default destination, inherited by aliases
- [ ] bulk destination listing and retargeting
- [ ] wildcard aliases
- [ ] explicit reject rules
- [ ] catch-all
- [ ] plus-addressing
- [ ] loop detection at configuration time
- [ ] address normalisation
- [ ] route precedence
- [ ] atomic routing snapshot
- [ ] live config reload
- [ ] `pigeon route inbound`
- [ ] `--json` on every read command
- [ ] bulk import from an existing forwarding provider

Route precedence:

```text
reject rule  →  exact alias  →  wildcard (longest match)  →  catch-all  →  reject unknown
```

The outbound tables — sender identities, principals, grants — are created here even though nothing uses them until Milestone 7. Retrofitting the identity model later is far more disruptive than carrying unused tables.

Exit criteria:

`pigeon route inbound user@example.com` exactly predicts runtime routing, and an existing set of domains and aliases can be imported in one command.

---

## Milestone 2 — Message authentication

- [ ] SRS0 encode and decode
- [ ] SRS1 for double-forward chains
- [ ] SRS replay window
- [ ] DKIM verification on receipt
- [ ] byte-for-byte body preservation
- [ ] Authentication-Results
- [ ] ARC validation
- [ ] ARC sealing
- [ ] DMARC evaluation
- [ ] `rewrite_from` fallback policy, per domain
- [ ] loop detection
- [ ] forwarding trace headers

**This is the go/no-go milestone.** Everything before it is plumbing and everything after it is hardening. If forwarded mail does not land with `dmarc=pass`, nothing else matters.

Exit criteria:

Forwarded mail is accepted with passing authentication by every major receiving provider, verified against real mailboxes rather than local tests.

---

## Milestone 3 — Durability

- [ ] durable spool: write, fsync, atomic rename
- [ ] acknowledge only after the queue row commits
- [ ] recipient rejection at `RCPT TO`
- [ ] lease-based queue claim
- [ ] lease expiry and safe retry
- [ ] exponential backoff
- [ ] terminal states and dead-lettering
- [ ] bounce generation via the SRS return path
- [ ] DSN generation
- [ ] body deletion once all recipients are terminal
- [ ] delivery metadata retention
- [ ] duplicate suppression
- [ ] loop detection at delivery, as a backstop for chains leaving and
      re-entering through systems Pigeon cannot see
- [ ] STARTTLS
- [ ] SMTP timeouts, connection and size limits
- [ ] malformed message handling
- [ ] graceful shutdown

Exit criteria:

Killing the process mid-delivery loses no accepted mail, and transient destination failures resolve themselves without intervention.

---

## Milestone 4 — Abuse and reputation controls

- [ ] DNSBL checks at connect time
- [ ] greylisting
- [ ] content filtering via an external scanner
- [ ] connections per IP
- [ ] commands per connection
- [ ] recipients per message
- [ ] concurrent connection limits

This milestone protects the sending reputation of the host. Forwarding unfiltered spam into a major provider is attributed to the forwarder, not the original sender, and is the fastest route to a blocklisted IP.

Rejection happens during the SMTP conversation. Accepting and then discarding is never acceptable.

---

## Milestone 5 — DNS validation

- [ ] resolver with timeout and failure handling
- [ ] MX validation
- [ ] A / AAAA resolution
- [ ] PTR validation
- [ ] hostname consistency
- [ ] SPF validation
- [ ] DKIM key generation (RSA-2048 default)
- [ ] optional ed25519 second selector
- [ ] DKIM TXT rendering
- [ ] DMARC validation
- [ ] TLS validation
- [ ] finding severities: FATAL / ERROR / WARNING / INFO
- [ ] `pigeon domain check`
- [ ] `pigeon domains check`
- [ ] startup gating per §5.1 of ARCHITECTURE
- [ ] certificate issuance and renewal
- [ ] operator alerts on domain gate and recovery
- [ ] alert transition tracking, confirmation window and cooldown
- [ ] resolver circuit breaker
- [ ] `pigeon alerts test`

RSA-2048 is the default DKIM key type. Ed25519 remains unevenly supported by receivers and is offered only as an additional selector alongside RSA, never alone.

Alerting ships alongside gating rather than later. A gated domain that nobody is told about is an outage discovered by a colleague asking why you never replied.

Exit criteria:

A fresh domain can be added, its required records printed, its DNS validated, and it can reach `ACTIVE` without anyone editing SQLite by hand. Gating a domain notifies the operator, and `pigeon alerts test` confirms the path end to end.

---

## Milestone 6 — Operations

- [ ] queue inspection
- [ ] retry one message
- [ ] retry a domain
- [ ] freeze / unfreeze
- [ ] delivery log with search
- [ ] disk pressure protection
- [ ] database integrity check
- [ ] backup command
- [ ] restore validation
- [ ] metrics endpoint, local-only by default
- [ ] health command
- [ ] systemd unit
- [ ] Docker image
- [ ] log rotation guidance
- [ ] graceful upgrades

Backup deserves specific attention. DKIM private keys are the only state that cannot be regenerated: losing them means republishing DNS for every domain by hand.

---

## Milestone 7 — Outbound sending

- [ ] submission listener on TCP/587
- [ ] STARTTLS required
- [ ] authentication
- [ ] application credentials
- [ ] password hashing and constant-time comparison
- [ ] sender identity policy
- [ ] per-domain sender allowlist
- [ ] envelope and header alignment checks
- [ ] DKIM signing
- [ ] outbound SPF guidance
- [ ] direct-to-MX delivery
- [ ] upstream smarthost delivery
- [ ] per-domain outbound mode
- [ ] outbound queue and bounce processing
- [ ] per-principal and per-domain rate limits
- [ ] anti-open-relay integration suite
- [ ] optional CLI send for diagnostics

Sequenced after forwarding because it is the larger and more security-critical body of work, and because forwarding is what breaks first in production.

Exit criteria:

A standard mail client authenticates on 587, sends as an allowed identity, receives a deterministic response, and the message is delivered directly or through a relay. The anti-open-relay suite passes.

---

## Milestone 8 — Second node

- [ ] configuration replication
- [ ] per-node identity
- [ ] shared-nothing queue behaviour
- [ ] duplicate delivery safeguards
- [ ] node health
- [ ] failover documentation
- [ ] rolling upgrade procedure

Availability for a forwarder is a easier problem than for a mailbox host: there is no shared mutable state, and a sending server delivers to exactly one MX, so duplicates do not arise naturally. The only genuinely hard part is replicating read-mostly configuration.

Given that consolidating many domains onto one host makes that host a single point of failure for all of your mail, this is worth doing earlier than its number suggests.

Adding a second MX record alone is not a high-availability design.

---

## Milestone 9 — Security hardening

- [ ] secret redaction
- [ ] key file permissions
- [ ] privilege dropping
- [ ] optional container confinement
- [ ] SMTP command fuzzing
- [ ] MIME parser fuzzing
- [ ] DNS response fuzzing
- [ ] SQLite corruption tests
- [ ] queue crash tests
- [ ] dependency review
- [ ] threat model
- [ ] responsible disclosure process

---

## Milestone 10 — Stable release

- [ ] migration compatibility policy
- [ ] semantic versioning policy
- [ ] complete CLI documentation
- [ ] deployment guide
- [ ] recovery guide
- [ ] compatibility matrix
- [ ] tagged release artefacts
- [ ] checksums and signatures
- [ ] package publishing

---

## Explicit non-goals

Unless the project direction changes, Pigeon will not become:

- a mailbox host
- an IMAP server
- a POP3 server
- webmail
- a marketing campaign platform
- a customer support inbox
- a newsletter builder
- a general CRM

A user interface is not a non-goal, but it is not part of this project. Pigeon is headless by design, and the `--json` CLI contract exists so that anything built on top can consume it across a process boundary.
