# Pigeon Roadmap

This roadmap prioritises correctness and mail reliability over feature breadth.

It is sequenced as a **vertical slice**: get one message from a real sender to a real mailbox early, then harden. Building complete horizontal layers first would mean not forwarding a single message until most of the work was already done, and the hardest question — does forwarded mail actually survive? — would go unanswered the longest.

---

## Milestone 0 — End-to-end skeleton

- [x] Cargo workspace, CI, formatting, linting, dependency audit
- [x] release profile
- [x] structured logging
- [x] SMTP listener on TCP/25
- [x] EHLO / MAIL FROM / RCPT TO / DATA / QUIT
- [x] hardcoded in-memory route
- [x] MX resolution for the destination
- [x] relay bytes to the recipient's MX
- [x] scriptable SMTP peer in `pigeon-testkit`
- [x] fuzz targets for the command parser, both stream framers, the address
      validator and the delivery client

Exit criteria:

A message sent to a test domain arrives in a real mailbox. No queue, no persistence, no authentication. Ugly and working.

Expect this to deliver to a permissive destination and be rejected by a strict one. That is the correct result at this stage — Milestone 0 proves the plumbing, Milestone 2 proves the product.

**Confirm outbound TCP/25 is permitted on the host before starting.** Everything downstream assumes it.

### What actually shipped

The protocol core, codecs, delivery client and MX ordering are pure — no I/O, no runtime — and carry roughly 90 tests that need neither a network nor a fixture server. That was not tidiness for its own sake: the cases that matter are the ones a live connection cannot be made to produce on demand, such as an end-of-data marker split across two reads.

Two harnesses, because they catch different things. Integration tests run against the real server on an ephemeral port, which is where the pipelining bugs live — those only appear when a genuine client writes a whole transaction in one packet. `pigeon-testkit` provides the opposite: a scripted peer that misbehaves on purpose, for testing the delivery client against servers that reject `EHLO`, answer 4xx, hang up mid-reply, or emit nonsense.

The peer deliberately does not depend on `pigeon-smtp`. It scans for the end-of-data marker itself, so a codec looking for the wrong bytes cannot agree with itself and pass.

It carries a hostile client too, for the opposite direction. The server's connection cap, command and data timeouts, and survival of an abrupt mid-body disconnect had never been exercised — defensive code that has never defended anything is worse than none, because the configuration field invites you to rely on it. The cap and the command timeout only work as a pair: without the timeout, slowloris turns the cap from a defence into the mechanism of denial.

**Relay refusal is partially covered already.** The half of the matrix needing authenticated submission waits for Milestone 7, but *unauthenticated sender, remote recipient* is live code today and is tested — including `victim@example.net.attacker.test`, the suffix trick that defeats naive domain matching. There is a paired test asserting local recipients are still accepted, since refusing everything would pass the first one perfectly.

Two boxes stay unchecked on purpose. DKIM and ARC fixtures, and malformed-DNS generators, would be written against APIs that do not exist yet — that is not coverage, it is rework scheduled early.

The peer found two bugs on first use:

- **`deliver()` had no timeouts at all.** A peer that accepted a connection and then went silent would hold a delivery task open forever: no error, no retry, a message that simply stopped moving. Every read is now bounded, as is the body write, since a peer that stops reading blocks `write_all` once socket buffers fill.
- **Invalid UTF-8 in a reply was reported as an I/O error**, which reads as a broken socket when the truth is a peer not speaking SMTP — and sends whoever reads the log to investigate the network instead of the remote server.

Deviations worth carrying forward:

- **MSRV is 1.88**, set by `hickory-resolver` 0.26 rather than by choice.
- **A twelfth crate, `pigeon-alert`**, arrived early; its design is in `ALERTING.md` and its implementation belongs to Milestone 5.
- **`DataReader` buffers the whole body in memory.** At the 50 MB ceiling that is 50 MB per concurrent connection — a denial of service, not a tuning question. Milestone 3 must make it write through to the spool.
- **The resolver classified errors by matching their text**, because hickory's error kinds looked like an unstable surface. That was wrong in a way that lost mail: NXDOMAIN and NODATA share both the variant and the `Display` string, so a domain with an A record and no MX was refused permanently and the implicit-MX fallback became dead code. Classification now reads `response_code` off the error kind. See finding 13.
- **Forwarding does not retry.** A failure logs — with its permanent/transient verdict, which is the seam the queue will act on — and leaves the message in the spool. This is the gap Milestone 3 closes.
- **The envelope sender passes through unchanged**, so SPF fails at the receiver. This is expected, and it is exactly what Milestone 2 exists to fix.

---

## Milestone 1 — Control plane

- [x] SQLite schema and migration runner
- [x] configuration loader
- [x] domain add / remove / list / show
- [x] domain lifecycle states
- [x] DKIM keypair generation (RSA-2048 default)
- [x] DKIM TXT rendering
- [x] aliases and multiple destinations
- [x] per-domain default destination, inherited by aliases
- [x] bulk destination listing and retargeting
- [x] wildcard aliases
- [x] explicit reject rules
- [x] catch-all
- [x] redundant-alias detection against catch-all
- [x] plus-addressing
- [x] loop detection at configuration time
- [x] address normalisation
- [x] route precedence
- [x] atomic routing snapshot
- [x] live config reload
- [x] `pigeon route inbound`
- [x] `--json` on every read command
- [x] bulk import from a CSV file (provider adapters are additive; see `M1-IMPORT.md` §3)

Route precedence:

```text
exact alias  →  wildcard (most literal characters)  →  catch-all  →  reject unknown
```

The most specific matching rule wins, and that rule's kind — forward or reject —
decides the result. Reject is not a tier: one pattern has exactly one rule, so
no two rules of equal specificity can both match, and a wildcard reject must not
silently disable an address the operator named explicitly. See
`M1-SNAPSHOT.md` §2.

The outbound tables — sender identities, principals, grants — are created here even though nothing uses them until Milestone 7. Retrofitting the identity model later is far more disruptive than carrying unused tables.

DKIM key generation sits here rather than with the rest of the DNS work in Milestone 5, for two reasons. `pigeon domain add` is specified to generate the key and print the record as part of adding a domain, so the key is part of the domain's creation rather than of validating it later. And Milestone 2 cannot seal an ARC set without a private key to sign with — leaving generation in Milestone 5 would have made the go/no-go milestone depend on one three steps further out.

What stays in Milestone 5 is *checking* the published record against the local key, which is validation and belongs with the other validators.

Exit criteria:

`pigeon route inbound user@example.com` exactly predicts what the routing
snapshot answers; every mutating command is refused unless the configuration it
would produce builds and validates; and an existing set of domains and aliases
can be imported in one command.

The runtime half of this — the daemon serving that snapshot — moved to Milestone
3, where the durable per-destination state it needs lives. See the note there,
and `M1-FINDINGS.md` for why.

---

## Milestone 2 — Message authentication

- [x] SRS0 encode and decode
- [x] SRS1 for double-forward chains
- [x] SRS replay window
- [x] DKIM verification on receipt
- [x] payload preservation: a conforming message is relayed byte for byte;
      bare CR/LF anywhere in the payload is transport-converted to CRLF before
      signing, and an unterminated final line gains the CRLF the end-of-data
      marker requires (`M2-DESIGN.md` §2)
- [x] SRS key ring, rotation, and the retirement barrier
- [x] DKIM signing for the `rewrite_from` path
- [x] Authentication-Results
- [x] ARC validation
- [x] ARC sealing
- [x] DMARC evaluation
- [x] `rewrite_from` fallback policy, per domain
- [x] loop detection (the trace-header cap; delivery-side detection is M3)
- [x] forwarding trace headers

**This is the go/no-go milestone.** Everything before it is plumbing and everything after it is hardening. If forwarded mail does not land with `dmarc=pass`, nothing else matters.

It depends on Milestone 1 for more than configuration: ARC sealing needs a private key, and a domain that can actually receive mail is what makes the result testable against a real mailbox rather than a fixture.

Exit criteria:

Forwarded mail is accepted with passing authentication by every major receiving provider, verified against real mailboxes rather than local tests.

**Status: implementation complete, acceptance pending — and the gate is
waived.**

The operator's standing decision is that live mailbox testing happens when the
product is complete, not before. Milestone 3 therefore proceeds with the risk
accepted explicitly: everything built on top of this assumes bytes no provider
has yet accepted, and if a provider objects to something structural — the ARC
set, the `From:` rewrite — the work above it is unwound rather than adjusted.

That is a deliberate choice, recorded here so it stays one.

Every item above is built and tested. The pipeline is wired into the delivery
path and its output is verified cryptographically rather than by inspection —
the tests parse what the daemon actually transmitted and validate the ARC set
and the DKIM signature against the test key, offline.

What has *not* happened is the exit criterion itself: no message has been
forwarded to a real mailbox at a real provider. That needs a domain, published
DNS records and an internet-facing host, none of which exist yet.

This milestone calls itself go/no-go, so the distinction matters. Nothing below
this line should be treated as building on proven ground: every provider has
acceptance behaviour that no local test reproduces, and finding out during
Milestone 5 that Gmail dislikes something about the ARC set means unwinding
work built on top of it. Proceeding to Milestone 3 before this is run is a
deliberate risk, taken with the failure mode stated: **durability built around
mail that providers reject.**

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
- [x] delivery metadata retention
- [x] duplicate suppression (declined by policy: §6.2 — safe only within one
      accepted transaction, which is what the acceptance path already does)
- [ ] loop detection at delivery, as a backstop for chains leaving and
      re-entering through systems Pigeon cannot see
- [x] STARTTLS
- [x] SMTP timeouts, connection and size limits
- [x] malformed message handling
- [x] graceful shutdown

- [x] a routing revision counter, bumped by triggers on the routing tables, so
      queue commits stop waking the reload loader — with a single ordering for
      publication that reconciliation does not have to bypass, since a restore
      can present the same revision over different rows (`M1-RELOAD.md` C-1..3)
- [x] the daemon's RCPT accept/reject decision and resolved destination set come
      from the routing snapshot, replacing `PIGEON_ACCEPT` and
      `PIGEON_FORWARD_TO`

Exit criteria:

Killing the process mid-delivery loses no accepted mail, and transient destination failures resolve themselves without intervention.

The daemon's `RCPT` accept/reject decision and resolved destination set come
from the routing snapshot. Each resolved destination has independently
retryable queue state, and `pigeon route inbound` predicts that decision and
destination set exactly.

The routing revision arrives with the queue for a reason. Live reload polls
`data_version`, which moves on *every* commit to the database — so the moment
the queue shares that file, a busy relay would make the detector load and hash
the routing tables once a second to conclude each time that nothing routing-
related had changed. A counter bumped only when routing changes makes the
doorbell selective. See `M1-RELOAD.md` §2.

This arrived from Milestone 1, which could not meet it: fan-out belongs here
because safe retries require independently durable destination state. Note what
it does *and does not* claim — the CLI predicts the routing decision and the
destinations it resolves to. It cannot predict DNS or a remote server's answer,
and "runtime routing" and "per-destination outcome" were both ambiguous about
that.

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
- [ ] optional ed25519 second selector
- [ ] DKIM selector validation against the published record
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
- [ ] anti-open-relay integration suite — the unauthenticated half landed in
      Milestone 0; what remains is every combination involving an authenticated
      principal, which needs the submission listener to exist first
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
