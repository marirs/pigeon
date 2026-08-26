# Pigeon Roadmap

This roadmap prioritizes correctness and mail reliability over feature breadth.

## Milestone 0 — Repository foundation

- [ ] Rust workspace
- [ ] CI
- [ ] formatting and linting
- [ ] dependency audit
- [ ] release profile
- [ ] configuration loader
- [ ] SQLite migrations
- [ ] structured logging
- [ ] command framework
- [ ] test fixtures
- [ ] documentation skeleton

Exit criteria:

- `pigeon --version`
- `pigeon check`
- database can initialize and migrate safely
- CI passes on supported Linux targets

## Milestone 1 — Domain control plane

- [ ] domain add/remove/list/info
- [ ] domain lifecycle states
- [ ] DNS resolver
- [ ] MX validation
- [ ] SPF validation
- [ ] DKIM key generation
- [ ] DKIM TXT rendering
- [ ] DMARC validation
- [ ] hostname validation
- [ ] PTR validation
- [ ] TLS validation
- [ ] `pigeon domain check`
- [ ] global `pigeon check`

Domain lifecycle:

```text
NEW
 ↓
PENDING_DNS
 ↓
READY
 ↓
ACTIVE
 ↓
SUSPENDED / ERROR
```

Exit criteria:

A fresh domain can be added from the CLI, required DNS records are printed, DNS can be validated, and the domain can transition to ACTIVE without editing SQLite manually.

## Milestone 2 — Alias routing

- [ ] aliases
- [ ] multiple destinations
- [ ] catch-all
- [ ] explicit reject routes
- [ ] route precedence
- [ ] route simulator
- [ ] atomic routing snapshot
- [ ] live config reload
- [ ] address normalization

Route precedence:

1. explicit reject
2. exact alias
3. catch-all
4. reject unknown recipient

Exit criteria:

`pigeon route test user@example.com` exactly predicts runtime recipient routing.

## Milestone 3 — SMTP receiver

- [ ] SMTP listener on TCP/25
- [ ] EHLO/HELO
- [ ] MAIL FROM
- [ ] RCPT TO
- [ ] DATA
- [ ] STARTTLS
- [ ] connection limits
- [ ] message size limits
- [ ] recipient validation before DATA
- [ ] spool before acknowledgement
- [ ] durable queue
- [ ] malformed message handling
- [ ] SMTP timeouts
- [ ] graceful shutdown

Exit criteria:

Pigeon can safely receive a message, durably spool it, acknowledge only after persistence, and reject unknown recipients during SMTP conversation.

## Milestone 4 — Forwarding engine

- [ ] destination delivery
- [ ] retry queue
- [ ] exponential backoff
- [ ] DSN generation
- [ ] loop detection
- [ ] sender rewriting
- [ ] DKIM preservation
- [ ] Authentication-Results handling
- [ ] ARC validation
- [ ] ARC sealing
- [ ] forwarding trace headers
- [ ] duplicate suppression

Exit criteria:

Forwarded mail remains deliverable through major receiving providers and transient delivery failures do not lose mail.

## Milestone 5 — Outbound sending

- [ ] SMTP submission listener on TCP/587
- [ ] STARTTLS required
- [ ] authentication
- [ ] application credentials
- [ ] sender identity policy
- [ ] per-domain sender allowlist
- [ ] envelope/header alignment checks
- [ ] DKIM signing
- [ ] outbound SPF guidance
- [ ] direct-to-MX delivery
- [ ] upstream smarthost delivery
- [ ] per-domain outbound mode
- [ ] outbound queue
- [ ] bounce processing
- [ ] retry policy
- [ ] rate limits
- [ ] outbound abuse controls
- [ ] optional CLI send for diagnostics

Exit criteria:

A configured mail client can authenticate to Pigeon on port 587, submit a message as an allowed address, receive a deterministic SMTP response, and Pigeon can deliver it directly or through a configured relay.

## Milestone 6 — Operational hardening

- [ ] queue inspection
- [ ] retry individual message
- [ ] retry domain
- [ ] freeze/unfreeze queue item
- [ ] dead-letter state
- [ ] disk pressure protection
- [ ] database integrity checks
- [ ] backup command
- [ ] restore validation
- [ ] log rotation guidance
- [ ] metrics endpoint optional and local-only by default
- [ ] health command
- [ ] systemd unit
- [ ] Docker image
- [ ] graceful upgrades

## Milestone 7 — Security hardening

- [ ] password hashing
- [ ] secret redaction
- [ ] key permissions
- [ ] privilege dropping
- [ ] optional chroot/container confinement
- [ ] anti-open-relay tests
- [ ] SMTP command fuzzing
- [ ] MIME parser fuzzing
- [ ] DNS response fuzzing
- [ ] SQLite corruption tests
- [ ] dependency review
- [ ] threat model
- [ ] security policy
- [ ] responsible disclosure process

## Milestone 8 — High availability

Not required for initial stable release.

- [ ] secondary MX
- [ ] configuration replication strategy
- [ ] per-node identity
- [ ] shared-nothing queue behavior
- [ ] duplicate delivery safeguards
- [ ] failover documentation
- [ ] node health
- [ ] rolling upgrade procedure

## Milestone 9 — Stable release

- [ ] migration compatibility policy
- [ ] semantic versioning policy
- [ ] complete CLI docs
- [ ] deployment guides
- [ ] recovery guide
- [ ] compatibility matrix
- [ ] tagged release artifacts
- [ ] checksums/signatures
- [ ] final license
- [ ] `SECURITY.md`
- [ ] package/repository publishing

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
