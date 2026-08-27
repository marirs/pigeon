# Architecture

## 1. Overview

Pigeon is a single-host-first mail routing service composed of a Rust daemon, SQLite control database, durable mail spool, DNS validator, inbound forwarding engine, and outbound submission/delivery engine.

The initial architecture deliberately avoids a web UI, external database, message broker, Redis, or separate control-plane service.

```text
                         ┌──────────────────────────┐
                         │          DNS             │
                         │ MX / SPF / DKIM / DMARC  │
                         └────────────┬─────────────┘
                                      │
                              validation/lookups
                                      │
┌─────────────────┐        ┌──────────▼──────────┐
│ Internet sender │─SMTP25→│       Pigeon        │
└─────────────────┘        │                     │
                           │  SMTP receiver      │
┌─────────────────┐        │  submission server │
│ Mail client/app │─587───→│  route engine      │
└─────────────────┘        │  auth/policy       │
                           │  DKIM/ARC/SRS       │
                           │  queue workers      │
                           └──────┬───────┬──────┘
                                  │       │
                         ┌────────▼──┐ ┌──▼───────────┐
                         │ SQLite DB │ │ Durable spool│
                         └───────────┘ └──────────────┘
                                  │       │
                         ┌────────▼───────▼────────┐
                         │    Delivery engine     │
                         └──────────┬──────────────┘
                                    │
                         ┌──────────┴───────────┐
                         │                      │
                  forwarding target      recipient MX
                  or upstream relay       direct SMTP
```

## 2. Runtime components

### 2.1 SMTP receiver

Listens on TCP/25.

Responsibilities:

- connection policy
- SMTP state machine
- STARTTLS where configured
- envelope parsing
- recipient validation
- message size enforcement
- basic protocol abuse limits
- durable spool
- queue insertion

Unknown recipients should normally be rejected at `RCPT TO`, before the sender transmits DATA.

### 2.2 Submission server

Listens on TCP/587.

Responsibilities:

- require STARTTLS
- authenticate a Pigeon credential
- determine authorized sender identities
- validate envelope sender
- validate `From:` policy
- reject unauthorized domain use
- spool outbound submission
- enqueue for delivery

Port 587 is for authenticated message submission, not public MTA-to-MTA receipt.

### 2.3 Routing engine

Loads an immutable routing snapshot from SQLite.

For inbound recipients:

```text
explicit reject
    ↓
exact alias
    ↓
catch-all
    ↓
unknown recipient reject
```

For outbound submission:

```text
authenticated principal
    ↓
allowed sender identity
    ↓
domain ACTIVE and outbound enabled
    ↓
message accepted
```

### 2.4 DNS validator

Checks required and advisory DNS state.

Inbound checks:

- MX
- A/AAAA
- hostname
- PTR
- TLS

Outbound/authentication checks:

- SPF authorization
- DKIM public key
- DMARC
- selector correctness

The validator distinguishes:

- FATAL
- ERROR
- WARNING
- INFO

### 2.5 Authentication engine

Inbound forwarded mail may require:

- SPF evaluation at receipt
- DKIM verification
- DMARC evaluation
- Authentication-Results
- ARC validation and sealing
- sender rewriting

Outbound originated mail requires:

- DKIM signing
- correct envelope identity
- SPF-compatible sending host
- DMARC-aligned From domain

### 2.6 Durable spool

Mail bytes should not be stored inside SQLite.

SQLite stores metadata and queue state. Message bodies live in a durable spool directory.

Suggested flow:

```text
receive DATA
   ↓
write temporary file
   ↓
fsync file
   ↓
atomic rename into spool
   ↓
SQLite transaction creates queue entry
   ↓
SMTP 250 accepted
```

The system must not send `250 OK` before it can recover the accepted message after a process crash.

### 2.6.1 Retention

Pigeon is a relay, not a mailbox. A message body is deleted once every recipient reaches a terminal state.

Delivery *metadata* — envelope, recipients, outcome, SMTP response — is retained separately with configurable retention. Without it, queue inspection and post-incident debugging are guesswork.

One consequence follows directly: because nothing is archived, `DEAD` is irreversible. The retry schedule is therefore deliberately generous (the ~5 day SMTP convention) before a message is abandoned.

A second consequence shapes the receiver. Anything accepted and later undeliverable must be bounced, and bouncing mail that should have been refused makes Pigeon a backscatter source. This is why recipient rejection at `RCPT TO` is a correctness requirement rather than an optimisation.

### 2.7 Queue workers

Workers claim due messages using a lease.

States:

```text
QUEUED
DELIVERING
DEFERRED
DELIVERED
BOUNCED
DEAD
```

Worker crashes must allow lease expiry and safe retry.

### 2.8 SQLite

SQLite stores:

- domains
- aliases
- destinations
- sender identities
- submission credentials
- domain policy
- DNS check state
- queue metadata
- delivery attempts
- settings
- migration state

WAL mode is appropriate for the expected single-host workload.

## 3. Process model

### 3.1 Crate layout

Pigeon is a Cargo workspace. The split follows subsystem boundaries so that each piece can be tested in isolation and compiled in parallel.

```text
pigeon-types      core types, no I/O, no runtime
pigeon-config     bootstrap TOML and its validation
pigeon-db         SQLite, migrations, repositories
pigeon-dns        resolution and record validation
pigeon-auth       DKIM, SPF, DMARC, ARC, SRS
pigeon-route      routing snapshot and precedence
pigeon-smtp       receiver state machine and delivery client
pigeon-spool      durable spool, queue leases, retries
pigeon-testkit    scriptable SMTP peer, fake resolver, fixtures
pigeond           the daemon binary
pigeon-cli        the `pigeon` binary
```

The dependency graph is acyclic and shallow: everything depends on `pigeon-types`, `pigeon-route` and `pigeon-spool` additionally depend on `pigeon-db`, and only the two binaries depend on more than that.

### 3.2 Zero-copy handling

Message bytes are copied as few times as possible.

- SMTP commands are parsed from `&[u8]` without intermediate `String` allocation.
- Addresses borrow subslices of the parse buffer; plus-tag stripping is a subslice, not a new allocation.
- DATA is read into `BytesMut` and frozen into `Bytes`, so fanning one message out to N destinations costs N refcount bumps rather than N copies.
- Message parsing borrows from the input buffer rather than allocating.
- Body hashing for DKIM and ARC is streamed; a message is canonicalised and hashed without materialising a second copy.

Where a value must cross a task boundary or outlive its buffer, a refcounted handle is preferred over a borrow — lifetimes across `await` points cost more in complexity than they return in performance.

One copy of the body is unavoidable and should be understood rather than chased. Removing dot-stuffing deletes bytes from the stream, so the result is not a subslice of the input and cannot alias it. The goal is that it happens exactly once, after which the body is refcounted for the rest of its life.

Envelopes are the other deliberate exception: a sender and its recipients outlive the command lines they were parsed from, so they are owned. That is a few small allocations per transaction, not per byte.

### 3.4 Dependency policy

Pigeon does not link OpenSSL. CI fails the build if `openssl-sys` enters the dependency graph, directly or transitively, and `deny.toml` bans it declaratively.

The objection is not to C code. It is to *system-library coupling*: locating a shared object at build time, matching its version across build and deployment hosts, and inheriting a distribution's patch schedule. Two dependencies do contain C, and neither has those properties:

| Dependency | Why C | Why acceptable |
|---|---|---|
| SQLite via `rusqlite` with `bundled` | SQLite is written in C | Vendored source compiled with `cc`. No system library, no pkg-config, no version skew. |
| TLS crypto via `ring` | C and assembly from BoringSSL | Vendored. Chosen over rustls 0.23's default `aws-lc-rs`, which additionally requires cmake. |

rustls itself, `mail-auth`, `mail-parser`, `hickory-resolver` and the async stack are pure Rust. The pure-Rust rustls crypto provider exists but is explicitly not audited for production, which is not a trade worth making for a mail server's transport security.

If either C dependency later becomes avoidable without giving something up — a mature pure-Rust SQLite, or an audited pure-Rust crypto provider — the ban list makes the switch a one-line change rather than an archaeology exercise.

### 3.3 Runtime

Initial implementation:

```text
one pigeon process
  ├── SMTP/25 listener
  ├── SMTP/587 listener
  ├── DNS checker
  ├── queue scheduler
  ├── delivery workers
  └── local admin CLI interface
```

The CLI may either:

1. open SQLite directly for offline commands, or
2. communicate with the running daemon through a local Unix socket for commands requiring runtime coordination.

Preferred model:

- read-only CLI commands may read SQLite directly
- mutating commands use the daemon Unix socket when running
- offline mutation is permitted only when daemon is stopped

This avoids competing writers and allows runtime validation before commit.

## 4. Configuration model

Machine bootstrap configuration lives in a small TOML file.

Example:

```toml
hostname = "mx1.yourserver.net"
database = "/var/lib/pigeon/pigeon.db"
spool = "/var/spool/pigeon"

[smtp.inbound]
listen = "0.0.0.0:25"

[smtp.submission]
listen = "0.0.0.0:587"
require_starttls = true
```

Mail-domain configuration does not live in TOML.

It lives in SQLite and is changed through `pigeon domain ...`, `pigeon sender ...`, and related commands.

## 5. Domain lifecycle

```text
NEW
 │
 ▼
PENDING_DNS
 │
 ▼
READY
 │
 ▼
ACTIVE
 │
 ├──→ SUSPENDED
 │
 └──→ ERROR
```

`ACTIVE` is the only state allowed to receive production mail.

Outbound may have a separate enable flag because a domain can be valid for inbound forwarding but intentionally disabled for sending.

### 5.1 Startup gating

Onboarding is strict: a domain reaches `ACTIVE` only by passing every required DNS check, with no manual override.

That strictness belongs on the domain lifecycle, not on process startup. Two classes of failure are treated differently:

**Local and unambiguous — abort startup.**

- unreadable database
- failed migration
- unwritable or unusable spool
- invalid TLS configuration for a required listener
- missing DKIM private key for a signing domain
- listener that will not bind

These are misconfiguration. Running half-configured is worse than not running.

**Remote DNS state — gate the domain, keep serving.**

A domain whose records regress moves to `ERROR` and stops accepting its own mail. The daemon still starts and every other domain is unaffected.

The failure mode this avoids is specific and severe: if DNS validation gated process startup, a transient resolver outage would take down mail for *every* domain on the host simultaneously, and it would happen at the least convenient moment. One misconfigured domain out of forty must never be a total outage.

This is consistent with `SECURITY.md`: temporary external DNS issues degrade checks rather than destroy runtime state.

## 6. Outbound delivery modes

### Direct

```text
Pigeon → DNS MX lookup → recipient MX:25
```

Advantages:

- no external delivery provider
- fully self-hosted

Costs:

- IP reputation
- reverse DNS
- port 25 availability
- bounce handling
- provider-specific deliverability behavior

### Relay

```text
Pigeon → authenticated smarthost → recipient
```

Advantages:

- easier deliverability
- works when outbound port 25 is blocked
- provider handles IP reputation

Pigeon remains responsible for identity policy and can either DKIM-sign itself or use a configured provider signing model.

## 7. Failure philosophy

Pigeon follows four rules:

1. **Reject before acceptance when possible.**
2. **After acceptance, queue rather than lose.**
3. **Retry transient failures.**
4. **Surface permanent failures explicitly.**

## 8. High availability

High availability is intentionally deferred.

The first stable architecture targets one authoritative node with reliable backups.

A future two-node design must address:

- configuration replication
- queue ownership
- duplicate prevention
- DKIM key distribution
- credential distribution
- failover semantics

Adding a second MX record alone is not considered sufficient HA design.
