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
hostname = "mx1.pigeon.mx"
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
