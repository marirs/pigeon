# Milestone 3 — Durability

Design for review. **No implementation exists, and none should begin** until the
rulings in §10 are settled and the Milestone 2 acceptance test has either passed
or been explicitly waived again. M2 is *implementation complete, acceptance
pending*: no message has reached a real mailbox at a real provider. Everything
below assumes the bytes M2 produces are acceptable to receivers, and that
assumption is unverified.

Milestone 3 is where Pigeon stops being a relay that forwards and becomes one
that *keeps its promises*. `250` is a promise: the message will be delivered or
its sender will be told why. Today Pigeon makes that promise and cannot keep it
— a failed forward logs and stops.

Companion documents: `M1-SCHEMA.md` (the schema conventions and invariants this
extends), `M1-RELOAD.md` §2 (constraints C-1 to C-3, which land here),
`M2-DESIGN.md` (what an accepted message already carries), `ARCHITECTURE.md`
§2.6–2.8, and `M0-FINDINGS.md` finding 19, which named this milestone as its
fix.

---

## 1. What has to become true

The exit criteria, restated as properties:

1. **Killing the process mid-delivery loses no accepted mail.** Anything
   answered `250` survives `SIGKILL` at any instant.
2. **Transient failures resolve without intervention.** A destination that is
   down for an hour receives the mail when it returns.
3. **Permanent failures reach the sender.** Not silence, and not a log line the
   sender cannot see.
4. **The `RCPT` decision and the destination set come from the routing
   snapshot**, replacing `PIGEON_ACCEPT` and `PIGEON_FORWARD_TO`.
5. **Each resolved destination has independently retryable state**, so a partial
   outcome is representable.

Three deferrals arrive here, each with a reason recorded where it was made:

- **Fan-out** (M1). Safe retries need independently durable destination state,
  which is what this milestone is.
- **Finding 19** (M0). A `550` on the seventh of ten recipients currently
  reports *transient* for all ten, because duplication is the recoverable
  failure and loss is not. One delivery per destination removes the trade.
- **The routing revision** (M1-RELOAD C-1..C-3). Queue commits will otherwise
  wake the reload loader once a second forever.

And one M0 deviation becomes urgent: `DataReader` buffers the whole body in
memory, so `max_message_size` is per *connection*. At 50 MB and 256 connections
that is a denial of service, not a tuning question.

---

## 2. What an accepted message already is

By the time Milestone 3 sees a message, Milestone 2 has finished with it. This
is the most important input to the design, and the easiest thing to get wrong
later.

| Property | Fixed at | Consequence for retries |
|---|---|---|
| The relay bytes | acceptance | **Never re-derived.** They carry an ARC set that signs exactly these bytes. |
| The envelope sender | acceptance | **Never recomputed.** An SRS address with a timestamp and a key. |
| The forwarding policy and signing identity | acceptance | Already applied. Nothing at delivery reads policy. |
| The trace header | acceptance | One hop, one header, however many attempts. |

So a retry is a *transmission*, not a re-processing. That is the whole shape of
the queue: the durable object is a finished message plus a set of destinations,
and delivery moves bytes.

**Corollary, and it needs stating because it looks like a bug.** If an operator
retargets an alias while a message is queued, the message still goes to the
destination that was resolved when it was accepted. The snapshot that accepted
it decided where it goes, and re-resolving at delivery would mean a message
accepted for one mailbox arriving at another — which is worse than stale, it is
a message delivered somewhere its sender was never told about. See R-1.

---

## 3. Schema

Three tables, following `M1-SCHEMA.md`'s conventions: `STRICT`, integer time,
explicit `CHECK`s on every state column, and partial indexes where a rule is
"at most one of these".

```sql
CREATE TABLE message (
    id                INTEGER PRIMARY KEY,
    -- The spool file, by generated name. Never sender or recipient text:
    -- `pigeon-spool` already refuses to build paths from either.
    spool_id          TEXT NOT NULL UNIQUE,
    -- The envelope sender as it will be transmitted: the SRS return path,
    -- computed once at acceptance (M2 §5) and stored so no retry recomputes it.
    -- Empty for a bounce Pigeon itself sends.
    return_path       TEXT NOT NULL,
    -- What the sender used, for the log and for the DSN's `Original-Recipient`
    -- style fields. Never used to address anything.
    original_sender   TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL,
    received_at       INTEGER NOT NULL,
    -- The routing revision the accept decision was made against, for the
    -- delivery log. Diagnostic, never re-resolved against.
    routing_revision  INTEGER NOT NULL,
    -- Set when every delivery is terminal and the body has been removed. The
    -- row outlives the body; see §8.
    body_deleted_at   INTEGER
) STRICT;

CREATE TABLE delivery (
    id             INTEGER PRIMARY KEY,
    message_id     INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    -- One row per resolved destination. The unit of retry, of outcome, and of
    -- everything finding 19 could not express.
    destination    TEXT NOT NULL,
    state          TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','delivering','deferred','delivered','bounced','dead')),
    attempts       INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    -- Lease. Both columns or neither; a claimed row with no expiry is a row
    -- nothing can ever reclaim.
    claimed_by     TEXT,
    lease_expires_at INTEGER,
    last_code      INTEGER,
    last_response  TEXT,
    terminal_at    INTEGER,

    UNIQUE (message_id, destination),
    CHECK ((claimed_by IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((state IN ('delivered','bounced','dead')) = (terminal_at IS NOT NULL)),
    CHECK (state <> 'delivering' OR claimed_by IS NOT NULL)
) STRICT;

-- Due work, and nothing else. A partial index because the queue is mostly
-- terminal rows after a day, and scanning them to find the few that are due is
-- the difference between a query and a table scan.
CREATE INDEX delivery_due ON delivery(next_attempt_at)
    WHERE state IN ('queued','deferred');

CREATE TABLE delivery_event (
    id           INTEGER PRIMARY KEY,
    delivery_id  INTEGER NOT NULL REFERENCES delivery(id) ON DELETE CASCADE,
    at           INTEGER NOT NULL,
    kind         TEXT NOT NULL
        CHECK (kind IN ('attempt','defer','deliver','bounce','dead','claim_expired')),
    code         INTEGER,
    response     TEXT,
    remote       TEXT
) STRICT;
```

**`UNIQUE (message_id, destination)` is the duplicate suppression**, and it is a
constraint rather than a check in code because the same destination can be
reached twice through different rules — an alias and a catch-all, or two aliases
sharing a default. Fanning out to it twice would deliver the message twice for
reasons the sender cannot see. Deduplication happens where the destinations are
resolved, and the index is what makes that a rule rather than a habit.

**`ON DELETE CASCADE` from `message`** is deliberate and narrow: deleting a
message row is only ever done by retention, which is deleting the whole record.

---

## 4. Acceptance

The ordering `ARCHITECTURE.md` §2.6 specifies, with the step that makes it
atomic:

```text
DATA received
  → pipeline (M2): verify, normalise, rewrite, sign, seal
  → write spool temp file → fsync → rename → fsync directory
  → SQLite transaction:
        insert message
        insert one delivery per resolved destination
     commit
  → 250
```

**The transaction is what the `250` promises.** Not the spool write: a body on
disk with no queue row is a file nothing will ever look at. Not the rename: the
same. The commit is the first instant at which a crash leaves something a
restart can find, so it is the last instant before the acknowledgement.

A crash *before* the commit leaves an orphaned spool file. That is the correct
failure — the sender did not get a `250` and will retry — and the file is
collected by the sweep in §8.

**Recipient rejection at `RCPT TO` is a correctness requirement, not an
optimisation** (`ARCHITECTURE.md` §2.6.1). Anything accepted and later
undeliverable must be bounced, and bouncing mail that should have been refused
makes Pigeon a backscatter source. This is why the `RCPT` decision moving to the
snapshot belongs in *this* milestone rather than being a tidy-up: the queue is
what makes a wrong acceptance expensive.

---

## 5. Fan-out and the destination set

At `RCPT TO`, the snapshot resolves the recipient to a set of destinations.
Milestone 2 narrowed this to one policy per message by deferring a second
recipient in another managed domain; that restriction lifts here.

- **One `delivery` row per resolved destination**, deduplicated (§3).
- **A recipient resolving to several destinations is several rows.** A domain
  default fanning out to three mailboxes is three independent deliveries.
- **Several recipients resolving to the same destination is one row**, because
  the message is one message and delivering it twice is a duplicate the
  recipient cannot distinguish from a loop.

Milestone 2's per-message signing identity is unchanged by this: the policy and
key come from the *recipient's* domain, and a message accepted for two managed
domains would need two signings. R-2 settles whether that means two messages or
a continued restriction.

---

## 6. Claiming, leasing, and the duplicate window

A worker claims due deliveries in one transaction:

```sql
BEGIN IMMEDIATE;
  SELECT id FROM delivery
   WHERE state IN ('queued','deferred')
     AND next_attempt_at <= :now
     AND (lease_expires_at IS NULL OR lease_expires_at <= :now)
   ORDER BY next_attempt_at
   LIMIT :batch;
  UPDATE delivery
     SET state = 'delivering', claimed_by = :worker,
         lease_expires_at = :now + :lease, attempts = attempts + 1
   WHERE id IN (...);
COMMIT;
```

`BEGIN IMMEDIATE` for the same reason `M1-SCHEMA.md` gives everywhere else: two
workers selecting the same rows and then updating them would both succeed under
deferred locking, and both would send.

**`attempts` is incremented at claim, not at completion.** A worker that dies
mid-attempt must not leave a delivery that looks untried, or a destination that
crashes Pigeon retries forever at full rate.

### 6.1 Delivery is at-least-once, and that is a choice

The window cannot be closed. Between "the remote accepted the message" and "the
row is marked delivered" there is a commit, and a crash in between means the
next lease expiry retries a message the destination already has.

The alternative — mark delivered *before* sending — turns the same crash into
mail that was accepted and never sent, which is silent loss. Finding 19 already
made this trade once, in the same words: **duplication is the recoverable
failure.** A duplicate is visible to the recipient and annoying; a loss is
invisible to everyone.

What the design does about it:

- **The window is bounded** — it is one commit, not a delivery.
- **`Message-ID` is preserved**, so a receiver's own duplicate suppression can
  work. Rewriting or adding one would defeat it.
- **A delivery already terminal is never re-sent**: the claim excludes terminal
  states, so a crash after the commit cannot resend.

Stated in `M3-FINDINGS.md` when it exists, and stated here first, because a
system that quietly duplicates and does not say so is worse than one that says
so.

---

## 7. Backoff, terminal states, and dead-lettering

| From | On | To | Next attempt |
|---|---|---|---|
| `queued`/`deferred` | claim | `delivering` | — |
| `delivering` | 2xx | `delivered` | — |
| `delivering` | 4xx, connection failure, DNS temporary | `deferred` | now + backoff |
| `delivering` | 5xx | `bounced` | — |
| `delivering` | lease expiry (worker died) | `deferred` | now + backoff |
| `deferred` | age > give-up | `dead` | — |

**Backoff is exponential with jitter, per destination**: roughly 1m, 5m, 15m,
1h, 3h, then every 6h to the give-up horizon. Jitter because a destination that
comes back after an outage would otherwise receive every deferred message at the
same instant from every sender that backs off on the same curve.

**The give-up horizon is ~5 days**, the SMTP convention, and it is generous for
a specific reason: `dead` is irreversible because Pigeon archives nothing. A
message given up on is gone.

**`dead` is distinct from `bounced`.** Bounced means a destination refused it
and said why; dead means Pigeon stopped trying. The sender is told in both
cases, and the DSN says which — an operator reading "we gave up after five days"
and one reading "the mailbox does not exist" need different actions.

---

## 8. Retention: the body, the row, and the orphan

Three lifetimes, deliberately different:

- **The body** is deleted when every delivery for its message is terminal.
  Pigeon is a relay, not an archive.
- **The rows** outlive it, for a configurable window, because queue inspection
  and post-incident debugging without them is guesswork. `body_deleted_at`
  records that the body is gone so a retry attempt cannot mistake a missing file
  for a corrupted one.
- **Orphaned spool files** — written before a crash that preceded the commit —
  are swept at startup and periodically: any spool file with no `message` row,
  older than a grace period comfortably longer than the acceptance path, is
  removed. The grace period is what stops the sweep racing an acceptance in
  progress.

Deleting the body while any delivery is non-terminal would turn a deferred
delivery into a permanent failure at the next attempt, so the check is on
*every* delivery and it happens in the same transaction as the last terminal
transition.

---

## 9. Bounces and DSN semantics

The part with the most ways to be dangerous.

**A bounce is generated when a delivery becomes `bounced` or `dead`.** It is
sent to the message's `return_path` — reversed through SRS, which is exactly why
Milestone 2 stored it rather than recomputing it.

**Its own envelope sender is null** (`MAIL FROM:<>`). This is not a formality:
it is what stops two mail systems bouncing at each other forever. A bounce that
cannot be delivered is discarded, not bounced again.

**A message whose `return_path` is empty produces no bounce.** A null sender
means the message was itself a bounce; failing to deliver a bounce is a double
bounce, and the only correct action is to log it and stop. Anything else is
backscatter.

**Content**: RFC 3464 multipart/report, with

- the per-recipient status (`5.1.1` mailbox unknown, `4.4.7` expired, and so on),
- the remote's response text, which is the single most useful line for whoever
  reads it,
- and the original headers — headers only. Returning the body doubles the
  traffic an attacker gets from one message and returns content to an address
  that may not have sent it.

**Batching**: one DSN per message per terminal event, listing every destination
that reached the same terminal state. Three destinations failing produces one
report, not three.

**Rate limiting** is not optional. A flood of accepted mail for a destination
that starts refusing everything becomes a flood of bounces to whatever the SRS
addresses reverse to. See R-4.

Bounce generation is itself a message: it goes through the same spool and queue,
because a bounce that is lost on a restart is a sender who never learns.

---

## 10. Rulings required before implementation

**R-1 — destinations are resolved once, at acceptance.** A retry delivers to the
set resolved when the message was accepted, even if routing has changed.
Recommended: **yes**, with the alternative recorded — re-resolving at delivery
means a message can arrive at a mailbox its sender was never told about, and
makes "where did this go?" unanswerable after a configuration change.

**R-2 — a message accepted for two managed domains.** Milestone 2 defers the
second recipient because one message carries one signing identity. Options:
(a) keep the restriction; (b) accept and split into two messages at acceptance,
each signed for its own domain. Recommended: **(b)**, since the restriction is
visible to senders and splitting is invisible — but it doubles the spool write
and needs the deduplication rule to be per-message rather than global.

**R-3 — the give-up horizon and whether it is configurable.** Recommended: 5
days, configurable downward but not upward, because a longer horizon holds mail
whose SRS return path expires at 21 days and whose bounce would then be
unroutable.

**R-4 — bounce rate limiting.** Recommended: a per-return-path and global cap,
with excess bounces dropped and counted rather than queued, because a queue of
undeliverable bounces is the backscatter the null sender was supposed to
prevent.

**R-5 — streaming the body to the spool.** The 50 MB-per-connection ceiling
must go. Recommended: `DataReader` writes through to the temporary spool file as
it scans, keeping only the scan state in memory — which changes the M2 pipeline
input from `&[u8]` to something it can read twice (verify, then normalise), and
that is the part to design before writing code.

**R-6 — the routing revision.** Carried from `M1-RELOAD.md` C-1 to C-3, which
are constraints on this milestone and are restated here so they are not lost:

- **C-1**: publication needs one order. Socket-driven and poll-driven
  publication are two writers to one runtime; either one coordinator serialises
  them, or publication is conditional on a strictly newer state.
- **C-2**: a revision is only meaningful within one database. A restore can
  present the same number over different rows, so periodic reconciliation is
  not an optimisation — it is what makes the counter safe to trust.
- **C-3**: those two do not compose naively. A "strictly newer" CAS cannot
  install the equal-or-lower revision a restore produces, and exempting
  reconciliation reopens C-1. Either one coordinator, or a composite
  `(lineage, revision)` epoch where the lineage advances on a revision
  regression *and* on an equal revision over different rows.

The daemon already publishes routing, keys and the SRS ring as one runtime
through one publisher, and reconciles the ring by hashing it. **The revision
counter joins that path**; it does not get one of its own. Recommended: settle
C-3 as the coordinator, because the epoch's cost — a lock held across a load —
turned out to be comparable, and one critical section is the smaller thing to
get right.

**R-7 — worker identity.** `claimed_by` needs to survive a restart without
colliding: a hostname plus a boot-unique value, not a PID, which is reused.

---

## 11. To measure before implementing

1. **SQLite write throughput under the acceptance path**, with `WAL` and one
   `BEGIN IMMEDIATE` per message. If a commit per message is the ceiling, the
   design needs a batching story and it should be designed now rather than
   retrofitted.
2. **Whether `DataReader` can write through without changing its scanning**,
   which R-5 depends on.
3. **What real receivers do with the RFC 3464 report** Pigeon generates —
   ideally the same providers as the M2 acceptance test, since a DSN nobody can
   read is a bounce that did not happen.
4. **Lease expiry under a stopped-world process**, e.g. `SIGSTOP`, which is the
   case a lease exists for and the one a graceful shutdown test cannot produce.

---

## 12. Tests

Every property with the mutation that must break it, in the discipline the
previous milestones settled into.

| Property | Mutation that must fail a test |
|---|---|
| `250` follows the commit | acknowledge after the spool write, before the transaction |
| A crash before the commit loses no *accepted* mail | — (nothing was accepted; assert the orphan is swept) |
| Every destination is a row | fan out to the first destination only |
| The same destination twice is one row | drop the unique constraint |
| A terminal delivery is never re-claimed | include terminal states in the claim |
| `attempts` increments at claim | increment on completion |
| An expired lease is reclaimed | never expire |
| Backoff grows | fix the interval |
| Backoff is jittered | remove the jitter |
| The body survives until every delivery is terminal | delete when the first one is |
| A retry sends byte-identical content | re-run the pipeline on retry |
| A retry reuses the stored return path | recompute the SRS address |
| A bounce has a null sender | use the return path as its sender |
| A null-sender message produces no bounce | generate one |
| The DSN carries headers only | include the body |
| Destinations are not re-resolved | resolve at delivery |

Plus the crash tests, which are the milestone: `SIGKILL` at each of the four
points in §4, restart, and assert that everything answered `250` is delivered
exactly once and nothing else is delivered at all.

### Exit criteria

Unchanged from the roadmap, with one addition: **the Milestone 2 acceptance test
must have passed before this milestone can be called complete**, because
"transient failures resolve themselves" is not a property that can be observed
against a fixture peer alone. A queue that faithfully retries mail providers
reject is a queue that works and a product that does not.
