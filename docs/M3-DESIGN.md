# Milestone 3 — Durability

Design for review. **The rulings in §10 are settled and no implementation
exists.** None should begin until the Milestone 2 acceptance test has passed or
its risk has been explicitly accepted again. M2 is *implementation complete, acceptance
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

Five tables, following `M1-SCHEMA.md`'s conventions: `STRICT`, integer time,
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
    -- What the sender used. For the log and the DSN; never used to address
    -- anything.
    original_sender   TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL CHECK (size_bytes >= 0),
    received_at       INTEGER NOT NULL,

    -- Which routing state accepted this, for diagnostics only — never
    -- re-resolved against (R-1). The fingerprint is stored *with* the revision
    -- because a revision alone is ambiguous after a restore, which is the exact
    -- condition C-2 exists for: the same number over different rows.
    routing_revision  INTEGER NOT NULL,
    routing_fingerprint BLOB NOT NULL,

    -- Set once the body has actually been removed from disk (§8). Not part of
    -- the terminal transition: SQLite cannot commit a file deletion.
    body_deleted_at   INTEGER
) STRICT;

-- The recipients the sender named, before routing resolved anything.
--
-- RFC 3464 requires a DSN to carry enough information to associate a failure
-- with the recipient the sender *specified*, which after forwarding is not the
-- destination that failed. Without this table a report would say "delivery to
-- mailbox@provider.example failed" to a sender who addressed
-- `hello@example.com` and has never heard of the mailbox.
CREATE TABLE original_recipient (
    id          INTEGER PRIMARY KEY,
    message_id  INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    UNIQUE (message_id, address)
) STRICT;

CREATE TABLE delivery (
    id             INTEGER PRIMARY KEY,
    message_id     INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    -- One row per resolved destination. The unit of retry, of outcome, and of
    -- everything finding 19 could not express.
    destination    TEXT NOT NULL,
    state          TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','delivering','deferred','delivered','failed','expired')),
    -- Whether a DSN is owed for this delivery, and whether it exists yet.
    -- Separate from `state` because the two answer different questions and
    -- collapsing them makes a crash between the failure and the report look
    -- like a report that was sent (§9.2).
    notification   TEXT NOT NULL DEFAULT 'none'
        CHECK (notification IN ('none','owed','enqueued')),
    -- The DSN that reports this failure, once one exists. Durable grouping:
    -- a crash partway through notifying five failures cannot report the same
    -- one twice, because the ones already grouped carry the id.
    notified_by    INTEGER REFERENCES message(id) ON DELETE SET NULL,

    attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- Meaningful only while there is a next attempt to schedule.
    next_attempt_at INTEGER,
    claimed_by     TEXT,
    lease_expires_at INTEGER,
    last_code      INTEGER,
    last_response  TEXT,
    terminal_at    INTEGER,

    UNIQUE (message_id, destination),

    -- A claim and the state that has one are the same fact. The earlier form
    -- allowed a deferred row to keep a claim, which is a row no expiry sweep
    -- would reclaim and no worker would touch.
    CHECK (
        (state = 'delivering')
        = (claimed_by IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CHECK ((state IN ('delivered','failed','expired')) = (terminal_at IS NOT NULL)),
    -- Scheduling is for work that will be retried.
    CHECK ((state IN ('queued','deferred')) = (next_attempt_at IS NOT NULL)),
    -- Nothing is owed for a success, and a report cannot exist without being
    -- owed first.
    CHECK (notification = 'none' OR state IN ('failed','expired')),
    CHECK ((notification = 'enqueued') = (notified_by IS NOT NULL))
) STRICT;

-- Which of the sender's recipients led to which delivery.
--
-- Many-to-many because both directions happen: one alias fans out to several
-- destinations, and several aliases deduplicate onto one. A DSN needs both
-- ends — the alias the sender wrote and the destination that refused it.
CREATE TABLE recipient_delivery (
    original_recipient_id INTEGER NOT NULL REFERENCES original_recipient(id) ON DELETE CASCADE,
    delivery_id           INTEGER NOT NULL REFERENCES delivery(id) ON DELETE CASCADE,
    PRIMARY KEY (original_recipient_id, delivery_id)
) STRICT;

-- Due work, and nothing else. A partial index because the queue is mostly
-- terminal rows after a day, and scanning them to find the few that are due is
-- the difference between a query and a table scan.
CREATE INDEX delivery_due ON delivery(next_attempt_at)
    WHERE state IN ('queued','deferred');

-- Owed notifications, for the same reason.
CREATE INDEX delivery_owed ON delivery(message_id) WHERE notification = 'owed';

CREATE TABLE delivery_event (
    id           INTEGER PRIMARY KEY,
    delivery_id  INTEGER NOT NULL REFERENCES delivery(id) ON DELETE CASCADE,
    at           INTEGER NOT NULL,
    kind         TEXT NOT NULL
        CHECK (kind IN ('attempt','defer','deliver','fail','expire','notify','claim_expired')),
    code         INTEGER,
    response     TEXT,
    remote       TEXT
) STRICT;
```

**`UNIQUE (message_id, destination)` is the duplicate suppression**, and it is
scoped to a *message* rather than to a submission. Two aliases in the same
message resolving to one mailbox is one delivery: the message is one message and
sending it twice is a duplicate the recipient cannot distinguish from a loop.
Two recipients in *different* managed domains resolving to the same mailbox is
two deliveries, because R-2 splits them into two messages with different signed
bytes — the sender addressed two recipients and each one gets the form signed
for its own domain.

**`ON DELETE CASCADE` from `message`** is deliberate and narrow: deleting a
message row is only ever done by retention, which is deleting the whole record.

## 4. Acceptance

```text
DATA received, streamed to a raw spool file (R-5)
  → split by managed domain (R-2)
  → per group: pipeline (verify, normalise, rewrite, sign, seal)
                → final spool file → fsync → rename → fsync directory
  → ONE SQLite transaction:
        for each group: insert message, its original_recipient rows,
                        its delivery rows, and the mapping between them
     commit
  → 250
```

**The transaction is what the `250` promises.** Not the spool write: a body on
disk with no queue row is a file nothing will ever look at. Not the rename: the
same. The commit is the first instant at which a crash leaves something a
restart can find, so it is the last instant before the acknowledgement.

**One transaction for every group**, not one per group. A `250` covers the whole
submission, so a crash between two commits would leave the sender told that
everything was accepted while half of it existed — and the sender's retry would
then duplicate the half that survived. Every group's bytes are fsynced before
the transaction opens; the transaction only inserts rows.

A crash *before* the commit leaves orphaned spool files. That is the correct
failure — the sender did not get a `250` and will retry — and they are collected
by the sweep in §8.

**Recipient rejection at `RCPT TO` is a correctness requirement, not an
optimisation** (`ARCHITECTURE.md` §2.6.1). Anything accepted and later
undeliverable must be bounced, and bouncing mail that should have been refused
makes Pigeon a backscatter source. This is why the `RCPT` decision moving to the
snapshot belongs in *this* milestone rather than being a tidy-up: the queue is
what makes a wrong acceptance expensive.

---

## 5. Splitting, fan-out, and the destination set

At `RCPT TO`, the snapshot resolves each recipient to a set of destinations.
Milestone 2 narrowed a message to one policy by deferring a second recipient in
another managed domain; R-2 replaces that restriction with a split.

**A submission becomes one message per managed domain.** Each group gets its own
finished bytes, its own signing identity, its own spool file, its own `message`
row and its own delivery set — because the signing identity is a property of the
domain the mail was accepted *for*, and one set of bytes cannot carry two.

The split is invisible to the sender, which is the point: the previous behaviour
deferred a recipient and asked the sender to send it again.

Within a message:

- **One `delivery` row per resolved destination**, deduplicated.
- **A recipient resolving to several destinations is several rows.** A domain
  default fanning out to three mailboxes is three independent deliveries.
- **Several recipients resolving to the same destination is one row.**
- **`recipient_delivery` records which recipients led to it**, so a failure can
  be reported against the address the sender wrote.

Across messages there is deliberately no deduplication. If `a@one.example` and
`b@two.example` both forward to one mailbox, that mailbox receives two
messages — the sender addressed two recipients, the two relay forms are signed
under different identities, and suppressing one would mean silently dropping
mail the sender asked to send.

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

## 7. Backoff, terminal states, and giving up

| From | On | To | Notification |
|---|---|---|---|
| `queued`/`deferred` | claim | `delivering` | — |
| `delivering` | 2xx | `delivered` | `none` |
| `delivering` | 4xx, connection failure, DNS temporary | `deferred` | — |
| `delivering` | 5xx | `failed` | `owed`, unless the return path is empty |
| `delivering` | lease expiry (worker died) | `deferred` | — |
| `deferred` | age > horizon | `expired` | `owed`, unless the return path is empty |

**`failed` and `expired` are the terminal failures, and neither of them says
anything about the sender having been told.** That is what `notification`
records, and keeping them separate is the point of §9.2: a state that means both
"the remote refused" and "the report exists" cannot survive a crash between the
two.

**`expired` is distinct from `failed`.** Failed means a destination refused it
and said why; expired means Pigeon stopped trying. The sender is told in both
cases and the DSN says which — an operator reading "we gave up after five days"
and one reading "the mailbox does not exist" need different actions.

**Backoff is exponential with jitter, per destination**: roughly 1m, 5m, 15m,
1h, 3h, then every 6h to the horizon. Jitter because a destination that comes
back after an outage would otherwise receive every deferred message at the same
instant from every sender that backs off on the same curve.

**The horizon is a fixed five days** (R-3) — the SMTP convention — and it is
generous for a specific reason: giving up is irreversible because Pigeon
archives nothing. Configurability is deferred rather than declined; if it is
exposed later it has to be validated against the 21-day SRS window and the time
a DSN needs to be generated and delivered, because a return path that expires
before the bounce is sent is a failure nobody hears about.

---

## 8. Retention: the body, the row, and the orphan

Three lifetimes, deliberately different:

- **The body** is deleted when every delivery for its message is terminal *and*
  nothing is still owed a notification. Pigeon is a relay, not an archive — but
  a DSN quotes the original headers, so the body outlives the deliveries by as
  long as the reports take.
- **The rows** outlive it, for a configurable window, because queue inspection
  and post-incident debugging without them is guesswork.
- **Orphaned spool files** — raw, intermediate or final, written before a crash
  that preceded a commit — are swept at startup and periodically: any spool file
  with no row referring to it, older than a grace period comfortably longer than
  the acceptance path, is removed. The grace period is what stops the sweep
  racing an acceptance in progress.

### 8.1 Deletion is not part of the transition

SQLite cannot commit a file deletion, so `body_deleted_at` must not be written
as though the terminal transition and the `unlink` were one act. They are four
steps, in this order:

1. Commit the last terminal delivery (and, if one is owed, the notification —
   §9.2).
2. Delete the spool file and fsync its directory.
3. Set `body_deleted_at`.
4. Periodically finish the pairs a crash separated: terminal messages with no
   `body_deleted_at` whose file still exists get step 2 and 3 again.

A crash between 1 and 2 leaves a file with no reader, which step 4 collects. A
crash between 2 and 3 leaves a row claiming a body that is gone, which is why
every path that opens a spool file treats *absent* as a distinct outcome rather
than an I/O error — and why nothing may become deliverable again once terminal.

Doing it the other way round — setting `body_deleted_at` first — turns the same
crash into a message whose body exists and which nothing will ever read or
remove.

---

## 9. Bounces and DSN semantics

The part with the most ways to be dangerous.

### 9.1 What a report is and where it goes

**A DSN is owed when a delivery reaches `failed` or `expired`.** It is sent to
the message's `return_path`, reversed through SRS — which is exactly why
Milestone 2 stored the return path rather than recomputing it.

**Its own envelope sender is null** (`MAIL FROM:<>`). Not a formality: it is
what stops two mail systems bouncing at each other forever. A bounce that cannot
be delivered is discarded, not bounced again.

**A message whose `return_path` is empty owes nothing.** A null sender means the
message was itself a bounce; failing to deliver a bounce is a double bounce, and
the only correct action is to log it and stop. This is the one case where a
failure is discarded rather than reported, and it is the exception R-4 names.

**Content**: RFC 3464 `multipart/report`, carrying

- the per-recipient status (`5.1.1` mailbox unknown, `4.4.7` expired, and so on),
- the remote's response text, which is the single most useful line for whoever
  reads it,
- **`Original-Recipient` — the address the sender wrote**, from
  `original_recipient` via `recipient_delivery`, alongside the destination that
  actually failed. A report naming only the destination tells a sender that
  delivery failed to a mailbox they have never heard of.
- and the original headers. Headers only: returning the body doubles the traffic
  an attacker gets from one message and returns content to an address that may
  not have sent it.

### 9.2 A failure is not terminal until its report is durable

This is the correction that shapes the schema. If `failed` meant both "the
remote permanently refused" and "the sender has been told", a crash between the
two would leave a delivery that looks fully handled and a sender who never hears
anything — permanent, silent suppression of the one notification the whole
milestone exists to guarantee.

So the two facts are separate columns, and the report is created like an
acceptance:

1. Render the DSN and write it to a spool file. Fsync it, rename it, fsync the
   directory.
2. In **one** transaction: insert the DSN's `message` and `delivery` rows, and
   set `notification = 'enqueued'`, `notified_by = <the DSN message id>` on
   every failure it reports.
3. Commit.
4. Sweep the orphaned DSN file if the transaction never commits.

A crash before 3 leaves the failures still `owed`, and the next pass renders the
report again — a bounce rendered twice and sent once, rather than owed once and
sent never.

`notified_by` is the durable grouping identifier. A crash partway through a run
that notifies five failures cannot report any of them twice, because the ones
already committed carry the id and are no longer `owed`.

### 9.3 Batching

**One DSN per message per notification run**, listing every delivery of that
message which is `owed` when the run starts. Not "per terminal event": events
arrive at different times, and forcing them into one report would mean either
delaying the first failure until the last one resolves, or rewriting a report
already sent.

RFC 3464 permits several DSNs for one submission, so this is a correctness
question rather than a tidiness one: **report promptly, group what is already
owed, and never report the same delivery twice.** The uniqueness is enforced by
`notification`/`notified_by`, not by the batching rule.

### 9.4 Capacity is backpressure, not discard

**An owed DSN is never dropped.** Once Pigeon answered `250` it took on an
obligation: deliver the message or tell the sender why. Discarding the
notification because a limit was reached converts a delivery failure into
silence — the failure mode that is indistinguishable, from the sender's side,
from mail that vanished.

A rate limit may therefore:

- **delay** transmission,
- **coalesce** several owed failures into one report (§9.3),
- and **apply backpressure to acceptance** — refusing new mail with a transient
  reply when notification capacity is exhausted, because accepting more is
  taking on more liability while unable to discharge what is already owed.

It may not discard. The `owed` state is durable precisely so that a limit
becomes a queue rather than a loss. The single exception stays the null-sender
failure of §9.1, which owes nothing to begin with.

Bounce generation is itself a message: it goes through the same spool and queue,
because a bounce lost on a restart is a sender who never learns.

---

## 10. Rulings — settled

**R-1 — destinations are resolved once, at acceptance. Ruled.** A retry
delivers to the set resolved when the message was accepted, even if routing has
changed since. Re-resolving would let a message arrive at a mailbox its sender
was never told about, and makes "where did this go?" unanswerable after a
configuration change.

**R-2 — split by managed domain. Ruled.** Each domain group gets its own
finished bytes, signing identity, `message` row, spool file and delivery set,
and **every group becomes durable in one acceptance transaction before the
`250`**. Deduplication is per derived message: two recipient domains reaching
one mailbox is two deliveries, because the sender addressed two recipients and
the signed relay forms differ. §5.

**R-3 — a fixed five-day horizon. Ruled**, with configurability deferred rather
than declined. "Configurable downward but never upward" was safe and arbitrary;
if it is exposed later it must be validated against the 21-day SRS window and
the time a DSN needs to be generated and delivered. §7.

**R-4 — an owed DSN is never discarded. Ruled.** Once Pigeon answered `250`,
delivery or notification is an obligation. A rate limit may delay, coalesce and
apply backpressure to new acceptance; it may not drop a report that is owed.
When notification capacity is exhausted, the failure stays durably `owed` and
Pigeon stops taking on new liability. Null-sender failures remain the one
exception and are discarded. §9.4.

**R-5 — disk-backed streaming. Ruled**, with the boundary specified rather than
left to implementation:

- `DataReader` streams the **exact received bytes** into a `0600` raw temporary
  file; size accounting and terminator scanning stay incremental.
- Post-`DATA` authentication runs under a **bounded concurrency semaphore**.
- Verification reads or maps the raw file.
- Normalisation, rewrite, signing and sealing write a **separate final
  temporary**, which is fsynced and renamed before the queue commit.
- Raw and intermediate files are removed idempotently, and swept after a crash.

A memory map removes the 50 MB heap allocation and does **not** remove
working-set pressure, which is why the semaphore is part of the ruling rather
than a tuning knob. The precise file abstraction is not frozen until measurement
2 below says what `mail-auth` needs to read, and how many times.

**R-6 — one coordinator. Ruled.** C-3's two options were a coordinator or a
composite `(lineage, revision)` epoch; the coordinator wins because the epoch's
cost — a lock held across a load — turned out comparable, and one critical
section is the smaller thing to get right. One publication path, one ordering
authority: routing, keys, the SRS ring and now the revision counter all install
through it.

Queued messages record the routing **fingerprint** beside the revision (§3),
because a revision number alone is ambiguous after a restore — which is the
exact condition C-2 exists for. C-1 to C-3 are restated in `M1-RELOAD.md` §2 and
are constraints on this milestone, not references.

**R-7 — worker identity is hostname plus a random boot identifier. Ruled.** Not
a PID, which is reused, and not a timestamp alone, which collides across
machines that boot together and after a clock step.

---

## 11. To measure before implementing

1. **SQLite write throughput under the acceptance path**, with WAL and one
   `BEGIN IMMEDIATE` per submission. If a commit per message is the ceiling, the
   design needs a batching story designed now rather than retrofitted.
2. **What `mail-auth` needs from the payload, and how many times.** R-5's file
   abstraction depends on it: verification, signing and sealing each parse the
   message, and whether they can work from a mapped file or need a contiguous
   slice decides whether the raw file can be mapped or must be read. Freeze the
   abstraction after this, not before.
3. **What real receivers do with the RFC 3464 report** Pigeon generates —
   ideally the same providers as the M2 acceptance test, since a DSN nobody can
   read is a bounce that did not happen.
4. **Lease expiry under a stopped-world process** (`SIGSTOP`), which is the case
   a lease exists for and the one a graceful-shutdown test cannot produce.

---

## 12. Tests

Every property with the mutation that must break it, in the discipline the
previous milestones settled into.

| Property | Mutation that must fail a test |
|---|---|
| `250` follows the commit | acknowledge after the spool write, before the transaction |
| Every group commits together | one transaction per domain group |
| Every destination is a row | fan out to the first destination only |
| The same destination twice in one message is one row | drop the unique constraint |
| The same mailbox in two groups is two rows | deduplicate across messages |
| The sender's recipients are preserved | record only the resolved destination |
| A terminal delivery is never re-claimed | include terminal states in the claim |
| `attempts` increments at claim | increment on completion |
| An expired lease is reclaimed | never expire |
| A claim and `delivering` are the same fact | relax the equivalence check |
| Backoff grows | fix the interval |
| Backoff is jittered | remove the jitter |
| The body outlives every delivery *and* every owed report | delete when the last delivery is terminal |
| `body_deleted_at` follows the unlink | set it in the terminal transaction |
| A retry sends byte-identical content | re-run the pipeline on retry |
| A retry reuses the stored return path | recompute the SRS address |
| Destinations are not re-resolved | resolve at delivery |
| A failure stays `owed` until its DSN is committed | mark it notified when the DSN is rendered |
| A DSN reports the sender's recipient | report the destination only |
| A DSN has a null sender | use the return path as its sender |
| A null-sender failure owes nothing | generate a report for it |
| A delivery is never reported twice | ignore `notified_by` when grouping |
| Exhausted notification capacity refuses new mail | drop the owed report instead |

### 12.1 What the crash tests may assert

The earlier draft promised "exactly once and nothing else delivered", which
contradicts §6.1. Two windows cannot be closed, and a test that asserts they are
would be asserting something false about a system that is behaving correctly:

- **Commit succeeds, the process dies before the `250` reaches the client.** The
  message is durable and will be delivered; the client never saw an
  acknowledgement and will send it again. Two copies, and Pigeon cannot tell
  them apart — the second submission is a new message by every observable
  property.
- **The remote accepts, the process dies before the `delivered` commit.** The
  lease expires and the delivery is retried against a destination that already
  has it.

So the assertions are:

1. **Every message answered `250` is eventually delivered at least once, or its
   sender is notified.** Never neither.
2. **Nothing becomes deliverable before its queue transaction commits.** A crash
   at any earlier point leaves no delivery and no report — only an orphaned
   spool file, which the sweep removes.
3. **A delivery committed as terminal is never resent.** The bounded duplicate
   comes from the window before that commit, not after it.
4. **The remote-accept-then-crash window permits a bounded duplicate** — bounded
   by one attempt, not unbounded retries — and the test asserts the bound rather
   than the absence.
5. **A message committed before a lost `250` may still be delivered**, even
   though the client never observed the acknowledgement. This is correct
   behaviour and is asserted as such, so nobody later "fixes" it into loss.

The kill points are the four in §4 — after the raw write, after the final
rename, inside the transaction, and after the commit but before the reply — each
followed by a restart and the five assertions above.

### Exit criteria

Unchanged from the roadmap, with one addition: **the Milestone 2 acceptance test
must have passed before this milestone can be called complete**, because
"transient failures resolve themselves" is not a property that can be observed
against a fixture peer alone. A queue that faithfully retries mail providers
reject is a queue that works and a product that does not.
