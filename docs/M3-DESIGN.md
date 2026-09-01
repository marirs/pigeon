# Milestone 3 — Durability

Design for review. **The rulings in §10 are settled, and implementation has
begun.** The Milestone 2 acceptance test has not run; its risk was accepted
explicitly by the operator, whose standing decision is that live mailbox testing
happens when the product is complete, and `ROADMAP.md` records the waiver.

M2 remains *implementation complete, acceptance pending*: no message has reached
a real mailbox at a real provider. Everything below assumes the bytes M2
produces are acceptable to receivers, and that assumption is unverified.

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

### 4.1 A failed `COMMIT` is not the same as "nothing committed"

The distinction the acceptance path turns on, and the one place guessing is
forbidden.

A statement failing *before* the commit is unambiguous: the transaction rolls
back and nothing exists, so the spool files are orphans and must be removed. A
`COMMIT` returning an error is not. SQLite can fail a commit with the
transaction still active, and it can fail to *report* a commit that reached the
disk — an I/O error on the reply path, a process killed between the write and
the return.

Classifying that as "nothing committed" and deleting the file destroys a message
that rows already point at. Nothing recovers it: the body is not in the
database, and the sender, told nothing, retries into a queue that already
believes it has the message.

The costs are not symmetric, so neither is the rule:

| Outcome | Cost |
|---|---|
| A durable file leaks | recoverable — orphan recovery collects it |
| A retry duplicates | recoverable — the recipient sees two |
| A file with committed rows is deleted | **permanent loss** |

So on a failed commit the database is read back **through a fresh connection** —
the one that failed may be unusable, and asking it what happened is asking the
thing that just failed. Three answers:

- **every group present** — the commit landed; this is an acceptance,
- **no group present** — non-commit is *established*; the files may be removed,
- **anything else**, including the read failing and a partial result no single
  transaction could produce — **unknown**. The files stay, the sender gets a
  transient failure, and orphan recovery resolves it later.

The type enforces this rather than a comment: the failure carries which case it
is, and only the established-non-commit variant answers `spool_may_be_removed`
with true.

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

### 5.1 As built: one decision, at `RCPT`

Routing happens once per transaction, at `RCPT TO`, against the runtime pinned
at `MAIL FROM`. The decision — the managed domain the mail is accepted *for* and
the destinations it resolves to — is recorded in the transaction
(`pigeond/src/routing.rs`). `DATA` reads those decisions and makes none of its
own, even against the same runtime: a second lookup is a second answer waiting
to differ from the one the sender was given a `250` for.

The envelope the session finally holds is authoritative for *which* recipients
count: an address this sink accepted can still be refused by the recipient cap
immediately afterwards, and a destination only that address reached must not
become a delivery. An acknowledged recipient with no recorded decision is a
wiring bug, and is answered `451` rather than routed.

Grouping happens at `DATA` from those stored decisions: one group per managed
domain (R-2), destinations deduplicated within a group by mailbox — folding the
domain, never the local part — with every original recipient kept on the merged
row.

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

### 6.2 Duplicate suppression: where it is safe, and where it is guessing

Deduplication is safe in exactly two places:

- **Within one accepted transaction.** Pigeon knows those recipients belong to
  one submission, so a repeated `RCPT` is recorded once and several recipients
  resolving to one mailbox become one delivery (§5). Nothing is guessed.
- **Against an explicit idempotency identity** — a caller saying "this is the
  same request as before". Inbound SMTP carries no such thing.

Everything else is guessing, and it is **not done**:

- **Not by `Message-ID`.** It is written by the sender, is not unique in
  practice, and is trivially reused by broken clients.
- **Not by body hash.** Byte-identical mail is sent again on purpose: a
  mailing-list re-run, a monitoring alert that has not cleared, a person
  pressing send twice.
- **Not by envelope equality.** Same sender, same recipient, same content is a
  description of ordinary repeated mail.

The asymmetry decides it. Suppressing wrongly means a message accepted with a
`250` and then discarded — silent, and unrecoverable because Pigeon keeps no
copy. Not suppressing means a duplicate the recipient can see and delete. The
lost-`250` duplicate is inherent to at-least-once SMTP and every MTA has it;
inventing a content heuristic to hide it trades a visible annoyance for
invisible loss, which is the trade this project refuses everywhere else.

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
- **The rows** outlive it, for a fixed 30-day window, because queue inspection
  and post-incident debugging without them is guesswork. The window is measured
  from `body_deleted_at` — the moment Pigeon was finished with the message — so
  it answers the question it is actually about: how long after that can the
  outcome still be explained. Two things are kept regardless of age: anything
  not actually settled (a delivery in flight, a report owed), and any message a
  delivery still names as its `notified_by`, because collecting a DSN while the
  failure it reported still points at it would leave "was the sender told?"
  unanswerable. Configurability is deferred rather than declined, as with the
  horizon; if it is exposed it must stay well clear of the horizon plus the time
  a DSN takes to deliver.
- **Orphaned spool files** — raw, intermediate or final, written before a crash
  that preceded a commit — are swept periodically: any spool file with no row
  referring to it and no install in progress is removed.

  **Not an age heuristic.** A freshly installed file is *deliberately*
  unreferenced until its transaction commits, and "old enough that no acceptance
  could still be running" is a guess about scheduling that is wrong on a machine
  that is paused, swapping, or stopped in a debugger. Installs in progress are
  registered in memory instead, and the sweep skips them — exactly, not
  probably. The register lives in memory on purpose: after a crash there is no
  acceptance in progress, so every file it was protecting really is collectable.

  A listing that cannot be produced is its own answer. An empty set is a *claim*
  that nothing is referenced, and sweeping on that claim would delete every
  queued message on the host, so an unreadable or incomplete listing means no
  sweep at all.

### 8.1 Deletion is not part of the transition

SQLite cannot commit a file deletion, so `body_deleted_at` must not be written
as though the terminal transition and the `unlink` were one act. They are four
steps, in this order:

1. Commit the last terminal delivery, and the notification if one was owed
   (§9.2).
2. **Mark the body released** — `body_deleted_at` — and commit.
3. Delete the spool file and fsync its directory.
4. Periodically collect the files step 3 did not reach: a released body whose
   file still exists is an orphan, and nothing will ever read it again.

The mark goes **before** the unlink, which is the opposite of the obvious
order, because SQLite cannot commit a file deletion and one of the two crash
windows has to be chosen:

| Order | A crash in between leaves | Recoverable? |
|---|---|---|
| Mark, then unlink | a row saying the body is gone, and a file that is still there | yes — an orphan, swept |
| Unlink, then mark | a row claiming a body that no longer exists | **no** — every reader treats it as an integrity failure, correctly, forever |

An earlier draft of this section had it the other way round.

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

**A return path that cannot be reversed is classified before anything is
discarded.** Two very different things look the same at the call site:

- **Permanent** — not a return path this host issued, malformed, a tag that will
  never verify, or expired past a window that only moves further away. No amount
  of waiting produces a recipient, so the obligation is discharged as
  `abandoned`, with an operator alert as well as a delivery event.
- **Local** — the ring is unreadable right now, no key is eligible, the clock
  has jumped backwards. The address may be perfectly good, so the failure stays
  `owed` and the next pass tries again. Treating this as permanent would consume
  an obligation because a file was briefly unreadable.

`abandoned` is a state of its own rather than a return to `none`, because "no
report was required" and "a report was owed and will never be sent" are
different facts. Collapsing them means nobody can ask how many senders were left
without an answer.

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

**Measured and now frozen** (§11.2): `AuthenticatedMessage::parse` takes a
`&[u8]`, so the raw file is **mapped** — a chunked reader cannot satisfy it. A
map removes the 50 MB heap allocation and does not remove working-set pressure,
which is why the semaphore is part of the ruling rather than a tuning knob.

**The limit is the smaller of two bounds, not the CPU one alone:**

```text
permits = min(CPU-derived limit, memory_budget / worst_case_resident_bytes)
```

CPU count bounds how fast the work goes; it does not bound how much of it is
resident at once. At roughly twice the message size per permit, a 64-core host
sizing purely from cores would allow ~64 × 2 × `max_message_size` — several
gigabytes at a 50 MB ceiling — and the map does not help, because mapped pages
that are being hashed are resident pages.

`memory_budget` is configured, not inferred: a host's total memory is not
Pigeon's to spend, and inferring a fraction of it would make the limit change
when an unrelated service is installed. `worst_case_resident_bytes` is derived
from `max_message_size`, so lowering the message ceiling raises concurrency
rather than being a separate knob to keep consistent.

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

### Settled by the measurements in §11

**R-8 — no batching in the initial implementation. Ruled.** One transaction per
submission. The measured ceiling is ~68 messages per second on the whole
acceptance path, and group commit is a known ~9× lever if that ever binds.
Building it now would add a latency knob and a partial-failure mode to buy
throughput nothing needs.

**R-9 — durability pragmas are part of the promise, not tuning.** `250` means
the message survives, and the measurements show what each setting actually
survives:

| Setting | Survives a process crash | Survives power loss | Cost, this machine |
|---|---|---|---|
| `synchronous=NORMAL` | yes | **no** | 0.05 ms |
| `synchronous=FULL`, no `fullfsync` | yes | **not on macOS** | 0.08 ms |
| `synchronous=FULL` + `fullfsync` | yes | yes, here | 4.9 ms |

**The contract is `synchronous=FULL` plus the strongest barrier the platform
offers**, not "`fullfsync=ON`". `fullfsync` is a macOS-specific pragma mapping
to `F_FULLFSYNC`; on other platforms setting it is inert, and there the question
becomes whether `fsync` reaches stable media at all — which is a property of the
filesystem, the device and its write cache, not of SQLite. Linux `fsync` on a
consumer SSD with a volatile cache and barriers disabled is exactly as unsafe as
`fullfsync=off` here, and nothing in the pragma reports that.

So the ruling has two halves:

- **Configure** `synchronous=FULL`, plus `fullfsync` where it exists.
- **Verify per platform.** The durability claim is not established by setting a
  pragma; it needs a power-loss test, or an explicit statement that the operator
  has satisfied themselves about the storage stack. Until that verification
  exists for a platform, the documentation says what was measured and where —
  not "acknowledged mail survives power loss" as though it were universal.

A forwarder that loses acknowledged mail on a power cut has broken the one
promise this milestone is about, and the local ceiling in §11.1 is not a
constraint worth trading it for. An operator who knowingly wants the weaker
setting can have it, as a documented choice with the failure mode named.

---

## 11. Measurements

Two of the four are done, on an Apple-silicon laptop with an NVMe SSD, release
build. Absolute numbers are machine-specific; the *shapes* are not, and the
shapes are what the design turns on.

### 11.1 Acceptance cost is barriers, not rows — and acceptance is not the bottleneck

```text
transaction only, WAL
  synchronous=FULL, fullfsync=ON     205 msg/s    4.9 ms per commit
  synchronous=FULL, fullfsync=off  12,055 msg/s   0.08 ms per commit
  synchronous=NORMAL               21,575 msg/s   0.05 ms per commit
  batched x10, fullfsync=ON       1,876 msg/s    5.3 ms per commit

whole path — spool write, fsync, rename, directory fsync, commit
  50 KB message, fullfsync=ON          68 msg/s   14.6 ms
   5 MB message, fullfsync=ON          52 msg/s   19.2 ms
  50 KB message, fullfsync=off         96 msg/s   10.4 ms
```

Three findings, in order of how much they matter.

**Row work is free.** One destination and three destinations commit at the same
rate (205 vs 205); a 5 MB body costs 4.6 ms more than a 50 KB one across the
whole path, against ~15 ms of barriers. Acceptance is three durability barriers
— the spool file, its directory, the WAL commit — and everything else is noise.

**So batching does not belong in the initial implementation.** ~68 messages per
second is a **local acceptance-path ceiling on this machine** — what one process
can make durable and acknowledge — and it is neither an end-to-end rate nor a
daily capacity. Real throughput is governed by what happens after the `250`: DNS,
connection setup, remote servers, their rate limits, and retries against
destinations that are slow or down. Those dominate, and none of them is helped
by committing faster.

The finding is therefore narrow and sufficient: **acceptance is not the
bottleneck**, so building batching now would optimise the one stage that is not
the constraint. Group commit is the lever if that ever changes, and it is worth
~9× (205 → 1,876) because it amortises the barrier rather than the work. Recorded here so nobody has to re-derive it; **R-8** below
defers it explicitly rather than leaving it unmentioned.

**The durability knob is worth more than the batching one, and it is a
correctness decision.** `fullfsync=off` is 60× faster and is not a barrier on
macOS: the commit is in the drive's cache, so a power loss can lose an
acknowledged message. `synchronous=NORMAL` in WAL is weaker again — it survives
a process crash, which is what §12.1's kill tests exercise, but not a power
failure. Pigeon's promise is about accepted mail, so **R-9** rules on this.

### 11.2 What `mail-auth` needs from the payload

```text
per message, by size (parse / normalise / sign / seal)
   1 MB    0.1ms   0.5ms    4.0ms    4.2ms  →   8.7ms
   5 MB    0.0ms   2.3ms   18.6ms   18.2ms  →  39.1ms
  25 MB    0.0ms  12.1ms   91.4ms   90.3ms  → 193.8ms

body hashes forced by one message (5 MB body)
   1 signature  →  1 body hash   18.0ms
   8 signatures →  4 body hashes 77.1ms
  50 signatures →  4 body hashes 76.8ms

peak RSS for the 25 MB case, holding raw + normalised + signed: 110 MB
```

**Contiguity is required.** `AuthenticatedMessage::parse` takes `&[u8]`, so a
mapped file satisfies it and a chunked reader does not. That settles R-5's file
abstraction: the raw spool file is **mapped, not streamed**, for verification.

**Parsing is header-only and free; the cost is body hashing**, which happens in
`finalize` once per *distinct* `(canonicalisation, algorithm, l=)` triple rather
than once per signature. Under strict parsing `l=` must be zero, so the sender's
only lever is canonicalisation and algorithm — and the measurement shows it
saturates at **four** body hashes whether the message carries eight signatures
or fifty.

That is a better bound than `M2-DESIGN.md` §4.4 assumed. The signature cap still
earns its place — it bounds DNS lookups and public-key verifications, which are
per signature — but body hashing was already bounded by the library, at roughly
15 ms/MB in the worst case.

**Worst case per message is therefore about 23 ms/MB** (4 body hashes on
receipt, normalise, sign, seal), so a 50 MB message is a bit over a second of
CPU and about twice its size resident. 256 connections each entitled to that is
the denial of service R-5 exists to prevent.

Both quantities bound the semaphore, and **the CPU one alone does not** — see
R-5: cores decide how fast the work runs, and nothing about them limits how much
of it is resident at once. A large-core host sized from cores would permit
gigabytes of pressure, and the map does not help because pages being hashed are
resident pages. Peak RSS above is three buffers of a 25 MB message.

### 11.3 Still to measure, before the parts that need them

3. **What real receivers do with the RFC 3464 report** Pigeon generates —
   ideally the same providers as the M2 acceptance test, since a DSN nobody can
   read is a bounce that did not happen. Blocked on the same infrastructure.
4. **Lease expiry under a stopped-world process** (`SIGSTOP`), which is the case
   a lease exists for and the one a graceful-shutdown test cannot produce.
   Needs the queue to exist.

---

## 11.4 Protocol limits and malformed input

The limits are in `ServerConfig` and are compile-time defaults rather than
configuration: RFC 5321 §4.5.3.2 sets the timeout floors, and a wrong value
here is a mail outage rather than a tuning mistake. What each one defends
against is recorded beside it.

| Limit | Value | Without it |
|---|---|---|
| `command_timeout` | 300s | a connection held open by never speaking |
| `data_timeout` | 600s | the same, mid-body |
| `max_session` | 3600s | a client that stays *busy* — `NOOP` every few seconds resets the command timeout forever, and the connection cap becomes the means of denial rather than the defence against it |
| `max_connections` | 256 | unbounded concurrent sessions; the surplus waits rather than being refused |
| `max_message_size` | 50MB | advertised as `SIZE`, and an over-declaration is refused at `MAIL FROM` rather than after the body |
| `MAX_COMMAND_LINE` | 512 | an unbounded line buffer; an overlong line is reported once and the reader resynchronises |
| `MAX_HOPS` | 100 | a message going round a loop Pigeon cannot see |
| recipient cap | — | one transaction fanning out without bound |

### What is refused, and what is carried

**Refused at the end of `DATA`** — still before the `250`, so the message stays
the upstream MTA's to report on:

- **A NUL octet anywhere in the body** (`554`). A NUL truncates the message for
  every parser written in C and is an ordinary octet to the rest, so relaying
  one launders that difference: what Pigeon signs is not what the receiver
  reads. It is the same hazard `normalize` describes for bare CR, and a
  forwarder is the ideal machine for laundering it, because it re-emits a
  stranger's bytes from a trusted host. Stripping it instead would be silently
  altering somebody's mail.

**Carried, deliberately:**

- **Bare CR and bare LF** are converted to CRLF once, after authentication and
  before signing (`M2-DESIGN.md` R-1). Conversion rather than refusal because
  the fault is common and the fix is unambiguous.
- **Lines longer than 1000 octets.** RFC 5321 §4.5.3.1.6 caps them, but senders
  exceed it routinely — unwrapped base64, a pasted URL — and relays accept it.
  Refusing would reject deliverable mail every other MTA carries. The receiver
  at the far end is entitled to object, and if it does, the failure is reported
  through a DSN rather than guessed at here.
- **A message that does not parse at all.** It is forwarded with a trace header
  and no seal: refusing would lose mail over a parser disagreement.

---

## 11.5 STARTTLS

**Inbound.** Advertised exactly when a certificate is configured — the
advertisement is a promise, and the previous shape (a `bool` beside no
implementation) could promise what the server could not do. The certificate is
loaded at startup, so an unreadable one is an operator problem rather than a
discovery made while somebody's mail is in flight. Configuring it is optional:
MX-to-MX TLS is opportunistic, and an MX that refused to serve without a
certificate would refuse mail rather than protect it.

The upgrade itself has one rule: **nothing crosses it.**

- Every buffered byte is discarded before the handshake — framed or not. A
  client that pipelines `STARTTLS\r\nMAIL FROM:<...>` in one packet has put
  that command in the server's buffer, in plaintext; executing it afterwards
  would attribute an injected command to the encrypted session (the injection
  half of CVE-2011-0411).
- The session is reset: greeting, envelope and state. A fresh `EHLO` is
  required, because everything learned before the handshake was learned from an
  unauthenticated conversation.
- A failed handshake ends the connection. There is no plaintext fallback: the
  client was told `220` and believes everything it sends next is encrypted.

**Outbound.** Certificates are *not* verified, deliberately — see
`pigeon-smtp/src/tls.rs`. Without DANE or MTA-STS there is no authenticated
name to check against, and verifying against the public roots would fail on a
large share of the internet's mail servers, leaving only two options: send in
the clear anyway, or refuse mail every other MTA delivers. What opportunistic
TLS buys is protection from a passive observer, which is what can be had
honestly.

But once a peer *advertises* `STARTTLS`, plaintext is off the table for that
delivery:

- a refused upgrade (`4xx`/`5xx` to the command) defers;
- a failed handshake defers;
- neither retries the message unencrypted.

An attacker who can corrupt one packet could otherwise strip encryption from
every message by making the handshake fail, and a client that fell back would
hand them the plaintext for free. Deferral costs a retry; the fallback costs the
message's confidentiality.

---

## 11.6 Shutdown

Two phases, in this order:

1. **Stop accepting and stop claiming.** The listener is closed and the delivery
   worker stops taking rows.
2. **Drain what is already in progress**, bounded by `DRAIN_DEADLINE` (20s).

Reversing them does not converge: a drain that runs while connections are still
arriving and rows are still being claimed waits on work the daemon is still
taking on. The two are signalled by one channel, so the listener and the worker
stop at the same instant rather than in whatever order the shutdown code is
written in, and they drain concurrently — they wait on different things.

The bound is not an approximation of patience. One delivery may legitimately run
for the whole forward budget, half an hour against a slow receiver, and a
shutdown that waited for that is one nobody will use. What is left running at
the bound is safe by construction:

- **A session cut before its `250`** never had one. Acceptance is durable
  exactly when the queue transaction commits, so the sender retries.
- **An abandoned delivery attempt** holds a claim fenced by a token nothing else
  can produce, so its completion cannot land on a row that has since been
  reclaimed, and the row returns to the queue when its lease expires.

`SIGTERM` as well as `Ctrl-C`: the former is what an init system sends, and a
daemon that handled only the latter would be killed uncleanly by every restart
in production — which is the case this path exists for.

---

## 11.7 Loop detection at delivery

The inbound hop limit catches a message that has been round a loop a hundred
times. This catches it before the first pass.

Before connecting, each resolved mail exchanger is compared against what this
daemon is:

Filtering is **per address**, not per exchanger. One hostname can resolve to
both this host and a real server, and judging the exchanger usable because it
has one address elsewhere would still connect to the self address if it came
first in the list.

- **Addresses, not names.** The comparison is on the socket addresses a
  connection would actually be made to — never reverse DNS or the peer's
  banner, both of which the remote writes and neither of which says where the
  packets went. Resolution happens once, and the address checked is the address
  connected to. IPv4-mapped IPv6 is normalised, or a resolver returning
  `::ffff:198.51.100.7` would walk straight past a check on `198.51.100.7`.
- **The port is part of it**, because the question is "would this connection be
  answered by us?" — and `127.0.0.1:2526` is not this daemon when it serves
  `127.0.0.1:2525`.
- **Self identities** are the listener's own address, every loopback address
  when the listener is a wildcard, and `smtp.inbound.self_addresses`. Behind
  NAT or on a multi-homed host, the address the world's DNS points at cannot be
  inferred from a wildcard bind, which is what that setting is for.

The verdicts:

| What the resolver said | Verdict |
|---|---|
| Some address elsewhere | connect to **those addresses only** — the self ones are removed from the set, not merely outvoted by it, or a hostname resolving to this host *and* a real server would be connected to in order and reach this host first |
| Every address is this host | skip that exchanger and try the next |
| Cannot resolve, or timed out | transient, and **not** evidence of a loop |
| Every usable exchanger is this host | permanent: `554`, rendered as **5.4.6** in the DSN, and a report is owed |

Uncertainty never becomes a loop verdict: "we could not reach anyone" and
"everyone is us" are different answers, and only the second is a configuration
that no retry resolves. The report says *routing loop* rather than *no such
user*, because the mailbox is fine and the fault is on this side — the person
who can fix it is the operator, and they will not see the word "loop" in a
bounce that blames the recipient.

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
