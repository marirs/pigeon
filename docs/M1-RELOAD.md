# Milestone 1 — live reload

**Implemented.** `pigeon-route/src/reload.rs` for the detector,
`pigeond/src/reload.rs` for the worker and its supervision.

The `Arc` swap is already built and already tested. What is new here is the
change detector, and the only property that matters is that **it cannot miss a
commit**. A reload that is late is a stale routing table for a second. A reload
that is missed is a stale routing table until someone restarts the daemon, with
nothing anywhere saying so.

So this document is mostly about one ordering rule and the failure paths around
it.

---

## 1. Scope

**SQLite routing state only.**

| Changes | Picked up by |
|---|---|
| Domains, aliases, destinations, catch-alls | reload |
| `pigeon.toml` — hostname, listener addresses, paths, TLS, alerts | restart |
| DKIM key verification | restart (see below) |

Bootstrap configuration is excluded because it is not reloadable in any
meaningful sense: the listeners are bound, the keys root has been canonicalised
and every stored key path validated against it, and the spool has been probed.
Re-reading the file would produce values that disagree with a running process.

**Startup cross-checks are a gap worth naming, and DKIM is not the only one.**

`M1-SCHEMA.md` §5 has three checks that compare configuration against schema,
and every one of them can be invalidated by a mutation made while the daemon
runs:

| Check | How a live mutation breaks it | Consumer ships |
|---|---|---|
| Every active DKIM key derives its stored public half | `domain add` brings a key the check has never seen | M2 (signing) |
| `alerts.identity` is not on a managed domain | `domain add` for the identity's own domain makes it managed — the exact configuration startup refuses | M5 (alerting) |
| Hostname reverse DNS | unaffected; it reads no schema | — |

Neither costs anything today, because nothing signs and nothing alerts. Both
must be closed **when their consumer ships**, and the rule is the general one
rather than two special cases:

> Reload reruns every configuration-versus-schema invariant whose consumer is
> live, or that consumer verifies at the point of use.

Reload does not run them now because there is nothing to protect and a check
with no consumer is a check nobody maintains. Recorded here so that adding the
consumer and adding the check are one task rather than two.

---

## 2. The detector

**One long-lived connection, polling `PRAGMA data_version`.** No file watching:
under WAL the database file's mtime does not move on every commit, and a
watcher would be reporting on the wrong artefact.

Four properties, verified against the bundled SQLite before this was designed
rather than taken from the documentation:

| Property | Observed |
|---|---|
| A commit on **another** connection changes this connection's `data_version` | yes |
| A commit on **this** connection does **not** | no change |
| The value is stable inside a read transaction, and that transaction is isolated | stable, isolated |
| An open, uncommitted write transaction does not move it | unchanged until commit |
| Several commits between polls produce one change | yes — they coalesce |
| A commit to an **unrelated table** moves it | yes — it is *any* commit |

### `data_version` is a doorbell, not a diff

The last row matters more than it looks. `data_version` observes every commit to
the database, not every commit to routing. Milestone 3 puts the queue in the
same file, and a busy relay commits queue and delivery rows continuously — so a
detector that rebuilt and published on every version change would rebuild
constantly, publish identical tables, and log a reload for each one.

So the version is only the **wake-up signal**. What decides whether anything
happened is a canonical fingerprint of the routing inputs, computed from the
rows the snapshot was built from:

```text
version changed  ->  load  ->  fingerprint == last published?
                                  yes -> consume the version, publish nothing, log nothing
                                  no  -> build, publish, log
```

A commit that did not touch routing is consumed silently. This is also what
makes R-3 implementable: "log when routing changed" is not the same question as
"log when the database changed", and only the fingerprint can tell them apart.

#### What the fingerprint does not remove

It suppresses publication and logging. It does not suppress the **read** — the
routing rows are loaded and hashed *before* the detector can discover the commit
was unrelated. Today that costs nothing: an idle daemon wakes once a second and
runs one `PRAGMA data_version`, and the load only happens when something
actually committed. It is not busy-waiting, and it is not scanning.

Milestone 3 changes the arithmetic rather than the mechanism. Every queue commit
moves `data_version`, so a busy relay would mean one full routing read per
second, every second, to conclude each time that routing had not changed.

SQLite offers no reliable cross-process change event, so the answer is to make
the doorbell more selective:

- **A routing revision.** A small counter bumped transactionally — by triggers
  on the routing tables, so no writer can forget — and polled instead of
  `data_version`. Queue traffic stops waking the loader at all.
- **The Unix socket.** `ARCHITECTURE.md` §3.3 already routes mutating commands
  through the daemon, which is the event-driven path: commit, then publish
  immediately, with no detection involved.

**Plan: the revision first, the socket after, and the poll never removed.** The
revision lands before queue traffic begins, because that is when the cost
appears. The socket makes daemon-owned commits prompt when it arrives. The poll
stays as reconciliation, at a slower interval — offline tools, restores from
backup, and a dropped notification are all real, and none of them should be able
to turn a missed message into a stale routing table. Notification is what makes
reload *fast*; polling is what keeps it *correct*, and collapsing the two would
trade a bounded delay for a silent wrong answer.

Filesystem watchers were considered and rejected as a mechanism. Watching the
database and WAL is noisy, platform-specific, and cannot say whether routing
changed — at best a wake-up hint, which is the part that is already cheap.

#### Two constraints that plan must satisfy

Both come from the same place: the plan adds a second publisher and replaces the
signal that today is accidentally total.

**C-1 — Publication needs one order.** Socket-driven and poll-driven publication
are two concurrent writers to the same `Router`. Nothing about the swap orders
them, so the interleaving is available: A commits, B commits, B publishes, then
A — which had loaded first and was descheduled — publishes its older state over
B's. The routing table is now behind the database with **no pending signal to
repair it**: the revision has already been consumed, and the next change is the
next mutation, whenever that is. Not a race that resolves itself a second later;
a stale table that persists until someone edits something.

So either every publication goes through one coordinator that serialises them,
or publication is conditional on being newer than the published state — a
compare-and-set, where a publisher holding older state loses and discards its
snapshot. Whichever is chosen, "publish whatever I just built" stops being
correct the moment there are two publishers. **What the comparison is made on is
settled by C-3, not here**: the obvious answer, the database revision, conflicts
with C-2.

**C-2 — A revision is only meaningful within one database.** A restore from
backup can present the *same* number as the state already published, with
different rows underneath it. The detector compares equal, does not load, and
serves a routing table that the database on disk no longer contains.

Note which mitigation actually covers it. Database identity — an id stored in
the schema, compared alongside the revision — catches a *different* database
swapped in, but the common case is a restore of the *same* database, whose
identity matches. A revision that moves backwards is detectable and must force a
reload rather than being treated as "not newer", but a restore to a point whose
revision happens to equal the current one moves it neither forward nor back.

**Only reconciliation covers that case**, so the periodic forced load and
fingerprint is not an optimisation to drop later — it is what makes the revision
safe to trust in between. Requiring a restart after a restore is the honest
alternative, but it is an operational rule enforced by documentation, and the
failure mode when it is not followed is silent.

Worth being explicit about what changes here, because it is easy to miss:
today's `data_version` is accidentally *total* — it moves for every commit, so
every commit forces a load, and the fingerprint sees the actual rows each time.
A routing revision is deliberately *narrow*, and narrowing the doorbell removes
the fingerprint's opportunity to notice anything the doorbell missed. The
reconciliation poll is where that opportunity has to be given back.

**C-3 — C-1 and C-2 cannot both be satisfied by a revision CAS.** The two
constraints were recorded separately and their remedies do not compose. C-1's
cheap form orders publication by the database revision; C-2 exists precisely
because a restore can present an equal or lower revision over different rows.
Reconciliation must therefore install a snapshot the CAS is built to reject —
and exempting it from the CAS puts back the unordered second publisher that C-1
is about. An exemption is not a smaller version of the problem: reconciliation
is the publisher most likely to be slow, because it always loads.

Two ways out, and they differ in what they cost rather than in what they
guarantee.

**A publication coordinator.** One critical section spanning load *and*
publication, so ordering comes from the lock rather than from any number, and
reconciliation is an ordinary participant. It is the smaller thing to get right,
and the contention argument against it does not really apply here: mutations are
operator actions, not traffic, so the lock is uncontended outside the
reconciliation interval.

**A composite in-memory epoch,** if the socket path must not hold a lock across
a load. The published state carries `(lineage, revision)`, compared
lexicographically. `lineage` is a daemon-local counter, not a database value.
Whoever advances it publishes at the new lineage and wins over every in-flight
publisher, because those loaded under the old one; within a lineage the revision
does the ordering, as C-1 wants.

**Two things advance the lineage, and content is only one of them.**

- **Any revision regression** — an observed revision *lower* than the published
  one — regardless of whether the rows changed. This is the case a
  fingerprint-only rule gets wrong: a restore from revision 10 back to revision
  5 whose routing rows happen to be identical passes the fingerprint check
  unchanged, so the lineage does not move and the published state stays at
  revision 10. The *next real routing change* then commits at revision 6 and is
  rejected as older than what is published. The restore was harmless; the
  rejection of everything after it is not, and it persists until the revision
  sequence climbs back past 10.
- **An equal revision over different rows**, which needs the fingerprint,
  because nothing about the number distinguishes it. This is the case C-2
  describes and the reason reconciliation loads at all.

They differ in cost, and therefore in owner. A regression is *detectable* in the
revision read every ordinary poll already performs, so it is noticed at the next
poll rather than at the next reconciliation. Only the equal-revision case has to
wait, because nothing but a load can see it. Stating the rule as "reconciliation
advances the lineage" would be both wrong and slow: wrong because a regression
is not a content question, slow because the cheap half would inherit the
expensive half's interval.

**Cheap to detect is not cheap to handle.** The revision comparison says the
sequence was rewound; it says nothing about the rows, and revision 5's routing
tables may differ from the revision 10 tables currently published. Noticing the
regression and doing nothing would leave the daemon serving state that no longer
exists in the database — the C-2 failure, arrived at by a different route. So
the response is a full one:

1. Advance the lineage, **once**.
2. Load and build at the observed revision immediately, rather than waiting for
   the reconciliation interval.
3. Publish under the new lineage, which is what makes it win over in-flight
   publishers still carrying the old one.
4. Record that the reset happened — **including when the build fails.**

Step 4 is the one that is easy to leave out. A failed build leaves the published
state where it was, at the higher revision, so the next poll sees the same
regression and would reset again: an unbounded lineage climbing once per second,
a warning per poll, and — worse than either — an invalid-configuration backoff
that never engages, because backoff is keyed on the version that failed and the
epoch keeps changing underneath it. Recording the reset against the observed
revision makes the retry an ordinary failed rebuild, throttled like any other,
while a *further* regression is still a new observation and resets again.

The reason the epoch has to be composite is worth stating, since a bare counter
is the first thing anyone reaches for. A ticket taken *before* loading orders
publishers by when they started, and the one that started earlier can be the one
that read later state. A ticket taken *after* loading orders them by when they
finished, and a publisher that read old rows can finish last. Neither orders by
*what was read* — only the revision does that, which is why the database's
number stays in the key and the in-memory counter exists solely to break the
tie a restore creates.

Not settled here. C-3 is a constraint on the M3 design, not a decision made
ahead of it — but the design that ignores it will look correct, because the
failure needs a restore and a concurrent publication in the same window.

### The second row is a trap for later

`data_version` does not move for commits made on the *same* connection. Today
the daemon never writes — the CLI does, in another process — so the detector
sees everything. The moment the daemon gains its own writer, which is what the
Unix socket in `ARCHITECTURE.md` §3.3 is for, **its own commits become invisible
to its own detector**.

That path must publish directly rather than waiting to be told about itself.
Writing it down here because the failure is silent, and because the code that
introduces it will be nowhere near this file.

---

## 3. The ordering rule

This is the whole design.

```text
seen: Option<i64> = None            <- see "the baseline" below

loop {
    v = PRAGMA data_version         <- recorded BEFORE the read transaction
    if seen == Some(v) && not retrying { sleep 1s; continue }

    BEGIN                           <- read transaction
      rows = load()
      fingerprint = hash(rows)
      snapshot = build(rows)?
    END

    if fingerprint != published {
        publish(snapshot)
        log
    }
    seen = Some(v)                  <- the version read at the top, never a later one
}
```

**The recorded version must never be newer than the data the snapshot was built
from.**

Reading it afterwards violates that, and the failure is exactly the one worth
preventing:

```text
t0  read the rows            -> state S1
t1  another process commits  -> state S2
t2  read data_version        -> V2
t3  seen = V2

S1 is published. S2 is never seen again, because the next poll reads V2
and finds it equal to `seen`. The daemon routes against S1 until it restarts.
```

Recording the version *before* the read cannot do that. If a commit lands
between the version read and the transaction, the transaction may see newer data
than the version implies — so the next poll finds a version it has not seen and
rebuilds. The cost is one redundant rebuild; the benefit is that a miss is not
representable.

Reading the version at the *start of the transaction* is equally safe and
slightly tighter, since version and data then correspond exactly. The rule is
stated as "before" because it is the simpler thing to check in review, and both
satisfy the invariant.

### The baseline: `seen` starts as `None`

Startup builds a snapshot from its own connection, and the worker starts
afterwards. If the worker adopted the version it reads at start-up as its
baseline, a commit landing between those two moments would be inside the
baseline and never rebuilt — the same miss, arriving before the loop has run
once.

`None` closes it: the first iteration always rebuilds, whatever the version
says. One redundant build at start, and no window.

The alternative — capturing the baseline on the same connection *before*
startup's build — also works and is more efficient by exactly one rebuild. It is
not chosen because it couples the worker's correctness to the order of two
things in `startup.rs`, and that coupling is invisible from here.

### Reconnecting resets the baseline

`data_version` is only comparable across calls **on the same connection**. It is
a per-connection counter of changes that connection has observed, not a global
sequence number, and the difference is not academic:

```text
old connection has seen 3 changes      -> reads 3
reopen                                 -> reads 2
three more commits happen              -> a brand-new connection still reads 2
```

Verified against the bundled SQLite. So a worker that reopens after a
connection-level failure and adopts the new connection's current value would set
`seen` to a number with no relationship to what it had already published, and
would then skip every change until the new counter caught up.

**After any reconnect, `seen` returns to `None`** and the next iteration rebuilds
unconditionally. Reconnection is rare and a rebuild is cheap; a skipped change
is neither.

### Coalescing is fine, and is the point

Five commits between two polls produce one version change and one rebuild from
the latest state. The contract is that **the latest committed state is
eventually published**, not that every intermediate state is. Nothing observes
intermediate states — a routing table is a value, not a log.

---

## 4. Failure

Three kinds, and they must not be treated alike.

**Transient database failure** — `SQLITE_BUSY`, a lock held by a long import,
an I/O error. Retry with bounded exponential backoff. **`seen` is not
advanced**, so the change is still pending; advancing it would mean a transient
failure permanently swallowed a real change.

**Invalid configuration** — the snapshot does not build. A hand-edited row, a
restored database, a version this build cannot read. The last-known-good table
stays published, because a running server with a stale-but-valid routing table
beats one with none. `seen` is not advanced here either.

That raises a flooding problem the contract has to answer: an invalid
configuration does not fix itself, so retrying every poll rebuilds forever and
logs forever.

**The backoff throttles rebuilding, never polling.** The loop keeps reading
`data_version` every second, whatever is failing. What the backoff decides is
whether to attempt a *rebuild* for a version that has already failed:

```text
same version still failing   ->  skip the rebuild until the backoff expires
a version not seen before    ->  cancel the backoff, rebuild immediately
```

Suspending the poll instead would mean a fix committed during a sixty-second
backoff waits sixty seconds to be noticed — and the fix is the one commit that
most deserves to be picked up promptly. Detection is cheap; only the rebuild is
worth throttling.

- **Log once per version.** The message names the version that failed; the same
  version does not log again.
- **Back off the rebuild**, capped. The version is still not consumed — if it is
  fixed, the fix is a new commit and a new version, which cancels the backoff
  and is attempted on the next poll.

**A panic in the worker** is a bug, not a condition — and it is the one failure
the worker cannot report, because reporting is what it stopped doing.

An earlier draft said "the worker logs and exits". It cannot: a panic unwinds
past any logging the worker would have done, and a `JoinHandle` nobody awaits
holds the result silently until someone asks. A daemon that spawned the worker
and forgot it would keep serving the last published table forever, with routing
frozen and nothing anywhere saying why.

So the boundary is supervised from outside. The daemon holds the handle and
awaits it; a task that ends — for any reason, panic or otherwise — is reported
at that point, with the panic message when there is one. The daemon keeps
serving the last published table, because a frozen-but-valid table is still
better than none, but it says so rather than pretending.

### What each failure leaves

| Failure | Published table | `seen` | Logged |
|---|---|---|---|
| Transient | unchanged | not advanced | at each retry, at debug |
| Invalid configuration | last known good | not advanced | once per version, at warn |
| Worker panic | last known good | — | once, at error, **by the supervisor** |

---

## 5. What reload does not change

**In-flight mail transactions keep their pinned snapshot.** `Router::for_transaction`
already hands out an `Arc` per `MAIL FROM`, and a transaction holds it through
`DATA`. A message accepted under one configuration is delivered under the same
one; the next `MAIL FROM` on the same connection gets the new table.

That is already implemented and already tested — the reload worker changes
nothing about it, and the test that pins it is worth re-running against a
publication that came from the worker rather than from a test.

---

## 6. Shutdown

The worker is a task with a handle. Shutdown **signals and joins** — it does not
signal and hope.

Joining matters for two reasons, and an earlier draft gave a third that is not
true.

**Deterministic shutdown.** A signalled-but-unjoined worker may still be inside
a rebuild, and a process that exits underneath it makes "did the last reload
finish?" unanswerable from the outside. Joining makes the answer yes.

**Connection cleanup.** The worker owns a SQLite connection, and joining is what
closes it at a known point rather than at process teardown.

The claim it replaces was that an abandoned read transaction leaves WAL recovery
work. It does not — process exit releases the reader's locks, and the WAL is
consistent either way. What a live reader actually does is **hold back
checkpointing**: verified against the bundled SQLite, a checkpoint attempted with
an open read transaction returns busy, and succeeds once the reader ends. That
is a growth-of-WAL concern on a long-running daemon, not a correctness one, and
it is not a reason to join at shutdown — the process is ending anyway.

Keeping the wrong reason would have made the next reader believe a shutdown path
was protecting them from something it was not.

The wait is bounded. A worker that does not stop is logged and abandoned rather
than hanging the shutdown, since the alternative is a daemon that cannot be
stopped without `SIGKILL`.

---

## 7. Tests

Two real connections throughout — one standing in for the daemon, one for the
CLI. A test that drives both sides through the same connection proves nothing,
because the property under test is precisely that a *different* connection's
commits are seen.

| Property | Test |
|---|---|
| Uncommitted work is invisible | open a write transaction, insert, do not commit; assert no reload |
| A commit is picked up | commit, assert the new table is published |
| Rapid commits coalesce to the latest | ten commits in a burst; assert the final state is published |
| A commit racing snapshot construction is not lost | commit between the version read and the build; assert it is published by a later poll |
| Invalid configuration retains the last good table | publish a good one, write an invalid row, assert the good one still routes |
| Recovery | fix the invalid row, assert the fixed one is published |
| Invalid logs once per version | assert repeated polls do not repeat the message |
| Transient failure does not consume the version | fail the read, then succeed; assert the change arrives |
| Transactions keep their snapshot across a publication | pin, publish, assert the pinned table is unchanged and the next one is not |
| Shutdown joins | signal, join, assert the worker actually ended |
| A worker that gives up is reported | assert the supervisor logged it, not merely that the handle resolved |
| A panicking worker is reported as a panic | drive `supervise_handle` with a panicking task, assert the error event |
| The liveness probe reads the database | corrupt the file under an open connection: `SELECT 1` still answers, the probe does not |
| A dropped `Reloader` does not leak the worker | start, drop without signalling, assert the runtime still shuts down |
| The load is transactional | tick inside an outer transaction, assert it refuses to nest |
| An unreadable status is invalid, not transient | assert it warns once and backs off |
| A commit before the worker starts is not missed | commit between startup's build and the worker's first poll |
| A reconnect rebuilds unconditionally | force a reconnect, assert the next state is published |
| An unrelated commit publishes nothing | write to a non-routing table, assert no publish and no log |
| The backoff does not delay a fix | invalid, then fixed during the backoff window, assert prompt pickup |
| A panicking worker is reported | make the worker panic, assert the supervisor logs it |

The racing test is the one that needs care. It is not a timing test: the commit
is made *deterministically* between the version read and the build, by driving
those two steps explicitly rather than running the loop and hoping.

Mutations that must turn one of them red:

- `seen` advanced to a version read after building
- `seen` advanced on a failed build
- `seen` advanced on a transient error
- the invalid path publishing an empty table instead of retaining the last good
- the detector using the same connection as the writer
- shutdown signalling without joining
- the poll comparing against a version captured after the transaction closes
- `seen` initialised from the version at start-up instead of `None`
- a reconnect adopting the new connection's current version
- the backoff suspending the poll rather than only the rebuild
- publishing and logging on every version change, without the fingerprint
- the worker spawned and its handle dropped

---

## 8. Rulings

**R-1 — Poll interval: one second, as a constant.** Ruled. The check is
a single pragma on an open connection and costs nothing; a knob here invites
tuning a number that has no wrong value, and a slower poll only delays a reload
nobody is waiting on synchronously.

**R-2 — Polling only for Milestone 1.** Ruled. A Unix socket is the mechanism
`ARCHITECTURE.md` §3.3 already describes for mutating commands, and building
half of it as a reload ping would mean two notification paths to reconcile
later. Polling is correct on its own; the socket can make it prompt when it
arrives, and the detector remains the thing that cannot miss.

**R-3 — Does the daemon log every successful reload?**
Ruled: **log at info only when the routing input actually changed and was
published**, not on every `data_version` change. The two are different questions
once the queue shares the database, and §2 is what makes the distinction
available — a version change with an unchanged fingerprint is consumed silently.

The line carries the domain and rule counts, and the build's reports go with it,
so a redundant alias introduced at runtime is not silent.

---

## 9. As built

| Design | Where |
|---|---|
| §2 detector, §3 ordering, §4 failure | `pigeon-route/src/reload.rs` — `Watcher::tick` |
| §2 fingerprint | same file — `fingerprint` |
| Startup handover | same file — `initial` |
| §6 worker, supervision, shutdown | `pigeond/src/reload.rs` |

Sixteen tests, two real connections throughout.

### The race is produced, not waited for

`tick_with` takes a hook that runs **after the rows are read** and before the
version is recorded. That is the window the ordering rule is about: a commit
there is not in the snapshot just built, and a version read after it would
include it — so recording that version consumes a change that was never built.

The first attempt put the hook *before* the rows, which is the harmless window,
and the mutation "record the version after building" survived. Worth recording:
the test looked like it covered the rule and covered the adjacent one.

### What the mutation round found in the code

Eight mutations, and getting them all caught took three passes.

**A line that looked load-bearing and was not.** `tick` cleared `failed`
whenever the version changed. No mutation of that line could be made to fail a
test — because the throttle below is already guarded on `f.version == version`,
so a stale record simply never matches. Removed, with the reasoning kept: a
redundant guard is a guard nobody can check.

**Two tests that passed for the wrong reason.** The reconnect test committed a
change and watched it arrive, which passes whenever the fresh connection's
counter differs from the recorded one — most of the time. The transient test
observed the pending change through a *later* commit, and that commit moved the
version, hiding an advanced baseline. Both now assert the watcher's state
directly, through `has_baseline` and `baseline`.

**A backoff test that spent the throttle before the thing it tested.** It ticked
once after the failure, letting the backoff lapse, so "a new version cancels the
throttle" passed whether or not it did. The fix is now committed while the
throttle is still armed.

### Review findings, all fixed

Six, and the first three are the ones that mattered.

**`load_and_fingerprint` opened no transaction**, while its documentation said
it ran in one. `load` issues a query for domains, then one per domain, then one
per alias — so a commit landing partway through assembles a configuration from
two states of the database. That hybrid never existed and nobody committed it,
and it would have been published as though somebody had. The comment was the
specification and the code did not meet it.

Pinned by a test that does not race a writer: SQLite refuses to nest
transactions, so a tick on a connection already inside one must fail. If the
load opened none of its own, it would succeed.

**The worker started before the fallible setup.** An early `?` between the start
and the listener bind dropped the `Reloader` without signalling it — and a
dropped `watch::Sender` does *not* flip the value the receiver reads, so the
loop ran forever. Being a `spawn_blocking` task, the runtime then waited for it
and the process hung on shutdown. Verified.

Fixed twice over: the worker now also exits when its channel closes, and it is
started after every fallible step. The escape hatch alone would leave the next
fallible step added above the start as a hang again.

**`publish_for_test` was public**, which reopened the publication hole that
making `publish` crate-private had closed — a downstream caller could replace a
serving table with `Snapshot::default()` outside the commit contract. Removed;
the one test that used it seeds through `Router::new`, which is what the daemon
does.

**Every `LoadError` became `Transient`**, including a status this build cannot
read. That one reads the same way on every retry, so it is invalid
configuration: warn once and back off, rather than retry every second and log at
debug.

**`conn_is_broken` used `SELECT 1`**, which SQLite answers without reading a
page — verified to succeed against a connection whose file had been deleted. It
probes a real table now.

**And the section below claimed tests that did not exist.** `cargo test -p
pigeond reload` reported zero. The shutdown and supervision rows in §7 described
intent, and the daemon-side lifecycle bug above is exactly what that gap let
through — the one part of the design with no test was the one part with a
process-hanging defect.

Four worker tests now, including one asserting that a dropped `Reloader` does
not leave the worker running. Mutating the channel check makes that test hang
rather than fail, which is the correct signature: a leaked blocking task is
precisely what stops a runtime from shutting down.

### Two of those tests were still claims

A second pass found that two of the fixes above were asserted rather than
tested, which is the same defect one level up.

**The supervisor test only awaited its handle.** Delete every `tracing` call in
`supervise` and it still passed — an await proves the task ended, not that
anybody was told. Supervision is now asserted through the events themselves, and
the panic branch is reached by handing `supervise_handle` a task that panics,
since the worker's own body has no failure point a test can drive. That seam
exists for exactly this reason: a branch a test cannot reach is a branch that is
not known to work.

Three mutations, all caught: the panic arm folded into the generic one, the
clean-exit report deleted, and the panic message stripped of its wording. The
last matters because a panic must stay distinguishable from a clean exit — one
means restart, the other means shutdown worked.

**The probe fix had no regression test.** Reverting `SELECT count(*) FROM
domain` to `SELECT 1` left all 404 tests green.

Writing that test corrected the reason for the fix as well. The justification
first given was that `SELECT 1` succeeds against a connection whose file has
been deleted — true, and irrelevant: **both** probes succeed there, because the
descriptor and the cached pages outlive the directory entry. Measured:

| after | `SELECT 1` | `SELECT count(*) FROM domain` |
|---|---|---|
| the file is deleted | `1` | `0` |
| the file is replaced with garbage | `1` | `database disk image is malformed` |

So corruption is the case that separates them, and corruption is what the test
injects. The fix was right and the stated reason for it was not — which is how a
correct line survives the next refactor for the wrong reason.

### Verified against a running daemon

`routing reloaded domains=1 rules=1`, logged while serving, after an alias was
added by the CLI in another process.
