# Milestone 1 — live reload

Design for review. **No implementation until this is settled.**

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

**DKIM keys are a gap worth naming.** Startup derives each active key's public
half and compares it with the stored one. A domain added while the daemon runs
brings a key that check has never seen, and reload does not run it — the routing
snapshot does not read `dkim_key` at all. That costs nothing today because
nothing signs yet, and it must be closed when signing lands in Milestone 2:
either reload verifies new keys, or signing verifies on first use.

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
loop {
    v = PRAGMA data_version          <- recorded BEFORE the read transaction
    if v == seen { sleep; continue }

    BEGIN                            <- read transaction
      rows = load()
      snapshot = build(rows)?
    END

    publish(snapshot)
    seen = v                         <- the version read at the top, never a later one
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
logs forever. So:

- **Log once per version.** The message names the version that failed; the same
  version does not log again.
- **Back off the retry**, capped. The version is still not consumed — if it is
  fixed, the fix is a new commit and a new version, which resets the backoff and
  is attempted immediately.

**A poisoned lock or a panicked worker** is a bug, not a condition. The worker
logs and exits; the daemon keeps serving the last published table. It does not
silently restart itself into the same panic.

### What each failure leaves

| Failure | Published table | `seen` | Logged |
|---|---|---|---|
| Transient | unchanged | not advanced | at each retry, at debug |
| Invalid configuration | last known good | not advanced | once per version, at warn |
| Worker panic | last known good | — | once, at error |

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

Joining matters because the worker holds a SQLite connection, and a daemon that
exits while a read transaction is open leaves the WAL needing recovery on the
next start. That is recoverable and it is noise, and noise in a startup log is
how a real message gets missed.

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

---

## 8. Open questions

**R-1 — What is the poll interval?**
Recommend **one second**, as a constant rather than configuration. The check is
a single pragma on an open connection and costs nothing; a knob here invites
tuning a number that has no wrong value, and a slower poll only delays a reload
nobody is waiting on synchronously.

**R-2 — Should `pigeon` tell the daemon directly rather than being polled for?**
Recommend **no, not in Milestone 1.** A Unix socket is the mechanism
`ARCHITECTURE.md` §3.3 already describes for mutating commands, and building
half of it as a reload ping would mean two notification paths to reconcile
later. Polling is correct on its own; the socket can make it prompt when it
arrives, and the detector remains the thing that cannot miss.

**R-3 — Does the daemon log every successful reload?**
Recommend **yes, at info, with counts** — domains and rules. A reload that
happens is a change to what the daemon does, and an operator reading a log after
an incident needs to see when the table changed. Reports from the build go with
it, so a redundant alias introduced at runtime is not silent.
