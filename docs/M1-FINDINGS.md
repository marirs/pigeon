# Milestone 1 implementation notes and findings

What was decided while building the control plane, what was got wrong, and why
one exit criterion moved to another milestone.

Design documents are `M1-SCHEMA.md` and `M1-SNAPSHOT.md`. This is the record of
building against them.

---

## 1. Why fan-out moved to Milestone 3

Milestone 1's exit criterion was:

> `pigeon route inbound user@example.com` exactly predicts runtime routing.

It could not be met here, and the reason is that the criterion was mis-assigned
rather than merely deferred.

**The control plane half was met.** `route inbound` predicts what the routing
snapshot answers, exactly, by calling the same function the daemon calls. A
second implementation is how a prediction and the behaviour it predicts drift
apart, so there is only one.

**The runtime half needs the queue.** "Runtime routing" includes delivery, and
delivering one accepted message to several destinations requires each
destination to have its own state. Without it, a retry cannot know which
destinations already received the message, so the failure mode is silent
duplicates — which is worse than the documented gap it would replace.

Finding 19 in `M0-FINDINGS.md` is the same gap seen from the delivery side: a
single rejected recipient currently abandons the message for all of them, and
the fix named there is one recipient per delivery, "which needs the Milestone 3
queue to make a partial outcome representable."

So fan-out belongs in Milestone 3 because **safe retries require independently
durable destination state**, and that state is what Milestone 3 is.

### The wording matters more than the move

The replacement criterion in Milestone 3 is deliberately narrow:

> The daemon's `RCPT` accept/reject decision and resolved destination set come
> from the routing snapshot. Each resolved destination has independently
> retryable queue state, and `pigeon route inbound` predicts that decision and
> destination set exactly.

Both of the phrases it replaces were ambiguous in the same direction. "Runtime
routing" and "per-destination outcome" can be read as promising that the CLI
predicts what happens to a message — and it cannot. It predicts the routing
decision and the set of destinations that decision resolves to. Whether DNS
answers, whether a remote server accepts, and what it says are all outside what
any local table can know.

An exit criterion that can be read as promising more than it delivers is the
same failure as a comment asserting a guarantee the code does not provide, which
`M0-FINDINGS.md` closes on.

### What was not done, and why not half-done

Wiring acceptance to the snapshot while delivery still went to a single
hardcoded address would be worse than the current state, not a step toward it:
mail would be accepted for an address on the strength of a rule and then
delivered somewhere that rule does not name.

Both are wired together in Milestone 3, or neither. Until then the daemon says
so at startup and `pigeon route inbound` says so on every invocation, so the
prediction cannot be relied on by accident.

---

## 2. A test that could not see the ordering it was testing

The mutation contract is five steps and the order is the whole point:

```text
1. apply  2. validate inside the transaction  3. roll back  4. commit  5. publish
```

Each was mutation-tested by moving it and re-running. Four were caught
immediately. **Publishing before committing was not.**

The reason is worth keeping: when a mutation is valid the commit always
succeeds, so publishing before it and publishing after it produce identical
results. Every test in the file exercised a valid mutation or an invalid one —
and an invalid one never reaches either step.

The case that distinguishes them is a commit that fails *after* validation
passed, which nothing was arranging. The fix was to arrange it: SQLite's commit
hook can veto a commit, which is a real mechanism rather than a seam bolted onto
the contract, and a real commit fails for duller reasons — a full disk, a
filesystem error, a deferred constraint.

With that test present, the mutation is caught: *"a snapshot was published for a
change that never committed."*

This is the third time in this project that a test has passed because the
scenario distinguishing right from wrong was never constructed. The pattern is
not carelessness — it is that the author of a fix writes the test from the same
mental model as the fix, and that model does not contain the case it missed.

---

## 3. Review findings against the first implementation

Four corrections, all documentation asserting behaviour the code did not have.
Three were found in review; the fourth was found while fixing them.

**`ROADMAP.md` still described reject as a precedence tier.** The implemented
order is exact → wildcard → catch-all with the winning rule's kind deciding the
result, approved in review and applied to `ARCHITECTURE.md` and `CLI.md` at the
time. The roadmap's own copy of the diagram was missed.

**`pigeon-route`'s module documentation said plus-addressing is "stripped before
matching".** It is not, and the reason it is not is a bug that review caught:
stripping first means `hello+github@` can never have its own alias, and the
correction — the full local part getting one chance at the exact tier — broke
`hello+*` in a different way. The implemented order uses both forms, and the
module doc now states it.

**`Router::publish` was public, with a comment claiming there was "no way to
publish an unvalidated table because there is no way to obtain one".** False:
`Snapshot` is `Default` and `Clone`, so any caller could construct one and
publish it — before a commit, or without one. The comment described a guarantee
the type system was not providing.

`publish` is now `pub(crate)`, and the guarantee is visibility rather than the
type: `mutate` is the only caller and it publishes after the commit. `Router::new`
stays public because seeding a router that is not yet serving has no commit to
run ahead of.

**And, found while fixing the third: the same module doc said "an alias with no
destination is a reject rule".** It is not — no destination means the alias
*inherits the domain default*, which is the encoding `pigeon domain forward`
depends on. A reject rule is a separate kind, which is exactly why the two are
distinguished by a column rather than by counting rows.

The pattern across all four is the one `M0-FINDINGS.md` names: a comment
describing an intention outlives the intention. Three of these were written in
the same week as the code they misdescribe.

---

## 4. Decisions worth carrying forward

- **`schema_migration` is created by the runner, not by migration 1.** The
  runner has to read that table to discover whether migration 1 has run, so
  migration 1 cannot be what creates it. Found by the first test run.
- **Foreign keys are off during a migration batch, with `foreign_key_check`
  inside it.** This is SQLite's documented procedure for altering tables, and it
  is what makes a future table rebuild possible at all. The design document said
  ON throughout, which works for migration 1 and forbids migration 2.
- **The DKIM startup check refuses rather than pretends.** Deriving a public key
  from a private one needs an RSA implementation the workspace does not yet
  carry, so a `dkim_key` row that cannot be verified stops startup. There are no
  such rows yet, which is what makes refusing cheap — and the difference between
  a deferred branch and a comment claiming a guarantee.
- **Repositories write and do not decide.** `add_alias` does not know whether the
  domain has a default to inherit. That is a property of the resulting
  configuration, and `Snapshot::build` owns it, on the same transaction, before
  it commits.

---

## What to carry into the rest of Milestone 1

- DKIM keypair generation and TXT rendering, which also completes the startup
  key verification above.
- Live configuration reload, so a mutation reaches a running daemon without a
  restart. Until it exists, the CLI says so after every change.
- `--json` on every read command; several have it, not all.
- Bulk import from an existing forwarding provider.
