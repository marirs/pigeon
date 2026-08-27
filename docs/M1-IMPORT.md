# Milestone 1 — bulk import

Design for review. **No implementation until this is settled.**

Import is the first command that writes many rows and generates many keys from
one invocation, so the ordering that `domain add` got wrong once — and that its
tests now pin — has to hold across a batch rather than a single row.

Narrower than the schema and snapshot documents: the transaction boundary, the
input format it needs, and the one decision that must never be inferred.

---

## 1. The contract

```text
1. read and parse the whole input                  no writes, no network
2. normalise, and validate against current state   read-only; report every conflict
3. resolve merge versus replace                    explicit, never inferred
                                                   (triggered by any replace-scoped
                                                    routing, not by alias count)
4. generate and durably write one key per NEW domain
5. BEGIN IMMEDIATE
   re-read the scoped state and require it to match the plan
   apply every row
   build the prospective snapshot
   validate it
6. commit once            <- the point of no return
7. publish the snapshot
```

**Every returned error leaves zero imported rows and removes every key this run
wrote.** That wording is deliberate; see *What a crash leaves* below.

Four properties fall out of that shape, and each exists because of a way the
alternative fails.

**Everything is parsed before anything is written.** A file whose four
hundredth row is malformed must not leave three hundred and ninety-nine domains
behind. Parsing is cheap and reversible; row three hundred is neither.

**Every conflict is reported, not the first one.** An import that fails on row
12, is corrected, and then fails on row 19 is an afternoon. The whole input is
checked and the whole list comes back.

**Keys are written before the transaction and removed if it rolls back.** This
is `domain add`'s ordering, and it is here for the reason it is there: a row may
only ever name a key that is already durable on disk. The reverse order turns
any write or fsync failure into committed domains with no usable keys — and at
import scale that is forty domains, not one.

**The plan is re-checked after the lock is taken.** Step 4 is the slow one:
forty RSA-2048 keys is about a minute, and the operator confirmed `--replace`
before it started. In that minute somebody can add an alias to a domain in the
file — and `--replace` would then delete routing that nobody put in front of the
confirmation.

So the transaction re-reads the state of the domains it is scoped to and
requires it to match what was planned. If it has moved, the import aborts and
says which domain changed. This is the only check in the sequence that exists
because of *elapsed time* rather than because of the input, and it is why the
re-read is inside `BEGIN IMMEDIATE` rather than before it.

### Why the snapshot is inside the transaction

Step 5 is `pigeon_route::mutate`'s contract applied to a batch. The snapshot is
built from the transaction's own view, so what is validated is exactly the state
about to become real — including interactions *between* imported rows that no
row-level check can see. A file that imports `a@one.test → b@two.test` and
`b@two.test → a@one.test` is two individually valid rows and one loop, and the
only thing that can see it is a snapshot built from both.

### Where the failure boundary actually is

| Returned error | What is left behind |
|---|---|
| Parse or normalise (step 1–2) | Nothing. No key generated, no row written |
| Merge/replace unresolved (step 3) | Nothing |
| Key write or fsync (step 4) | Keys already written in this run are removed |
| The plan no longer matches (step 5) | Transaction rolls back; keys removed |
| Any row rejected (step 5) | Transaction rolls back; keys removed |
| Snapshot invalid (step 5) | Transaction rolls back; keys removed |
| Commit fails (step 6) | Transaction rolls back; keys removed |

A key that cannot be removed during cleanup is reported by name. It is inert —
no row references it, and no later import will choose the same name — but a file
holding private key material that nobody asked for should not disappear
silently.

### What a crash leaves

The table above covers errors the command *returns*. A process that is killed —
`SIGKILL`, a power failure, an OOM — returns nothing and runs no cleanup, so the
honest statement is narrower than "any failure":

- **Killed during step 4, or between step 4 and the commit:** the keys written
  so far remain on disk and no rows exist. They are orphans: nothing references
  them, no later run reuses their names, and the next import generates fresh
  ones. They are private key material for domains that were never created, so
  `pigeon check` reports unreferenced key files rather than leaving them to be
  found by `ls`.
- **Killed during the commit:** SQLite's own atomicity decides it. The
  transaction is applied or it is not, and either way the keys are consistent
  with it — orphaned if it rolled back, referenced if it did not.
- **Killed after the commit and before the publish:** the rows and the keys are
  correct and permanent. The only thing lost is the in-memory publication, which
  the next startup or reload rebuilds from the same rows.

**The commit is the point of no return.** Before it, an interrupted import is
recoverable by re-running it. After it, the import happened, and what remains is
bookkeeping the daemon reconstructs on its own.

---

## 2. Merge versus replace is never inferred

An import file is a list of what should exist. It says nothing about what should
stop existing, and treating it as though it did is how an import deletes the
alias somebody added last week.

So the mode is a flag, and when it matters the flag is **required**.

What makes it matter is **any routing that `--replace` would remove**, not the
alias count. Per ruling I-1 that is aliases *and* the catch-all, so a domain
with a catch-all and no aliases is exactly the case an "existing aliases" test
would wave through — and `--replace` would then silently delete the rule that
was accepting every address on it.

The trigger is therefore: does this domain have anything inside the replace
scope?

| Situation | Behaviour |
|---|---|
| No imported domain has replace-scoped routing | Proceeds. The distinction is empty |
| Any imported domain has aliases **or a catch-all**, no flag | **Refused**, naming the domains, what each holds, and both options |
| `--merge` | Existing routing is kept. An alias in both, with different destinations, is a conflict |
| `--replace` | Aliases and the catch-all on the **imported domains** are removed first |

Three things about `--replace`:

- **Its scope is the domains named in the file**, never the whole database. A
  file containing one domain cannot empty another.
- **It removes the catch-all and preserves the domain default** (I-1). A
  catch-all is routing, which the file expresses; a default is policy, which the
  file cannot set — removing it would delete something the import has no way to
  put back.
- **It requires `--yes`**, and the confirmation counts the catch-all separately
  from the aliases, because losing one is a different kind of surprise.

`--merge` is not the default. There is no default. A file that is ambiguous
about a domain that already exists stops and says so, because the operator knows
which they meant and the file does not.

---

## 3. Input

`pigeon import csv <file>` in Milestone 1. Provider adapters are deliberately
later and deliberately additive: they produce the same intermediate list, and
inherit steps 2 through 7 unchanged. A provider adapter that had its own
transaction handling would be a second, quieter import.

### Format

Two required columns, one optional. A header row is **required** (I-2), and
columns are matched by name so column order does not matter. Guessing which
column is the destination is how an import writes every alias backwards.

```csv
address,destination
hello@example.com,me@example.net
support@example.com,me@example.net
support@example.com,ops@example.net
shop-*@example.com,shop@example.net
*@example.com,catchall@example.net
```

| Column | Meaning |
|---|---|
| `address` | The address Pigeon receives. `*@domain` is the catch-all; a `*` in the local part is a wildcard alias |
| `destination` | Exactly one mailbox |
| `kind` | Optional. `forward` (default) or `reject` |

**One destination per row, and repeats accumulate into a fan-out set.**
`support@example.com` above ends with two destinations because it appears twice.

An earlier draft packed several destinations into one cell separated by `;`. That
is ambiguous, and not theoretically: `"a;b"@example.com` is a legal address and
`Address::parse` accepts it today — verified before changing this. `,` is no
better, being the field separator. There is no delimiter that a quoted local part
cannot contain, so the format does not use one.

Repeating an address with a **different `kind`** stays a conflict. Accumulating
destinations is a union of forwards; a row saying "forward" and a row saying
"reject" for the same address are two different intentions, and picking either
would be a guess.

### What import does not set

Domain defaults, plus-addressing, outbound and delivery mode are not in the
file. They are per-domain policy rather than routing, and a file that could set
them would be a file that could change them by omission.

Imported domains are created exactly as `pigeon domain add` creates them.
`CLI.md` says imported domains land in `PENDING_DNS`; nothing moves a domain out
of `new` until DNS validation exists, so that sentence describes Milestone 5 and
is flagged here rather than being quietly implemented as a fake transition.

---

## 4. Conflicts

Everything below is collected across the whole input and reported together, with
the row number. None of it writes anything.

**Within the file:**

- The same address twice with different `kind` — one row saying forward and one
  saying reject are two intentions, and picking either is a guess
- The same address twice with the *same* destination — a duplicated row rather
  than a fan-out, reported so a mangled export is visible
- An address that is not parseable, or a pattern that fails the wildcard grammar
- A destination that is not a deliverable address
- `kind=reject` with a destination, or `kind=forward` with none

**Against the database:**

- An alias that exists with a different destination set — under `--merge` only;
  `--replace` removes it first, so it cannot conflict
- A domain name that exists but is not usable as an A-label

**Found only by the snapshot, in step 5:**

- Loops, including ones formed between two imported rows
- Ambiguous equal-precedence wildcards
- An alias inheriting a default the domain does not have

The third group cannot be checked earlier without building the snapshot, which
is why it is built inside the transaction rather than the failure being made
cheaper. The report names the row where possible.

**Not a conflict:** the same address with the *same* destinations, already
present. That is a re-run of an import that partly succeeded elsewhere, and it
is reported as `unchanged` rather than refused.

---

## 5. `--dry-run`

Runs steps 1, 2, 3 and 5, and commits nothing.

**It generates no keys**, and that is a real limitation rather than an
optimisation: generating forty RSA-2048 keys takes a minute, and a dry run is
something an operator does two or three times while fixing a file.

What it proves, stated precisely: **the file parses, its conflicts are known,
and the prospective routing snapshot builds.** That is narrower than "the
configuration is serveable" in one specific way — it deliberately omits the
`dkim_key` rows a real import creates, and the daemon refuses to start on a key
it cannot verify. A dry run cannot see that, because there is no key to see.

So a full disk, an unwritable keys directory, or a key that will not derive is
found by the real run — which is why the real run writes keys before it writes
rows, and leaves nothing behind when it cannot.

Domains are created inside the rolled-back transaction without `dkim_key` rows.
That is sound because the routing snapshot does not read them; it is stated
because "dry run created a domain without a key" would otherwise look like a
bug.

---

## 6. Reporting

Human output is a summary and then the conflicts. `--json` follows the contract
in `CLI.md` — one value on stdout, `format_version`, `error` present.

```json
{
  "format_version": 1,
  "error": null,
  "applied": true,
  "mode": "merge",
  "rows": 412,
  "domains_created": 38,
  "domains_matched": 4,
  "aliases_created": 401,
  "aliases_unchanged": 11,
  "keys_generated": 38,
  "conflicts": []
}
```

`conflicts` is always present and is `[]` on success, per the null-versus-omitted
rule. A conflict carries `row`, `address`, `kind` and `message`; the `kind` is a
stable identifier and the message is not.

A failed import returns the `error` envelope with code `import_conflicts` and
the same list, so a consumer does not need two shapes to handle one command.

---

## 7. Acceptance tests

Driven through the real binary, parsing real output, against a real database.

| Property | Test |
|---|---|
| A malformed row anywhere leaves nothing behind | 400 good rows, one bad, assert zero domains |
| Every conflict is reported, not the first | three distinct conflicts, assert all three |
| Keys are written before rows | unwritable keys directory, assert zero rows |
| A rolled-back import removes its keys | a loop between two imported rows, assert no key files |
| A loop between imported rows is caught | `a@one → b@two`, `b@two → a@one` |
| `--replace` needs `--yes` | assert `confirmation_required` |
| `--replace` is scoped to the file's domains | a second domain's aliases survive |
| Neither flag, existing aliases | refused, naming both options |
| `--merge` keeps existing aliases | assert both old and new present |
| `--dry-run` writes no rows and no keys | assert both empty |
| Re-importing the same file changes nothing | second run reports all `unchanged` |
| Import is atomic across keys and rows | key count equals new-domain count exactly |
| A catch-all alone requires the flag | domain with a catch-all and no aliases, no flag, assert refused |
| `--replace` removes the catch-all and keeps the default | assert catch-all gone, `default_destination` unchanged |
| Repeated addresses fan out | two rows, one address, assert two destinations |
| A repeated address with a different kind conflicts | forward and reject rows for one address |
| A quoted local part containing `;` survives | `"a;b"@example.com` imports as one destination |
| A missing header row is refused | assert the error rather than a mis-parse |
| An existing domain keeps its state | `active`, disabled, assert both after import |
| The plan is re-checked under the lock | state changed mid-run, assert abort |

Mutations that must turn one of them red:

- rows applied before keys are written
- cleanup skipped when the transaction rolls back
- parsing interleaved with writing, so a late failure leaves early rows
- the first conflict returned instead of all of them
- `--replace` widened beyond the file's domains
- merge/replace inferred from whether the domain exists
- `--dry-run` writing keys
- the flag trigger looking at aliases only, ignoring a catch-all
- `--replace` removing the domain default
- the post-lock re-check skipped

---

## 8. Rulings

Settled in review.

**I-1 — `--replace` removes the catch-all and preserves the domain default.**
A catch-all is routing the file expresses; a default is policy the file cannot
set, so removing it would delete something the import has no way to restore.

**I-2 — a header row is required.** Column order varies between exporters, and
guessing which column is the destination imports every alias backwards.

**I-3 — every existing lifecycle and administrative state is preserved.** A
domain already carried by Pigeon keeps its `status`, `inbound_enabled`,
`outbound_enabled`, `plus_addressing`, delivery mode and default destination.
Import adds routing; it is not a lifecycle operation, and moving a live domain
because a file mentioned it would stop its mail.
