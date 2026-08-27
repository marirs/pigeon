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
4. generate and durably write one key per NEW domain
5. one transaction:  apply every row
                     build the prospective snapshot
                     validate it
6. commit once
7. publish the snapshot
```

**Any failure leaves zero imported rows and removes every key written in step 4.**

Three properties fall out of that shape, and each exists because of a way the
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

### Why the snapshot is inside the transaction

Step 5 is `pigeon_route::mutate`'s contract applied to a batch. The snapshot is
built from the transaction's own view, so what is validated is exactly the state
about to become real — including interactions *between* imported rows that no
row-level check can see. A file that imports `a@one.test → b@two.test` and
`b@two.test → a@one.test` is two individually valid rows and one loop, and the
only thing that can see it is a snapshot built from both.

### Where the failure boundary actually is

| Failure | What is left behind |
|---|---|
| Parse or normalise (step 1–2) | Nothing. No key generated, no row written |
| Merge/replace unresolved (step 3) | Nothing |
| Key write or fsync (step 4) | Keys already written in this run are removed |
| Any row rejected (step 5) | Transaction rolls back; keys removed |
| Snapshot invalid (step 5) | Transaction rolls back; keys removed |
| Commit fails (step 6) | Transaction rolls back; keys removed |
| Publish (step 7) | Cannot fail; it is a pointer store |

A key that cannot be removed during cleanup is reported by name. It is inert —
no row references it, and no later import will choose the same name — but a file
holding private key material that nobody asked for should not disappear
silently.

---

## 2. Merge versus replace is never inferred

An import file is a list of what should exist. It says nothing about what should
stop existing, and treating it as though it did is how an import deletes the
alias somebody added last week.

So the mode is a flag, and when it matters the flag is **required**:

| Situation | Behaviour |
|---|---|
| No imported domain has existing aliases | Proceeds. The distinction is empty |
| Any imported domain has existing aliases, no flag | **Refused**, naming the domains and both options |
| `--merge` | Existing aliases are kept. An alias in both, with different destinations, is a conflict |
| `--replace` | Existing aliases on the **imported domains** are removed first |

Two things about `--replace`:

- **Its scope is the domains named in the file**, never the whole database. A
  file containing one domain cannot empty another.
- **It requires `--yes`.** It removes routing that is currently carrying mail,
  and the count is in the confirmation.

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

Two required columns, one optional. A header row is required, and columns are
matched by name so column order does not matter.

```csv
address,destination
hello@example.com,me@example.net
support@example.com,me@example.net;ops@example.net
shop-*@example.com,shop@example.net
*@example.com,catchall@example.net
```

| Column | Meaning |
|---|---|
| `address` | The address Pigeon receives. `*@domain` is the catch-all; a `*` in the local part is a wildcard alias |
| `destination` | One or more mailboxes, separated by `;` |
| `kind` | Optional. `forward` (default) or `reject` |

`;` separates destinations rather than `,` because `,` is the field separator
and quoting it is the sort of thing that works in one exporter and not the next.

**An empty `destination` with `kind=forward` is an error, not an inheritance.**
Inheriting the domain default is a real state, and a blank cell is far more
often a broken export than a deliberate one. An import that guessed would create
aliases pointing at whatever the domain default happened to be.

A reject rule is `kind=reject` with an empty destination. A `kind=reject` row
carrying a destination is a conflict, not a silently ignored column.

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

- The same address twice with different destinations
- The same address twice with different `kind`
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

The consequence has to be stated where it will be read: **a dry run does not
prove that key generation or key writing will succeed.** It proves the file
parses, that its conflicts are known, and that the configuration it produces is
one Pigeon can serve. A full disk or an unwritable keys directory is found by
the real run — which is why the real run writes keys before it writes rows, and
leaves nothing behind when it cannot.

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

Mutations that must turn one of them red:

- rows applied before keys are written
- cleanup skipped when the transaction rolls back
- parsing interleaved with writing, so a late failure leaves early rows
- the first conflict returned instead of all of them
- `--replace` widened beyond the file's domains
- merge/replace inferred from whether the domain exists
- `--dry-run` writing keys

---

## 8. Open questions

**I-1 — Does `--replace` remove the catch-all and domain default too?**
Recommend: **catch-all yes, domain default no.** A catch-all is a routing rule
and the file expresses routing; a domain default is policy the file cannot set,
so removing it would delete something the import has no way to restore.

**I-2 — Should import accept a file with no header row?**
Recommend: **no.** Column order varies between exporters, and guessing which
column is the destination is a way to import every alias backwards.

**I-3 — What happens to a domain in the file that exists and is `active`?**
Recommend: **import its aliases and leave its state alone.** Import is not a
lifecycle operation, and moving a live domain back to `new` would stop its mail
because a file mentioned it.
