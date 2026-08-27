# Milestone 1 — database schema and configuration

Design for review. **No implementation until this is settled**, because the
schema constrains every other Milestone 1 deliverable and the cost of changing
it rises with each one built on top.

Two parts, in the order they have to be decided:

1. The migration contract — what a migration is allowed to be, and what the
   runner guarantees. This comes first because it determines whether a mistake
   in part 2 is recoverable.
2. The schema itself, then the configuration shaped around what it needs at
   startup.

---

## 1. Scope

### In Milestone 1

`schema_migration`, `setting`, `domain`, `destination`, `alias`,
`alias_destination`, `dkim_key`, and the outbound identity tables
(`sender_identity`, `principal`, `principal_grant`, `relay`).

### Deferred, and the rule that decides it

The roadmap already says the outbound tables are created here "even though
nothing uses them until Milestone 7", because "retrofitting the identity model
later is far more disruptive than carrying unused tables". That is the right
call, but it is stated as a fact about one case rather than as a rule, so here
is the rule it generalises to:

> **Carry a table early when its shape constrains other tables. Defer it when
> it is additive.**

The identity model is relational — `principal_grant` sits between two tables
that both have to exist and both have to have settled primary keys. Adding it
later means either a migration that rebuilds neighbours or a compromise in how
it references them.

By that rule:

| Table | Milestone | Why |
|---|---|---|
| outbound identity tables | **M1** | Relational; constrains `domain` and `sender_identity` shape |
| `queue_message`, `queue_recipient`, `delivery_attempt` | M3 | Self-contained; references `domain` by an FK that will exist |
| `domain_check` (health, transitions, cooldown) | M5 | Per-domain scalars; purely additive |

Deferring is not a smaller decision than carrying. A migration that adds a
column is routine; one that adds a table whose foreign keys point *into*
existing rows is where the data has to be invented.

---

## 2. Migration invariants

The runner is small. The invariants are the product.

### I1 — Forward only. No down migrations.

There is no `down`. The recovery path for a bad migration is restore from
backup, and saying so is more honest than shipping reverse scripts that are
exercised far less than the forward ones and are trusted at exactly the moment
things have already gone wrong.

This is a stronger commitment than it sounds: it means **every migration must
be safe to apply to a database carrying real mail configuration**, because the
only way out is a restore.

### I2 — Append-only and immutable once released.

A migration that has shipped is never edited. Not to fix a typo in a comment,
not to add a column it should have had.

Enforced rather than requested: the runner stores a checksum of each
migration's text and refuses to start if a migration already applied does not
match the one in the binary. A developer who edits migration 3 after it has run
on their own machine finds out immediately, which is where that mistake is
cheap.

### I3 — One transaction per migration, including its version row.

SQLite runs DDL inside transactions, unlike MySQL. So a migration and the row
recording it commit together, and there is no state in which a migration is
half-applied or applied-but-unrecorded.

Two pragmas cannot participate and are therefore set outside, on the
connection, before any migration runs:

- `journal_mode = WAL` — persistent, set once at database creation.
- `foreign_keys = ON` — **per connection, not persistent.** Every connection
  the daemon or CLI opens must set it. This is the single most common way a
  SQLite schema's referential integrity turns out to be decorative.

### I4 — Versions are dense, ordered integers.

`1, 2, 3, …`, applied in order, no gaps. A gap means a migration was lost in a
merge; the runner refuses rather than skipping it.

### I5 — A database from the future stops startup.

If the database records version 9 and the binary knows 7, the runner aborts.

This is the downgrade case, and silence would be the worst outcome: a binary
that does not know about a column keeps working, writes rows that the newer
schema's constraints would have rejected, and the damage is discovered after
the next upgrade.

### I6 — The runner holds a write lock for the whole run.

`BEGIN IMMEDIATE` before reading the current version, so two processes starting
at once cannot both decide migration 5 needs applying. The daemon and the CLI
can both be launched by an operator in the same second.

### I7 — Only the daemon migrates.

The CLI opens the database read-only for read commands and routes mutations
through the daemon's Unix socket (`ARCHITECTURE.md` §3.3). It never migrates.

A CLI meeting a database older than it knows reports the version mismatch and
exits, rather than reading a schema it will misinterpret. Offline mutation,
which `CLI.md` permits when the daemon is stopped, is the one exception and
takes the same lock.

### I8 — `foreign_key_check` after every run.

Cheap at this scale, and the alternative is discovering a violated constraint
during a delivery.

### I9 — `user_version` mirrors the table.

`schema_migration` is authoritative — it carries names, checksums and
timestamps. `PRAGMA user_version` is set to the same number so an operator with
nothing but `sqlite3` can read it in one line.

### Open question M-1

Should migrations be embedded `.sql` files (`include_str!`) or Rust functions?

**Recommend: `.sql` files, embedded.** A migration is then reviewable as
SQL, checksummable as text, and reproducible by hand against a backup. Rust
migrations are only needed for data transforms that SQL cannot express, and the
moment one is needed it can be added as a separate mechanism rather than
shaping every migration around the possibility.

---

## 3. Conventions

### C1 — `STRICT` tables

Every table is `STRICT` (SQLite ≥ 3.37). Without it, SQLite's type affinity
will happily store `"active"` in an `INTEGER` column and the mistake surfaces
as a routing failure. `rusqlite`'s `bundled` feature pins the version, so this
is our decision to make rather than the host's.

### C2 — Timestamps are `INTEGER` Unix seconds, UTC

Not ISO-8601 text. Text invites format drift between writers, sorts correctly
only by luck, and needs parsing before arithmetic — and the queue in Milestone
3 does arithmetic on every retry.

The readability cost is one view:

```sql
CREATE VIEW domain_readable AS
  SELECT name, status, datetime(created_at, 'unixepoch') AS created_at FROM domain;
```

### C3 — Internal integer keys, natural keys in the JSON contract

Tables use `INTEGER PRIMARY KEY` (a rowid alias) for foreign keys. Those
integers are **never** exposed in `--json`.

`CLI.md` calls `--json` a stable contract. A rowid is not stable — it changes
when a domain is removed and re-added, and it means nothing to a reader. What
identifies a domain is its name, and what identifies an alias is its domain and
pattern. Queue message IDs are the exception, being opaque handles by design.

### C4 — Enumerations are `TEXT` with a `CHECK`

`status TEXT NOT NULL CHECK (status IN ('new','pending_dns',…))`.

An operator reading the database with `sqlite3` during an incident should not
have to look up what `3` means. The storage cost is irrelevant at this scale
and the `CHECK` gives the same guarantee an integer enum was reaching for.

### C5 — Address case: two different rules, deliberately

This is the one convention most likely to look like an inconsistency later, so
it is written down with its reasoning.

| Value | Local part | Domain |
|---|---|---|
| **Alias pattern** (an address Pigeon *is*) | lowercased on write | lowercased |
| **Destination** (an address Pigeon *sends to*) | **preserved exactly** | lowercased |

RFC 5321 §2.4 reserves interpretation of a local part to the host named in the
domain. For an alias, **Pigeon is that host**, so Pigeon may decide that
`Hello@example.com` and `hello@example.com` are the same mailbox — and should,
because every mail system does and the alternative surprises everyone.

For a destination, Pigeon is a relay and cannot know. Finding 12 is exactly
this mistake made in the other direction: folding a destination's local part
merged two recipients and dropped one silently.

So the rule is not "fold case" or "do not fold case". It is: **fold where we
are authoritative, preserve where we are not.**

Both columns additionally carry `COLLATE NOCASE` on the domain half, so a
hand-edited row cannot create a duplicate that the application's normalisation
would have prevented.

### C6 — Internationalised domains are stored as A-labels

Punycode, normalised on write. DNS lookups, DKIM selectors and `Received:`
headers all use the A-label; storing the U-label would mean converting at every
read and getting it wrong somewhere.

### Open question C-1

`local` and `domain` as separate columns, or one `address` column?

**Recommend: separate.** It is the only way the two case rules in C5 can be
expressed as column collations rather than as application discipline, and
`destination list` needs to group by domain.

---

## 4. Schema

### `schema_migration`

```sql
CREATE TABLE schema_migration (
    version    INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    checksum   TEXT    NOT NULL,   -- SHA-256 of the migration text; see I2
    applied_at INTEGER NOT NULL
) STRICT;
```

### `setting`

```sql
CREATE TABLE setting (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
```

Runtime-tunable values that are not machine identity — retention windows, retry
bounds. Machine identity stays in TOML (§5). The boundary: **if changing it
requires a restart, it is TOML; if it can take effect on reload, it is here.**

### `destination`

```sql
CREATE TABLE destination (
    id      INTEGER PRIMARY KEY,
    local   TEXT NOT NULL,                  -- case preserved: see C5
    domain  TEXT NOT NULL COLLATE NOCASE,
    UNIQUE (local, domain)
) STRICT;
```

A normalised table rather than address text repeated in three places, because
of what `CLI.md` asks for:

- `destination list` reports, per mailbox, how many aliases and domains use it
  and how many domains default to it. With a shared row that is three counts
  over foreign keys; with repeated text it is a `UNION` and a `GROUP BY` that
  has to re-apply the normalisation rules at query time.
- `destination replace old new` repoints every use — aliases, catch-alls and
  domain defaults — optionally narrowed to one domain. That is repointing
  foreign keys, which is a bounded operation with an exact preview.

Every reference uses `ON DELETE RESTRICT`. A destination is deleted only by an
explicit prune of unreferenced rows, so no path can orphan a mailbox that is
still routing.

### `domain`

```sql
CREATE TABLE domain (
    id                      INTEGER PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE COLLATE NOCASE,

    status                  TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','pending_dns','ready','active','suspended','error')),

    inbound_enabled         INTEGER NOT NULL DEFAULT 1 CHECK (inbound_enabled IN (0,1)),
    outbound_enabled        INTEGER NOT NULL DEFAULT 0 CHECK (outbound_enabled IN (0,1)),

    delivery_mode           TEXT NOT NULL DEFAULT 'direct'
        CHECK (delivery_mode IN ('direct','relay')),
    relay_id                INTEGER REFERENCES relay(id) ON DELETE RESTRICT,

    default_destination_id  INTEGER REFERENCES destination(id) ON DELETE RESTRICT,

    catchall_enabled        INTEGER NOT NULL DEFAULT 0 CHECK (catchall_enabled IN (0,1)),
    catchall_destination_id INTEGER REFERENCES destination(id) ON DELETE RESTRICT,

    plus_addressing         INTEGER NOT NULL DEFAULT 1 CHECK (plus_addressing IN (0,1)),
    forward_policy          TEXT NOT NULL DEFAULT 'preserve'
        CHECK (forward_policy IN ('preserve','rewrite_from')),

    notify_destination_id   INTEGER REFERENCES destination(id) ON DELETE RESTRICT,

    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,

    -- Catch-all is never enabled implicitly, and a destination for a disabled
    -- catch-all is a contradiction that would route mail after a later enable.
    CHECK (catchall_enabled = 1 OR catchall_destination_id IS NULL),
    -- Relay delivery without a relay is a domain that cannot send.
    CHECK (delivery_mode = 'direct' OR relay_id IS NOT NULL)
) STRICT;
```

`outbound_enabled` defaults to `0` while `inbound_enabled` defaults to `1`.
That asymmetry is the point: forwarding is what the operator asked for by
adding the domain, and the authority to *send* as it is a separate grant
(`OUTBOUND.md`, identity model).

Catch-all lives as two columns rather than its own table because a nullable
foreign key alone cannot distinguish *enabled, inheriting the domain default*
from *disabled*. The flag plus the `CHECK` encodes both states without a 1:1
table.

### `alias`

```sql
CREATE TABLE alias (
    id          INTEGER PRIMARY KEY,
    domain_id   INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,

    pattern     TEXT NOT NULL,              -- lowercased: see C5
    kind        TEXT NOT NULL DEFAULT 'forward' CHECK (kind IN ('forward','reject')),

    -- Generated, not stored by the application, so it cannot drift from the
    -- pattern it describes.
    is_wildcard INTEGER GENERATED ALWAYS AS (instr(pattern, '*') > 0) VIRTUAL,

    created_at  INTEGER NOT NULL,
    UNIQUE (domain_id, pattern)
) STRICT;

CREATE INDEX alias_by_domain ON alias(domain_id);
```

### `alias_destination`

```sql
CREATE TABLE alias_destination (
    alias_id       INTEGER NOT NULL REFERENCES alias(id)       ON DELETE CASCADE,
    destination_id INTEGER NOT NULL REFERENCES destination(id) ON DELETE RESTRICT,
    PRIMARY KEY (alias_id, destination_id)
) STRICT;
```

Three alias states, and how they are distinguished:

| State | Encoding |
|---|---|
| Own destinations | `kind='forward'`, one or more rows here |
| Inherits the domain default | `kind='forward'`, **zero** rows here |
| Reject | `kind='reject'`, zero rows here |

"Zero destinations" meaning two different things is why `kind` is an explicit
column rather than inferred from the absence of rows.

The distinction between *inherits* and *has an explicit destination that
happens to equal the default* is load-bearing. `pigeon domain forward` moves
the first and leaves the second, and `CLI.md` shows exactly that split in its
preview. Encoding inheritance as an absence gets this right for free; storing
the resolved destination on every alias would lose it.

**Invariant not expressible in SQLite:** `kind='reject'` implies no rows in
`alias_destination`. SQLite `CHECK` cannot reach another table. Enforced in the
repository layer and asserted by `pigeon check`. Flagged here because an
invariant the database cannot hold is one that needs a named owner — see open
question S-2.

### `dkim_key`

```sql
CREATE TABLE dkim_key (
    id               INTEGER PRIMARY KEY,
    domain_id        INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
    selector         TEXT NOT NULL,
    algorithm        TEXT NOT NULL DEFAULT 'rsa2048' CHECK (algorithm IN ('rsa2048','ed25519')),
    public_key       TEXT NOT NULL,   -- base64 SPKI, for rendering the TXT record
    private_key_path TEXT NOT NULL,   -- on disk, 0600; never in this database
    state            TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','retiring','retired')),
    created_at       INTEGER NOT NULL,
    retired_at       INTEGER,
    UNIQUE (domain_id, selector)
) STRICT;
```

Private key material stays on disk and out of the database, so a database
backup or a `sqlite3` session cannot leak it (`SECURITY.md`). The cost is that
the two can drift — a row whose key file has been deleted — which is precisely
why "missing DKIM private key for a signing domain" is on the startup-abort
list, and why §5 makes that cross-check an explicit startup step rather than a
lazy failure at first signature.

`state` supports selector rotation and the optional ed25519 second selector
(Milestone 5) without a schema change: multiple `active` rows per domain, at
most one per algorithm.

### Outbound identity tables

Created now, used in Milestone 7. Per the rule in §1: this is the relational
part that would be disruptive to retrofit.

```sql
CREATE TABLE relay (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL DEFAULT 587,
    username     TEXT,
    secret_ref   TEXT,          -- reference, never the secret: see SECURITY.md
    created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE sender_identity (
    id         INTEGER PRIMARY KEY,
    domain_id  INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
    local      TEXT NOT NULL,   -- lowercased: Pigeon is authoritative here (C5)
    created_at INTEGER NOT NULL,
    UNIQUE (domain_id, local)
) STRICT;

CREATE TABLE principal (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,     -- generated, e.g. pg_7N...
    password_hash TEXT NOT NULL,            -- Argon2id; never the password
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
) STRICT;

CREATE TABLE principal_grant (
    id           INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL REFERENCES principal(id) ON DELETE CASCADE,
    domain_id    INTEGER NOT NULL REFERENCES domain(id)    ON DELETE CASCADE,
    -- NULL means the whole domain: `pigeon auth allow name '*@example.com'`.
    local        TEXT,
    created_at   INTEGER NOT NULL
) STRICT;

-- Two partial indexes, not one UNIQUE constraint. See below — this is the one
-- place in this schema where the obvious spelling is silently wrong.
CREATE UNIQUE INDEX principal_grant_identity
    ON principal_grant(principal_id, domain_id, local) WHERE local IS NOT NULL;

CREATE UNIQUE INDEX principal_grant_domain_wide
    ON principal_grant(principal_id, domain_id) WHERE local IS NULL;
```

`principal_grant` references `domain` and an optional local part rather than
`sender_identity(id)`, so that a domain-wide grant is one row and does not have
to be expanded across every identity or re-expanded when one is added. It also
means revoking an identity does not silently narrow a domain-wide grant.

`relay.secret_ref` names a protected file rather than holding a password, per
`SECURITY.md`'s preference ordering.

**The two partial indexes replace a `UNIQUE (principal_id, domain_id, local)`
that does not work.** SQL treats NULLs as distinct inside a `UNIQUE`
constraint, so with `local` nullable that spelling permits any number of
identical domain-wide grants. It reads as correct and is not.

The consequence is a revocation that does not revoke: `pigeon auth allow mac
'*@example.com'` run twice leaves two rows, `pigeon auth revoke` removes one,
the command reports success, and the principal still holds the whole domain.
That is a security property failing quietly, which is the worst shape for one
to fail in.

The partial indexes state the two real rules separately — at most one grant per
identity, and at most one domain-wide grant. A domain-wide grant and a specific
grant may still coexist, which is intentional and harmless because
authorisation is a union; it does mean the CLI must report the *effective*
grant rather than a row count.

This was found by applying the schema to SQLite rather than by reading it (§7).

---

## 5. Configuration, shaped around what the schema needs

`pigeon-config` holds machine identity only. The boundary is already stated in
its module docs and in `ARCHITECTURE.md` §4; what follows is what the schema
above forces it to carry and to check.

```toml
hostname = "mx1.yourserver.net"
database = "/var/lib/pigeon/pigeon.db"
spool    = "/var/spool/pigeon"
keys     = "/var/lib/pigeon/keys"

srs_secret_file = "/var/lib/pigeon/srs.key"

[smtp.inbound]
listen = "0.0.0.0:25"

[smtp.submission]
listen           = "0.0.0.0:587"
require_starttls = true
tls_certificate  = "/etc/pigeon/tls/fullchain.pem"
tls_private_key  = "/etc/pigeon/tls/privkey.pem"

[alerts]
enabled  = true
identity = "pigeon@ops.example.com"
to       = "me@example.net"
confirm_checks    = 3
cooldown          = "6h"
breaker_threshold = 0.5
```

Two fields exist because of decisions above:

- **`keys`** — `dkim_key.private_key_path` is stored per row, but the directory
  is machine-level and its permissions are a startup check. A per-row absolute
  path with no configured root would let a hand-edited row point anywhere,
  which is the path-traversal case `SECURITY.md` names. Stored paths are
  resolved against `keys` and required to stay inside it.
- **`srs_secret_file`** — the SRS secret must be stable across restarts, or
  every bounce return path issued before the restart stops verifying. It is a
  secret, so it is a `0600` file referenced by path rather than a value in a
  TOML that is convenient to make readable.

### Startup ordering

The order is forced by the dependencies, and getting it wrong means either
checking something that is not loaded yet or binding a listener before the
system is known to work.

```text
1  load and parse TOML                          — no I/O beyond the file
2  validate local paths and permissions         — database dir, spool, keys 0700,
                                                  TLS material readable if submission
                                                  requires it, SRS secret present 0600
3  open the database, set pragmas               — WAL, foreign_keys, busy_timeout
4  run migrations                               — I3–I8; abort on any failure
5  cross-check config against schema            — see below
6  prepare the spool                            — create, probe write/fsync/remove
7  build the routing snapshot                   — the first read of the new schema
8  bind listeners
9  serve
```

Step 5 is the step that only exists because of this schema, and it is three
checks that can each abort startup:

1. **Every `dkim_key` row in state `active` for a domain that signs has a
   readable private key at its path, `0600`, inside `keys`.** This is the
   `SECURITY.md` startup-abort item made concrete. It cannot happen earlier —
   the rows are not readable until migrations have run.
2. **`alerts.identity`'s domain is not a row in `domain`.** `ALERTING.md` is
   explicit that an alert must never be sent as a domain under test, and that
   the failure mode is silent: the alert is destroyed by the fault it reports.
   Config alone cannot check this; it needs the domain table.
3. **`hostname` resolves and its reverse DNS agrees.** DNS, and therefore *not*
   a startup abort — this one gates nothing and is reported as a warning, per
   the local-versus-remote split in `ARCHITECTURE.md` §5.1.

That third item is the reason this list is worth writing down. Two of these
three look identical when read as "validate configuration at startup", and one
of them must not stop the daemon.

---

## 6. Open questions

Decisions I have taken a position on but that change work downstream, so worth
settling before code exists.

**S-1 — Is `destination` normalised, or is address text repeated?**
Recommend normalised (§4). Cost: a prune step and one more join when loading
the snapshot. Benefit: `destination list` and `destination replace` become
foreign-key operations with exact previews, and the case rules in C5 live in
column collations rather than in every query.

**S-2 — Who owns the invariants SQLite cannot express?**
`kind='reject'` implies no destinations; a domain's default destination must
not create a routing loop; a redundant alias must be reported, not rejected.
Recommend: the repository layer enforces on write, and `pigeon check` verifies
the whole database — so an invariant violated by a hand-edited row is found by
a command rather than by a message going to the wrong place. The alternative is
SQLite triggers, which are invisible in code review and hard to test.

**S-3 — Where does loop detection read from?**
Configuration-time loop detection walks destination → managed domain → alias →
destination. Recommend it runs against the **in-memory routing snapshot**, not
against SQL, so the CLI's prediction and the daemon's routing cannot diverge —
which is Milestone 1's exit criterion stated as a design constraint rather than
as a test.

**S-4 — Does `--json` expose a schema version?**
Recommend yes: a top-level `"schema": <n>` on every read command. `CLI.md`
promises `--json` is stable across releases; a consumer that can see the
version can tell a stable field from a new one.

**C-1, M-1** — stated inline above.

---

## 7. Verification

This schema was applied to SQLite 3.51.0 before being proposed, rather than
reviewed as text. Given how much of this document is an argument that a
constraint written down is not a constraint enforced, proposing an unexecuted
schema would have been the wrong shape of mistake to make.

What was checked, and held:

| Claim | Result |
|---|---|
| All 11 tables create, in dependency order | pass |
| `STRICT` rejects `TEXT` in an `INTEGER` column | pass — refused at insert |
| `is_wildcard` generates correctly | `hello` → 0, `shop-*` → 1 |
| Catch-all destination without the flag is refused | `CHECK` fired |
| `delivery_mode='relay'` without a relay is refused | `CHECK` fired |
| `domain.name` folds case | `EXAMPLE.COM` rejected as duplicate |
| `destination` folds the domain, preserves the local part | `me@EXAMPLE.net` rejected as duplicate; `Me@example.net` accepted as distinct |
| A destination in use cannot be deleted | `FOREIGN KEY constraint failed` |
| Deleting a domain cascades to its aliases | pass |

What did **not** hold, and is the reason this section exists:

**`UNIQUE (principal_id, domain_id, local)` accepted two identical domain-wide
grants.** SQL treats NULLs as distinct inside `UNIQUE`. Two rows went in
cleanly. Corrected to the two partial indexes in §4, and re-verified: the
second domain-wide grant is now refused, a duplicate identity grant is refused,
and a domain-wide grant coexisting with a specific one is still allowed.

An audit of every other `UNIQUE` in the schema found no second instance —
`principal_grant.local` is the only nullable column inside one.

---

## 8. Before implementation

`rusqlite` was declared in `workspace.dependencies` but used by no crate, so it
had never been resolved and was absent from `Cargo.lock`. Since it pulls in
`libsqlite3-sys` and vendored C into a workspace with a hard OpenSSL ban, it was
resolved temporarily and put through the existing gates before this design was
proposed, then reverted — a dependency that failed them would change the plan
rather than delay it.

| Gate | Result |
|---|---|
| `cargo check -p pigeon-db` | builds |
| `cargo deny check` | advisories, bans, licences, sources — all ok |
| No-OpenSSL dependency-tree assertion (`--target all`) | 0 matches |
| MSRV 1.88.0 | builds |
| Bundled SQLite version | **3.51.3** |

3.51.3 clears both version floors this design depends on: `STRICT` needs 3.37
and generated columns need 3.31. Because `bundled` compiles vendored source,
that version travels with the binary rather than depending on the host — so
`STRICT` is available everywhere Pigeon runs, not merely everywhere it was
built.

Worth noting for whoever implements this: the verification in §7 ran against
the host's SQLite 3.51.0, one patch release behind the bundled 3.51.3 that will
actually execute it. Nothing here is near a version boundary, but the schema
tests should run through `rusqlite` rather than the `sqlite3` binary, so what
is tested is what ships.
