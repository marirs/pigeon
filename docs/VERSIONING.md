# Versioning and compatibility

What a version number promises, and what it does not.

---

## Semantic versioning, over four surfaces

Pigeon is a daemon and a CLI rather than a library, so "the API" means the
things an operator or a script actually depends on:

1. **The `--json` output**, which is a contract and carries its own
   `format_version`.
2. **Exit codes**, which scripts branch on.
3. **The configuration file** — every key, and what happens when one is absent.
4. **The database schema**, through the migrations that produce it.

A **major** version may change any of them. A **minor** version adds: a new
command, a new configuration key with a default that preserves current
behaviour, a new field in JSON output. A **patch** version fixes behaviour that
was already wrong.

Adding a field to `--json` output is a minor change, and consumers must ignore
fields they do not know. Removing or renaming one is major. `format_version`
increments only on a major change to that output.

### Before 1.0

Everything above applies from 1.0. Until then the version is `0.x` and the
promises are weaker in exactly one way: a minor version may make a breaking
change, and the release notes will say so at the top rather than in a footnote.
The database migration policy below holds from now, because a database is not
something an operator can re-derive.

---

## Migrations

**Forwards only, automatically, at startup.**

- Every migration is applied in order, in one transaction each.
- A **backup is taken before the first migration of a run** and its path is
  logged. It is not deleted afterwards.
- Each migration's bytes are checksummed and recorded. A migration whose file
  has changed since it was applied is a hard startup failure, not a warning: it
  means the database's history is not what this binary believes it to be.

**There are no down migrations.** A rollback that restores a schema cannot
restore the data a forward migration transformed, and one that pretends to is
worse than none — the pre-migration backup is the rollback, and it is honest
about what it costs.

**An older binary refuses a newer database.** It does not guess at a schema it
does not know, and it says which version it found and which it supports. The
recovery is to install the newer binary, not to repair anything.

### What this means for upgrades

| Situation | What happens |
|---|---|
| Newer binary, older database | migrates forwards, after a backup |
| Same version | nothing |
| Older binary, newer database | refuses to start, names both versions |
| Migration fails halfway | transaction rolls back; the database is unchanged; the backup is still there |

Two nodes should not run different schema versions for longer than a change
window. Nothing breaks — they do not talk to each other — but a routing feature
present on one and absent on the other means mail is accepted or refused
depending on which MX a sender picked, which is the most confusing failure the
two-node design has. See [CLUSTER.md](CLUSTER.md).

---

## Compatibility matrix

What Pigeon is built and tested against.

| | Supported | Notes |
|---|---|---|
| **Rust** | 1.88 (MSRV) and later | pinned by `hickory-resolver`; raising it is a minor version |
| **Edition** | 2024 | |
| **Linux** | x86-64, aarch64 | what CI runs; the packaged systemd unit targets this |
| **macOS** | development only | it builds and the tests pass; nothing about it is deployed or measured |
| **Windows** | no | privilege dropping, `statvfs` and the unit file are all POSIX |
| **SQLite** | bundled | compiled from vendored source, so there is no system version to skew |
| **TLS** | rustls with `ring` | OpenSSL, native-tls and `aws-lc-rs` are refused by `deny.toml` |
| **SMTP** | RFC 5321, 5322, 3207, 4954 | plus DKIM 6376, ARC 8617, SPF 7208, DMARC 7489, DSN 3464, SRS |

The MSRV is a floor rather than a target: Pigeon is built with current stable,
and 1.88 is what the dependency graph currently requires.

---

## What is deliberately not stable

- **Log lines.** Structured fields are for humans and for grep, not for parsing.
  Use `--json` or the metrics endpoint.
- **Metric names**, until 1.0. They are read from the database per scrape, and
  the set will grow.
- **Internal crate boundaries.** The twelve crates are one unit, versioned
  together, and none is published to crates.io.
- **The spool file format.** It is the message as it will be transmitted; what
  is stable is that a spooled file is exactly the bytes that go on the wire.
