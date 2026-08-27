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
- **The DKIM startup check refused rather than pretended, until it could
  actually check.** While the workspace carried no RSA implementation, a
  `dkim_key` row that could not be verified stopped startup — which cost nothing
  because no such rows could exist, and was the difference between a deferred
  branch and a comment claiming a guarantee. It performs the real comparison
  now; see §6.
- **Repositories write and do not decide.** `add_alias` does not know whether the
  domain has a default to inherit. That is a property of the resulting
  configuration, and `Snapshot::build` owns it, on the same transaction, before
  it commits.

---

## 5. The `rsa` dependency, and the exception it needed

DKIM key generation needs an RSA implementation. `ring` cannot generate RSA keys
— mail-auth carries the same TODO for the same reason — and every other option
is a TLS backend `deny.toml` bans.

`mail-auth` was probed first, since it is already a declared dependency and has
a `generate` feature. It brings six advisories:

| Advisory | Crate | Arrives via |
|---|---|---|
| RUSTSEC-2026-0118, -0119 | `hickory-proto 0.25` | mail-auth's own resolver — a **second** DNS stack, older than the one Pigeon already has |
| RUSTSEC-2026-0194, -0195 | `quick-xml` | the `report` feature, on by default |
| RUSTSEC-2023-0071 | `rsa` | the `generate` feature |
| RUSTSEC-2025-0134 | `rustls-pemfile` | unmaintained, on by default |

Milestone 1 does not need any of that. It needs key generation, which is `rsa`
alone: one advisory, no second resolver, no XML parser. mail-auth is deferred to
Milestone 2 where signing and verification actually happen, and the duplicate
DNS stack is a decision to make then rather than a consequence to inherit now.

**RUSTSEC-2023-0071 is ignored, narrowly and with the argument written down.**
The Marvin attack is a timing sidechannel in RSA *decryption*: it needs an
oracle that decrypts attacker-chosen ciphertexts while the attacker measures how
long each takes. Pigeon never decrypts. `rsa` generates a keypair in
`pigeon domain add`, which takes no input from anyone and runs once per domain.

That is an argument about what the code does, so **CI checks the code**: a
grep for decryption calls, in the same shape as the existing OpenSSL assertion.
A decryption call would make the exception false without changing the dependency
graph, and nothing else would notice.

The exception is scoped to Milestone 2. Signing is a private key operation over
content somebody else wrote, which is a different argument that has not been
made — and it must use `ring`.

## 6. The deliberate refusal, closed

`check_dkim_keys` refused to start rather than claim a check it could not make.
It now makes the check: the public key is derived from the private key on disk
and compared against the one stored beside it.

An existence check is not the property. A key file replaced during a botched
rotation, or restored from a backup taken before the last one, exists and passes
every permission check — and then signs every message with a key whose public
half is not the one in DNS. Every signature verifies as `dkim=fail`, at the
receiver, silently, while the daemon reports a clean start.

Verified against a real daemon: a domain added, its key swapped for another
valid one, and startup refused with the file named.

Two things fixed while doing it:

- **Every active key is checked, not the first.** A host carrying forty domains
  that stops at the first good one has verified one fortieth of its signing.
- **`pigeond` printed errors with `Debug`.** Returning `Result` from `main` does
  that, which renders a multi-line explanation as one line of escaped `\n`.
  Every startup error here is a paragraph telling an operator what to do, so it
  now prints with `Display`.

Five mutations, all caught: removing the comparison, checking only the first
key, dropping the permission check, deriving the public key from the wrong
private key, and rendering a record with an empty `p=` tag.

---

## 7. Four findings against the DKIM work

### The key was written after the commit

`domain add` committed the row and then wrote the private key. The reasoning was
about the wrong failure: a key file for a domain that does not exist looked like
the thing to avoid, and the opposite — a domain that exists with no usable key —
is worse and was deterministically reachable.

`domain remove` keeps the key file on purpose, because it is the one piece of
state no backup of the database restores. So with `{domain}.key` as the name:

```text
domain add example.com      -> row committed, example.com.key written
domain remove example.com   -> row gone, example.com.key kept
domain add example.com      -> new row committed with a NEW public key
                               create_new refuses the existing file
                               daemon now refuses to start
```

Reproduced against a real daemon before fixing, and the daemon's own message was
the one that named it: *"the DKIM private key ... is not the one published in
DNS."* The startup check caught the damage the command had done.

**Fixed:** a key file name carrying a random component, written and fsynced —
file *and* parent directory — before the transaction opens, so a row can only
name a key that is already durable. A transaction that rolls back removes the
file, since a key belonging to no domain is private key material left behind by
a failed command.

Seven tests now drive the real binary. That level matters: the repository was
correct, the key writer was correct, the transaction was correct, and the
command composed them wrongly. Nothing below the command could see it.

### `Debug` printed the private key

`KeyPair` derived `Debug`, so `{:?}` in a log line, an error, a panic message or
a failing assertion would have written the complete private key wherever that
went. `SECURITY.md` says DKIM private keys are never logged; a derive is how
that stops being true without anyone deciding it.

`to_pkcs8_pem` also returns `Zeroizing<String>`, and the code called
`.to_string()` on it — copying the key into an ordinary `String` that is freed
without being cleared.

**Fixed:** manual redacting `Debug`, `Zeroizing` retained rather than copied out
of, `Clone` removed, and the PEM read at startup zeroized too.

### The recorded algorithm was ignored

`dkim_key.algorithm` was stored and never read. A 1024-bit key recorded as
`rsa2048` matches its own public half perfectly, so every other check passed —
while the record published in DNS advertised a strength the signing key did not
have.

**Fixed:** the key's modulus size is checked against the recorded algorithm, and
`ed25519` is refused explicitly rather than reaching the RSA parser and failing
with a confusing message about PKCS#8.

This also made the tests honest: they generated 1024-bit keys and recorded them
as `rsa2048`, which the check correctly refuses. They now use real 2048-bit
keys, generated once per test binary.

### A comment overclaimed what a feature flag does

`Cargo.toml` said `default-features = false` kept the RSA decryption paths out
of the build. It does not: `rsa`'s features govern encoding and arithmetic, not
which operations exist.

The exception in `deny.toml` is still defensible — RustSec's own guidance is
that the exposure is to *observable* private-key operations and that local use
is acceptable, and Pigeon's use is offline generation and parsing. But it rests
on a **source-use guard**, not on absence from the build, and the comment now
says so.

Five mutations, all caught: the original ordering, a non-unique key name, no
cleanup after rollback, a derived `Debug`, and the algorithm check disabled.

### And a note on how the gates were being read

Two commits in a row went to CI with a clippy failure after a local run I had
called clean. The first was a genuine platform difference —
`clippy::result_large_err` is a byte count against a struct layout, and
`StartupError` crossed 128 bytes on x86_64 and not on aarch64.

The second was not. It reproduced locally the moment the file was touched: the
result I had read was **cached**, and I was grepping its output for lines
starting with `error` rather than checking the exit code. A stale cache
produces no such lines, which reads exactly like success.

Gate runs now check exit codes. Grepping a tool's output for the absence of
something is the same shape of mistake as a comment asserting a guarantee: it
looks like evidence and is not.

---

## 8. `--json` as a versioned API

Treated as a contract rather than a formatting option, which changed what the
work was: the fields were mostly there already, and none of the five rules were.

**Failures wrote no JSON at all.** `--json` printed prose to stderr and left
stdout empty, so a consumer had to check the exit status before deciding whether
there was anything to parse. Now every invocation emits exactly one value, and
`error` is the discriminator — `null` on success, an object with a stable `code`
otherwise. The code is what a script matches; the message beside it is free to
be reworded, which is the point of having both.

**Notes were dropped rather than moved.** `route inbound` carries a standing
caveat that it predicts the control plane and not the daemon, and under `--json`
it was skipped entirely — hiding it from exactly the consumers most likely to
build something on the answer. Notes now go to stderr in JSON mode: still said,
still unable to corrupt the parse.

**`null` versus omitted needed a rule, not a habit.** The one adopted: a field a
command can produce is always present, `null` means it applies and has no value,
and a missing key means only that the producing build did not have the field.
Without that, `format_version` cannot do its job — a consumer has no way to tell
an absent value from an absent feature.

**Confirmation prompts have no JSON form.** A destructive command run without
`--yes` returns `confirmation_required` as a failure rather than a success
object saying "please confirm", because the latter is what a script is least
likely to check and most likely to mistake for the outcome. `--dry-run` is how a
consumer gets the preview as data.

Six mutations, all caught: prose instead of JSON on failure, `format_version`
dropped, `error` omitted on success, a note printed to stdout, the route caveat
dropped, and an empty list emitted as `null`.

### The contract found a test that was conflating the streams

`domain_add.rs` concatenated stdout and stderr into one string. That was
harmless only because `--json` produced no stderr at the time — the moment notes
moved there, it was parsing a JSON value with prose stuck to it, and it failed.

Worth recording because the test was not wrong when it was written. It encoded
an accident of the implementation as though it were a property, and the accident
changed.

---

## What to carry into the rest of Milestone 1
- Live configuration reload, so a mutation reaches a running daemon without a
  restart. Until it exists, the CLI says so after every change.
- `--json` on every read command; several have it, not all.
- Bulk import from an existing forwarding provider.
