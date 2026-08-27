# Milestone 1 — the routing snapshot

Design for review. **No implementation until this is settled.**

The snapshot is Milestone 1's enforcement boundary. `M1-SCHEMA.md` S-2 makes
snapshot construction — not the repository layer, and not `pigeon check` — the
place where every invariant SQLite cannot express is enforced. Nothing that
writes exists until this does.

Scope is deliberately narrower than the schema document: nine decisions, the
data structure they imply, and the tests that have to catch them being wrong.

---

## 1. Normalised lookup keys and case rules

Two rules, already settled in `M1-SCHEMA.md` C5 and repeated here because the
snapshot is where they are *applied* rather than stored:

| Value | Local part | Domain |
|---|---|---|
| Alias pattern, domain name — addresses Pigeon **is** | folded to lowercase | folded |
| Destination — addresses Pigeon **sends to** | preserved exactly | folded |

Fold where we are authoritative, preserve where we are not.

### Folding without allocating

`pigeon-route`'s module doc commits to allocation-free lookup: "Lookups take
`pigeon_types::Address<'_>` and return borrows into the snapshot. Resolving a
recipient allocates nothing."

An incoming recipient arrives in whatever case the sender used, so it has to be
folded before it can be looked up — and `to_ascii_lowercase()` allocates. The
resolution is that `Address::parse` already bounds both halves: a local part is
at most 64 octets and a domain at most 255, refused otherwise. So folding goes
into a fixed stack buffer sized by those same limits, and the `&str` borrowed
from it is the lookup key.

Nothing longer can reach the snapshot, because nothing that failed
`Address::parse` gets that far. The buffer sizes are therefore not a guess —
they are the limits the parser already enforces, and a change to one is a
change to the other.

ASCII-only folding is correct here rather than merely convenient: SMTPUTF8 is
not advertised (finding 2), so a local part is ASCII by the time it is parsed,
and domains are stored and received as A-labels (C6).

---

## 2. Precedence

The documented chain is:

```text
reject  →  exact alias  →  wildcard (longest match)  →  catch-all  →  reject unknown
```

**Reject is not a tier.** It is the outcome of a rule that matched, and putting
it first in the chain implies a question the schema has already answered:
`UNIQUE (domain_id, pattern)` means one pattern has exactly one rule, so no two
rules of the same specificity can ever both match. There is nothing for a
reject tier to win against at its own level.

What the chain leaves genuinely undecided is whether a *wildcard* reject beats
an *exact* forward — `hello@` explicitly aliased, and `hell*` added later as a
reject. Read as written, reject-first says the explicit alias stops working.

Proposed, and this is the decision most worth reviewing:

```text
most specific matching rule wins:
    exact alias  →  wildcard, longest  →  catch-all  →  reject unknown
and the winning rule's kind decides accept or reject.
```

So a wildcard reject does **not** override an exact alias. The reasoning is
which mistake is recoverable. A broad reject silently disabling an address the
operator explicitly named is mail refused with no diagnostic — the alias is
still listed, still looks correct, and `pigeon route inbound` is the only way to
discover it. An operator who needs an address refused absolutely writes it as an
exact rule, which wins under this ordering and is also what they would write
anyway.

This narrows what `reject` guarantees, so it must be said in the CLI: a reject
rule refuses everything no *more specific* rule claims.

**`ARCHITECTURE.md` §2.3 and `CLI.md` both need the diagram corrected.**

### Ties inside the wildcard tier

"Longest match" is not a total order — `a*c` and `ab*` both match `abc` and are
both three characters. An undefined tie means the same configuration can route
differently between runs, which is the worst possible failure to debug.

Total order, applied in sequence:

1. longer pattern wins
2. then more literal (non-`*`) characters wins
3. then bytewise smaller pattern wins

The third rule is arbitrary and exists only to be total. It is documented as
arbitrary so nobody later reasons from it. Validation *reports* overlapping
wildcards of equal precedence as an ambiguity worth resolving, without blocking
(§7).

---

## 3. Wildcard grammar

Globs, not regular expressions — `CLI.md` already states why: local parts
arrive from the network and a regex engine on untrusted input invites
catastrophic backtracking.

**Exactly one `*`, matching zero or more characters, anywhere in the pattern.
No `?`. No character classes. No escape.**

One `*` is not a stylistic limit; it is what makes the matcher structurally
incapable of backtracking. A pattern splits once into prefix and suffix, and a
candidate matches when:

```text
candidate.len() >= prefix.len() + suffix.len()
    && candidate.starts_with(prefix)
    && candidate.ends_with(suffix)
```

That is linear with no branch on input shape. With two `*` it becomes a search
with backtracking — bounded for globs, but bounded by an argument rather than by
construction, and this is a path reachable by any anonymous sender.

Consequences, both accepted:

- **`*` alone is a valid wildcard alias** matching every local part. It is not
  the same as catch-all: it sits in the wildcard tier, above catch-all, so it
  wins over one. `CLI.md` already relies on this when it explains why
  `alias remove --all` is a flag rather than `*`.
- **A local part containing a literal `*` cannot be aliased.** `*` is in
  RFC 5321's `atext`, so `a*b@example.com` is a legal address this design
  cannot route by an exact rule. Accepted: such addresses do not occur, and an
  escape syntax would be a permanent complication in every pattern anyone ever
  reads to avoid a case nobody has.

Rejected at validation: zero `*` in a pattern stored as a wildcard, two or more
`*`, an empty pattern, or a pattern whose non-`*` characters are not valid in a
local part.

---

## 4. Plus-address stripping order

The order is load-bearing, and the obvious one is wrong.

Stripping before matching means `hello+github@` can never have its own alias.
Matching the full local part first means that on a catch-all domain, every
tagged address hits the catch-all before the alias it belongs to — because
catch-all matches everything, and it would be reached on the first pass.

So neither "strip first" nor "full first" works alone:

```text
1. exact alias for the FULL local part            -> if it matches, done
2. if plus_addressing and the local has a tag, strip it
3. exact alias  ->  wildcard, longest  ->  catch-all   on the resulting key
4. reject unknown
```

The full local part gets exactly one chance, at the exact tier. Everything after
that uses the base. That gives both properties: a dedicated alias for a tagged
address is possible, and a tagged address on a catch-all domain still reaches
the alias its base names.

When nothing is stripped — no tag, or `plus_addressing` off — step 1 and step 3's
exact lookup are the same lookup and happen once. The two steps are written
separately because they answer different questions, not because the work is
done twice.

Details that follow from `Address::local_without_tag`, which already exists:

- The split is on the **first** `+`, so `hello+a+b` has base `hello`.
- A leading `+` is a real local part, not an empty base: `+tag@` has base
  `+tag` and is unchanged. Already tested in `pigeon-types`.
- `hello+@` has base `hello`.
- `plus_addressing` is per domain and defaults on.

**Routing uses the base; delivery keeps the original.** The tag survives into
the forwarded message so the destination mailbox can still filter on it
(README). The snapshot therefore returns the *rule that matched*, never a
rewritten address — anything that rewrote the recipient here would silently
delete the tag.

---

## 5. Inheritance versus explicit destinations

An alias with `kind='forward'` and no rows in `alias_destination` inherits the
domain default. An alias with rows has its own. The distinction is what
`pigeon domain forward` moves and leaves, and encoding inheritance as an
absence gets it right for free (`M1-SCHEMA.md` §4).

**Inheritance is resolved at build time.** The snapshot stores fully-resolved
destination lists, and lookup never consults the domain default.

The alternative — resolving on each lookup — puts a fallback branch on the hot
path that is taken only for inheriting aliases, which is to say a branch that is
rarely exercised and therefore eventually wrong. Resolving once also means the
"inherits, but the domain has no default" case is a *build* failure (§7) rather
than a lookup that returns nothing at the moment a message is being answered.

Catch-all inherits the same way and is resolved the same way. The schema already
refuses an enabled catch-all with no effective destination, including on the
`UPDATE` path; the snapshot re-checks anyway, because the schema's guarantee
covers rows written through SQLite and not a database restored from somewhere
else.

Which aliases inherit is still answerable — it is a query against the database
for `domain forward`'s preview, not a property the snapshot needs to carry.

---

## 6. Loop detection on the prospective snapshot

Ruled in review: in memory, against the post-mutation snapshot, built but not
installed, before the write commits.

The walk is over concrete addresses, which is what makes it terminate:

```text
for each destination D in the proposed snapshot:
    while D's domain is managed here:
        resolve D through the snapshot          (D is concrete; wildcards match it)
        if the resolved rule is a reject or no rule matches: stop, no loop
        if (domain, local) already visited on this walk: LOOP
        follow each destination of the matched rule
```

Destinations are fixed addresses rather than functions of the input, so every
step resolves a concrete address and the set of reachable addresses is finite.
Wildcard and catch-all chains are covered without pattern intersection: a
wildcard is only ever asked whether it matches a concrete address, which it can
answer exactly. `a-*@x → a-1@y` and `a-*@y → a-1@x` is found on the third step.

Two decisions inside it:

- **Enablement is ignored.** A loop through a domain that is currently disabled
  or DNS-gated is still a loop, and it will start looping the moment the domain
  comes back — at which point nobody is looking for a configuration change,
  because there was not one. Loops are a structural property of the
  configuration, not of its current runtime state.
- **A hop limit backstops the visited set.** The visited set is the real
  mechanism; the limit exists because a bug in it should end a build rather
  than a process.

Delivery-time loop detection stays as the backstop for chains that leave and
re-enter through systems Pigeon cannot see — the `Received:` hop count, already
implemented. This check covers what is knowable at configuration time, which is
everything inside the managed set.

---

## 7. What blocks publication

The distinction: **blocking means the snapshot cannot answer correctly.
Non-blocking means it answers correctly and the answer is probably not what the
operator wanted.**

Blocking:

| Failure | Why the snapshot cannot answer |
|---|---|
| `kind='reject'` with destinations | Two contradictory answers for one rule; SQLite cannot express this |
| `kind='forward'`, no destinations, domain has no default | Resolves to nowhere |
| Catch-all enabled with no effective destination | Accepts every address on the domain and routes none |
| Routing loop | The answer does not terminate |
| Destination that fails `Address::parse` | Not a deliverable address |
| Pattern that fails the §3 grammar | No defined match |
| `domain.status` the binary does not recognise | `DomainStatus::from_stored` returns `None`; guessing would either gate a live domain or ungate a broken one |

Non-blocking, reported:

- An alias whose destinations equal the catch-all's — redundant, and meaningful
  again the moment the catch-all destination changes (`CLI.md`).
- Wildcards that overlap at equal precedence (§2).
- A domain that is `active` with `inbound_enabled = 0` — deliberate, and worth
  saying out loud because it looks like a fault.

Behaviour on a blocking failure, by caller:

| Caller | On failure |
|---|---|
| Startup | Abort. It is local and unambiguous — `ARCHITECTURE.md` §5.1 |
| Live reload | Keep the previous snapshot, log loudly. A running server with a stale-but-valid routing table beats one with none |
| Mutation | Refuse the write, inside the transaction, before commit |

---

## 8. Atomic replacement and concurrency

One writer — the daemon — per `ARCHITECTURE.md` §3.3. Many concurrent readers
on the SMTP path.

```rust
struct Router { current: RwLock<Arc<Snapshot>> }
```

A reader clones the `Arc` out under the read lock and then works on its own
handle. The critical section is one atomic increment, so contention is not a
consideration at this scale and `arc-swap` is not worth a dependency.

**A session pins its `Arc` for the whole transaction, and that is correctness
rather than performance.** `RCPT TO` accepts a recipient against the routing
table; the forwarding decision uses it again later. If a reload landed in
between, a message could be accepted under one configuration and delivered
under another — which for a recipient that was removed means accepting mail and
then having nowhere to put it, and Pigeon keeps no copy.

Publication order for a mutation:

```text
BEGIN IMMEDIATE
  apply the change
  build the prospective snapshot from the transaction's own view
  validate it (§7), including loop detection (§6)
  if invalid -> ROLLBACK, report, nothing was published
COMMIT
swap the Arc
```

Building inside the transaction is what makes "prospective" mean anything: the
snapshot is built from exactly the state that is about to become real. Building
before the transaction would validate a state that the write might not produce.

The swap is a single pointer store, so a reader sees the old snapshot or the new
one and never a partial one. Between commit and swap, lookups use the previous
snapshot — a bounded window in which Pigeon is behind its own database, which is
the same window a reload has and is why the routing table is allowed to be
stale but never invalid.

---

## 9. Acceptance tests that resist mutation

Three rounds of findings in `M0-FINDINGS.md` are about tests shaped to pass.
The routing table decides where mail goes, so the tests are specified before the
code and each must be shown to fail when the property it names is broken.

Every mutation below must turn at least one test red:

| Mutation | Property it breaks |
|---|---|
| Wildcard tier consulted before exact | §2 precedence |
| Longest-match replaced with first-match | §2 |
| Wildcard tie-break made non-deterministic | §2 total order |
| Two `*` permitted in a pattern | §3 no-backtracking |
| Tag stripped before the exact-full lookup | §4 — a tagged address loses its own alias |
| Full local matched against catch-all before the base | §4 — tagged mail hits catch-all on a catch-all domain |
| Inheritance resolved to the wrong domain's default | §5 |
| Loop detection stops at depth 1 | §6 — two-hop cycle |
| Loop detection skips disabled domains | §6 |
| Case folding dropped from the lookup key | §1 |
| `reject` treated as `forward` | §2 outcome |
| Snapshot swapped before validation | §8 |
| Snapshot swapped mid-transaction for a live session | §8 pinning |

Two tests carry more weight than the rest:

**The exit criterion is a differential test.** Milestone 1 exits when
`pigeon route inbound user@example.com` exactly predicts runtime routing. That
is asserted by driving the same address through the CLI's resolver and through
the server's recipient check and requiring identical results — over a generated
configuration, not a fixture. The two must call the same function, which makes
the test about wiring rather than logic, which is the point: a second
implementation is how the prediction and the behaviour drift.

**Precedence is property-tested.** Over randomly generated configurations and
addresses, invariants that must hold whatever the shape:

- if an exact alias matches, the result is never the catch-all's destination
- if any rule matches, the result is never `reject unknown`
- resolving the same address twice gives the same answer
- a domain with `accepts_inbound() == false` never resolves anything

---

## 10. Structure this implies

```rust
pub struct Snapshot {
    domains: HashMap<String, Domain>,   // key: folded domain
}

struct Domain {
    gate: DomainGate,                   // status + inbound_enabled, from pigeon-types
    plus_addressing: bool,
    exact: HashMap<String, Rule>,       // key: folded local part
    wildcards: Vec<Wildcard>,           // pre-sorted by §2 precedence
    catchall: Option<Rule>,
}

struct Wildcard { prefix: String, suffix: String, rule: Rule }

enum Rule {
    Reject,
    Forward(Vec<Destination>),          // inheritance already resolved (§5)
}

struct Destination { local: String, domain: String }  // local case preserved
```

Wildcards are sorted once at build time, so the longest match is the first match
and lookup is a scan with an early exit — no comparison of candidates, and no
opportunity for the ordering to be applied inconsistently at two call sites.

Lookup returns a `Decision<'_>` borrowing into the snapshot: the matched rule,
which tier matched, and the destinations. The tier is part of the return because
`pigeon route inbound` prints it, and a second code path that recomputes it
would be a second implementation of §2.
