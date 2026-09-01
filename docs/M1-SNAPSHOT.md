# Milestone 1 — the routing snapshot

**Implemented.** `crates/pigeon-route`, reviewed and approved as designed below,
with the review's corrections applied before any of it was written.

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

The chain as originally documented, now corrected in `ARCHITECTURE.md` §2.3 and
`CLI.md` following review:

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

**Approved in review. Both diagrams are corrected, and `CLI.md` now states the
narrowed guarantee: a reject rule refuses everything no more specific rule
claims.**

### Ties inside the wildcard tier

"Longest match" is not a total order — `a*c` and `ab*` both match `abc` and are
both three characters.

**A deterministic tie-break makes an ambiguous configuration repeatable, not
correct.** Picking one bytewise still means the operator wrote two rules, one of
them silently never applies, and nothing said so. So determinism is the fallback
and not the answer:

- **Two equal-precedence wildcards that overlap and route differently block
  publication** (§7). The configuration has no right answer and Pigeon does not
  invent one.
- **Two that overlap and route identically are reported as redundant**, in the
  same spirit as a redundant alias against a catch-all: a fact about the
  configuration rather than an error.

Overlap between two one-star patterns `p₁*s₁` and `p₂*s₂` is exact and cheap to
decide: they overlap when one prefix is a prefix of the other *and* one suffix
is a suffix of the other. The `*` absorbs any length, so whenever both ends are
compatible a witness exists — `p_longer` + filler + `s_longer`. No search, no
approximation.

Only equal precedence matters. `shop-*` and `shop-old-*` overlap too, and that
is exactly what the precedence order is for.

Where the order is still needed — ranking non-overlapping candidates against one
address:

1. more literal (non-`*`) characters wins
2. then bytewise smaller pattern wins

The first draft ranked by pattern length and *then* literal count. With exactly
one `*` those are the same number: literal count is always length minus one, so
the second criterion could never break a tie the first had not already broken.
Two rules where one was unreachable.

The bytewise rule is arbitrary and exists only to make the order total for the
cases §7 permits. It is documented as arbitrary so nobody later reasons from it.

---

## 3. Wildcard grammar

Globs, not regular expressions — `CLI.md` already states why: local parts
arrive from the network and a regex engine on untrusted input invites
catastrophic backtracking.

**Exactly one `*`, matching zero or more characters, anywhere in the pattern.
No `?`. No character classes. No escape.**

One `*` is a deliberately smaller grammar, chosen for the matcher and the
precedence order rather than for safety. A pattern splits once into prefix and
suffix, and a candidate matches when:

```text
candidate.len() >= prefix.len() + suffix.len()
    && candidate.starts_with(prefix)
    && candidate.ends_with(suffix)
```

Ten lines, no state, and — the part that actually decides it — an overlap test
between two patterns that is exact rather than approximate (§2). With several
stars, deciding whether two patterns can ever match the same address stops being
a prefix-and-suffix comparison, and the ambiguity rule in §7 becomes something
Pigeon can only guess at.

An earlier draft justified this as preventing catastrophic backtracking. That
was wrong and worth recording as wrong: a multi-star glob matcher runs linearly
with a two-pointer scan and needs no backtracking at all. The argument sounded
like a security property, which is the most expensive kind of comment to leave
standing — the next reader takes it as checked.

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

The order is load-bearing, and every obvious version of it is wrong in a
different way.

Stripping before matching means `hello+github@` can never have its own alias.
Matching the full local part first, all the way down, means that on a catch-all
domain every tagged address hits the catch-all before the alias it belongs to —
catch-all matches everything, so it is reached on the first pass.

An intermediate draft gave the full local part one chance at the exact tier and
then used the base for everything after. That fixed both of the above and broke
something else: **`hello+*` could never match `hello+github`.** The wildcard tier
only ever saw `hello`, which does not start with `hello+`, so a wildcard written
specifically for tagged addresses matched nothing at all. Verified before
correcting it — the pattern's prefix is six characters and the key it was tested
against was five.

The order that holds all three:

```text
1. exact alias, FULL local part
2. exact alias, BASE local part        (only if a tag was stripped)
3. wildcards matching EITHER form, ranked once by §2 precedence
4. catch-all
5. reject unknown
```

Both exact lookups precede every wildcard, so exact-over-wildcard survives. Both
forms are offered to the wildcard tier, so a tagged wildcard works. Catch-all is
not reached until both forms have been considered everywhere else, so tagged
mail on a catch-all domain still finds its alias.

Step 3 ranks the union: every wildcard that matches the full form *or* the base
form competes in one ordering, and the §2 comparison decides. Ranking the two
forms separately would make "the full form is tried first" a hidden fourth
precedence rule.

Details, all from `Address::local_without_tag`, which already exists:

- The split is on the **first** `+`, so `hello+a+b` has base `hello`.
- A leading `+` is a real local part, not an empty base: `+tag@` has base
  `+tag` and is unchanged. Already tested in `pigeon-types`.
- `hello+@` has base `hello`.
- `plus_addressing` is per domain and defaults on. With it off, or with no `+`
  present, there is no base form and steps 1 and 3 see only the full local part.

**Routing uses these forms; delivery keeps the original.** The tag survives into
the forwarded message so the destination mailbox can still filter on it
(README). The snapshot returns the *rule that matched*, never a rewritten
address — anything rewriting the recipient here would silently delete the tag.

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

The walk is over concrete addresses, which is what makes it terminate.
Destinations are fixed addresses rather than functions of the input, so every
step resolves a concrete address and the reachable set is finite. Wildcard and
catch-all chains need no pattern intersection: a wildcard is only ever asked
whether it matches a concrete address, which it answers exactly.

**Depth-first, with a path-local set — not a global one.**

```text
visit(node, on_path, finished):
    if node in on_path:   LOOP, and on_path is the cycle to report
    if node in finished:  return            -- already proved acyclic
    on_path.insert(node)
    for each destination D of the rule matching node:
        if D's domain is managed here: visit(D, on_path, finished)
    on_path.remove(node)
    finished.insert(node)
```

Two sets, doing different jobs. `on_path` is the recursion stack and is what
detects a cycle. `finished` is memoisation and only ever prevents repeated work.

A single global visited set would be wrong, not merely slow: a diamond —
`a → b`, `a → c`, `b → d`, `c → d` — reaches `d` twice by different routes with
no cycle anywhere. A global set reports the second arrival as a loop and refuses
a configuration that is perfectly valid. Fanning one alias out to several
destinations is an advertised feature (`alias add example.com security --to
a@…,b@…`), so diamonds are ordinary rather than exotic. There is a test for
exactly this shape (§9).

Fan-out is explicit above: a rule has a *list* of destinations and every one is
followed.

Two further decisions:

- **Enablement is ignored.** A loop through a domain that is currently disabled
  or DNS-gated is still a loop, and it starts looping the moment the domain
  returns — at which point nobody is looking for a configuration change, because
  there was not one. Loops are structural.
- **The backstop is derived, not fixed.** A constant hop limit rejects a valid
  deep configuration, which is a bug that looks like a policy. The bound is the
  number of concrete nodes in the graph: with a correct `on_path` set, no walk
  can visit more nodes than exist without repeating one. Exceeding it therefore
  proves an implementation error rather than an operator error, and says so.

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
| Wildcard pattern that fails the §3 grammar | No defined match |
| Exact pattern that is not a valid local part | Cannot be the left side of an address, so no message can ever match it |
| Managed domain name that is not a valid normalised A-label | Cannot be compared against an incoming domain that always is |
| Two equal-precedence wildcards that overlap and route differently | §2 — there is no right answer and Pigeon must not invent one |
| `domain.status` the binary does not recognise | `DomainStatus::from_stored` returns `None`; guessing would either gate a live domain or ungate a broken one |

Non-blocking, reported:

- An alias whose destinations equal the catch-all's — redundant, and meaningful
  again the moment the catch-all destination changes (`CLI.md`).
- Two equal-precedence wildcards that overlap and route *identically* —
  redundant rather than ambiguous. One of them never applies, and which one is
  arbitrary, but nothing routes anywhere unexpected.
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

**The `Arc` is pinned per mail transaction, not per connection.**

A transaction is `MAIL FROM` through the end of `DATA`, or through `RSET` —
which is also exactly the span over which a routing decision has to stay
consistent. `RCPT TO` accepts a recipient against the routing table and the
forwarding decision uses it again later; if a reload landed in between, a
message could be accepted under one configuration and delivered under another,
which for a removed recipient means accepting mail with nowhere to put it, and
Pigeon keeps no copy.

Pinning for the *connection* would be a different and worse thing. The session
cap is an hour and a client may send many messages inside it, so a connection
opened before a reload would keep routing against a configuration the operator
has already replaced — indefinitely, from their point of view, with no way to
tell which connections are stale. The snapshot is therefore taken at `MAIL FROM`
and released at the end of that transaction; the next `MAIL FROM` on the same
connection takes a fresh one.

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
| Wildcard tier shown only the base form | §4 — `hello+*` never matches `hello+github`, the bug review caught |
| Ambiguous equal-precedence wildcards published instead of blocked | §2, §7 — a rule the operator wrote never applies and nothing says so |
| Loop detection using one global visited set | §6 — a valid diamond is refused as a loop |
| Backstop made a fixed constant | §6 — a deep but acyclic configuration is refused |
| Exact pattern accepted without local-part validation | §7 |
| Managed domain accepted without A-label validation | §7 |
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
- a configuration that builds has no equal-precedence wildcard ambiguity, and
  one that has any does not build
- every accepted configuration is acyclic, and a diamond is accepted

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

---

## 11. As built

Implemented in `pigeon-route` after review. Where the code and this document
differ, the code is wrong.

| Design | Where |
|---|---|
| §1 folding | `fold.rs` — fixed buffers sized by `Address::parse`'s own limits |
| §2, §3 patterns and ordering | `pattern.rs` — `Wildcard::precedence`, `overlaps` |
| §2, §4, §5, §7 | `snapshot.rs` — `Snapshot::build`, `Snapshot::resolve` |
| §6 loops | `snapshot.rs` — `walk`, DFS with `on_path` and `finished` |
| §8 publication | `router.rs` — `Router::for_transaction`, `publish` |
| Reading rows | `load.rs` — transcribes and decides nothing |

### Every mutation in §9 was executed

Each was applied to the source and the suite re-run. All twelve turned a test
red:

| Mutation | Caught by |
|---|---|
| Exact tier skipped | `an_exact_alias_beats_a_wildcard` |
| Wildcard ordering reversed | `the_most_literal_wildcard_wins` |
| Wildcard tier shown only the base | `a_tagged_wildcard_matches_the_full_local_part` |
| Tag stripped before the exact-full lookup | `a_tagged_address_can_have_its_own_alias` |
| One global visited set | `a_valid_diamond_is_not_a_loop` |
| Ambiguity reported instead of blocked | `ambiguous_equal_precedence_wildcards_block_publication` |
| Case folding dropped | `lookup_folds_case_on_both_halves` |
| Reject treated as forward | `a_wildcard_reject_does_not_disable_a_more_specific_exact_alias` |
| Loop detection respecting enablement | `a_loop_through_a_disabled_domain_still_blocks_publication` |
| Two stars permitted | `more_than_one_star_blocks_publication` |
| Exact patterns unvalidated | `a_malformed_exact_alias_blocks_publication` |
| Domain A-label check dropped | `a_malformed_managed_domain_blocks_publication` |

One mutation appeared not to be caught and was mine rather than the suite's:
`Ok(()).and(Err(e))` still returns `Err(e)`, so it changed nothing. Re-run
properly, it was caught. Worth recording, because a mutation that does not
mutate reads exactly like a test that does not test.

### What is built and serving

The routing table is loaded, validated and reported at startup, and since
Milestone 3 it is what decides acceptance and delivery: `RCPT TO` resolves
against the published snapshot and the resolved destinations become queue rows.
`PIGEON_ACCEPT` and `PIGEON_FORWARD_TO` are retired.

Wiring acceptance alone would have accepted mail for an address on the strength
of a rule and then ignored where that rule points. Connecting both means fanning
one message out to several destinations, each needing independently durable state
so a retry knows which already received it — which is Milestone 3. That criterion
formally moved there; the reasoning is in `M1-FINDINGS.md` §1.
