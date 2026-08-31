# Milestone 2 — Message authentication

Design for review. **No implementation exists**, and none should begin until the
rulings in §9 are settled: several of them change what the other sections mean.

Milestone 2 is the go/no-go. Everything before it is plumbing and everything
after it is hardening — if forwarded mail does not land with `dmarc=pass`,
nothing else matters. The design is therefore written to be *falsifiable*: every
claim about bytes, ordering or failure handling names the test that would catch
it being wrong, and §8 lists what has to be measured before code rather than
asserted in a comment.

Companion documents: `M1-SCHEMA.md` (the `dkim_key` table, `srs_secret_file`,
the `keys` root), `M0-FINDINGS.md` findings 22 and 25 (the body round-trip),
`SECURITY.md` (path containment), `deny.toml` (the RustSec exception this
milestone is required to revisit).

---

## 1. What breaks when mail is forwarded, and what fixes it

A forwarded message arrives at the destination from Pigeon's IP, carrying the
original author's `From:`. Three things are then true:

- **SPF fails**, because the original domain does not authorise Pigeon's IP.
- **DKIM survives** if — and only if — the bytes it signed are unchanged.
- **DMARC passes** only on an *aligned* pass, which after a forward means DKIM
  alignment on the `From:` domain, since SPF alignment is gone.

So DKIM is the load-bearing mechanism, SRS exists to give SPF a domain that does
authorise this host (and to give bounces somewhere to go), and ARC exists for
the case where DKIM breaks anyway — a mailing list rewrote the subject, a
gateway re-encoded the body — by recording what authenticated *on arrival* and
signing that record.

This ordering is worth stating because it decides the failure priorities. A bug
that breaks DKIM loses mail to strict domains. A bug in ARC loses only the
recovery path. A bug in SRS loses bounces, which is invisible until someone asks
why they never learned a message was undeliverable.

---

## 2. The payload contract

`ForwardPolicy::Preserve` currently promises the body is relayed "byte for
byte", and `pigeon-auth`'s module docs repeat it. That is not achievable, and
saying it twice does not make it so — RFC 5321 requires the end-of-data marker
to begin a line, so a body whose final line is unterminated *must* gain a CRLF.
Finding 25 records this. The blanket promise is replaced here by an exact
statement of which bytes cross which boundary unchanged.

### 2.1 The boundaries

| Boundary | Form |
|---|---|
| **Wire → receipt** | dot-unstuffed; terminator removed; every other byte as sent |
| **Receipt → verification** | *exactly* the receipt bytes, unmodified |
| **Verification → normalised** | bare CR and bare LF → CRLF, **across the whole payload, headers included** |
| **Normalised → relay form** | + envelope rewrite, prepended headers, Pigeon's DKIM signature, ARC set |
| **Relay form → spool** | byte-identical to the relay form |
| **Spool → wire** | dot-stuffed; CRLF added before the marker if not at a line start |

**Nonconforming input is not byte-preserved, and the promise says so.** A payload
containing a bare CR or bare LF — anywhere, header or body — is transport-
converted before Pigeon signs or stores anything. RFC 6376 §5.3 puts that
conversion *before* signing, which is where this sits. What is preserved
byte-for-byte is a conforming payload: CRLF line endings throughout.

The middle row is the only one that changes bytes, and it changes them *once*,
before anything is signed or stored. Everything downstream of it — spooling,
retries, sealing, transmission — operates on one immutable buffer. A retry that
re-derived the relay form would be a second chance to derive it differently.

### 2.2 What `DataReader` does today, measured

Read from `crates/pigeon-smtp/src/codec.rs`, not from its comments:

- A line ends at CRLF. `Scan::LineStart` is entered **only** after CRLF, so
  dot-unstuffing is CRLF-relative, matching what a conforming receiver does.
- A **bare LF is preserved verbatim** and does not start a line.
- A **bare CR is preserved verbatim**, including the malformed `.` + CR case.
- The terminator is `CRLF.CRLF` and nothing else, which is the correct strict
  behaviour and is what makes Pigeon itself immune to inbound SMTP smuggling.
- Over `max_message_size` the bytes are dropped while scanning continues, so the
  session is still answered properly rather than desynchronised.

### 2.3 Headers are part of the problem, not just the body

Pigeon cannot be smuggled *into*: the reader accepts only `CRLF.CRLF`. What it
can do is *carry* a smuggling primitive. A body containing `LF . LF` relayed
verbatim to a receiver whose parser is lax terminates that receiver's DATA early
and injects everything after it as a new message, from Pigeon's IP, with
Pigeon's reputation.

This is the 2023–24 SMTP smuggling class, and a forwarder is the ideal
amplifier for it: it is precisely a machine that takes bytes from a stranger and
re-emits them from a trusted host.

**And the header block is not exempt.** A bare CR or LF inside a header is read
as a line break by some parsers and as an ordinary octet by others, which makes
the same bytes two different header sets depending on who reads them — header
injection by disagreement rather than by an unescaped newline. Normalisation
therefore covers the entire DATA payload, not the body alone. Restricting it to
the body would leave the more interesting half untouched.

### 2.4 Dot-stuffing is not the place to fix it

Stuffing conservatively — treating a bare LF as a line start when writing —
looks like a defence and is a corruption. A conforming receiver unstuffs only
after CRLF, so the extra dot stays in the delivered body. The choice is between
changing the body deliberately at one boundary (R-1) and shipping the primitive;
it is not available at the stuffing layer, and the existing comment in
`client.rs` explaining why the writer counts only CRLF is correct and should
stay.

### 2.5 The CRLF the marker requires

Unchanged from M0 and stated once, precisely: if the relay form does not end at
a line start, a CRLF is appended before `.CRLF`. It is DKIM-safe — RFC 6376
§3.4.3 has the signer's body canonicalisation add the same CRLF — but it is a
byte the sender did not send, and anyone diffing a spooled message against a
capture will see it.

---

## 3. Authentication ordering

The order is not a preference. Each step consumes a state the next step
destroys.

```text
1. receive              exact bytes, no modification
2. verify               SPF, DKIM, ARC chain — against those exact bytes
3. evaluate DMARC       against the ORIGINAL From:, using step 2's results
4. record               Authentication-Results / ARC-AAR from steps 2-3
5. normalise            bare CR/LF -> CRLF across the whole payload (R-1)
6. rewrite              envelope sender via SRS; From: if rewrite_from;
                        prepend Received and Authentication-Results
7. sign                 Pigeon's own DKIM signature — mandatory for rewrite_from
8. seal                 ARC set over the finished outbound form
9. spool                exactly what step 8 produced
```

Steps 5-7 are all "Pigeon's changes", and **the seal comes after every one of
them**, Pigeon's own DKIM signature included. RFC 8617 requires the ARC set to
be computed over the message as it leaves; a seal taken before the DKIM
signature is added covers a message that is not the one sent.

**Verify before mutate.** Any header Pigeon prepends is a header the original
DKIM signature did not cover, and an `h=` list that oversigns an absent header
turns an added one into a break. Normalising the body before verification would
be worse still: the verdict would describe a message that never arrived.

**DMARC against the original identities.** After step 5 the envelope sender is
an SRS address in a Pigeon-owned domain, and evaluating alignment against that
would return a meaningless pass. DMARC alignment is computed against the
`From:` domain as received, with the SPF and DKIM results from step 2.

**Seal last, and seal what is sent.** The ARC set attests to the message Pigeon
relays. Sealing before step 7 would sign a message that does not exist on the
wire; sealing after spooling would mean the spooled bytes are not the signed
bytes. There is exactly one correct position and it is between them.

### 3.1 A chain that arrived failed is not extended

The first draft said `cv=fail` is "sealed honestly rather than repaired". That
is wrong, and the distinction it misses is in RFC 8617:

- **The most recent ARC set already declares `cv=fail`.** The chain is
  terminally broken. Pigeon **does not add a set** — appending to a dead chain
  produces a longer dead chain and nothing else.
- **Pigeon evaluates the chain and finds it invalid** where the previous hop did
  not. Here Pigeon *does* append, with the prescribed failure set, because that
  record is the one piece of information the next hop cannot reconstruct.

`mail-auth` enforces this already: `ArcSealer::seal` returns
`Error::Arc(ArcError::InvalidCV)` when `arc_output.can_be_sealed()` is false.
That is a refusal to be handled, not an error to log — reaching it means the
chain arrived dead and the message is forwarded without a new set.

---

## 4. Headers

### 4.1 Preservation

Existing headers are relayed **unchanged**: not reordered, not refolded, not
re-encoded, not deduplicated. Every one of those is a body-hash break for
`simple` header canonicalisation and a plausible one for `relaxed`. `mail-parser`
is used to *read* headers; it is never the source of the bytes written.

### 4.2 Insertion, top-down

```text
ARC-Seal: i=N                     <- added last, signs the set below
ARC-Message-Signature: i=N        <- signs the message including everything below
ARC-Authentication-Results: i=N   <- what step 2-3 measured
Received: by pigeon ...           <- this hop
Authentication-Results: ...       <- always, when authentication ran (R-5)
<original message, untouched>
```

Under `rewrite_from` the author's `From:` is **replaced**, not preceded. Every
existing `From:` field is removed — folded continuations included, since a
header is not a line — and exactly one generated field is inserted. Prepending
would leave a message with two of a field RFC 5322 permits once, receivers
disagree about which one counts, and a `h=from` signature ordinarily covers the
*last* occurrence: Pigeon would sign the author's header and display its own.

The address is a validated type rather than a header string, so a caller cannot
supply a value containing CRLF. The message is assembled by concatenation, which
makes a newline in a field value indistinguishable from the end of that field.

The `Received:` header is inserted before sealing, so the ARC-Message-Signature
covers it. That is deliberate: it is part of the message Pigeon relays, and a
signature that excludes it invites a downstream to add or strip hops without
detection.

### 4.3 Canonicalisation

`relaxed/relaxed` for everything Pigeon signs. `simple` header canonicalisation
breaks on any whitespace or folding change between here and the receiver, which
is exactly what intermediate systems do. The original signature's choice is not
Pigeon's to make and is irrelevant to it — Pigeon verifies whatever the signer
chose.

### 4.4 Limits

Every one of these is a refusal, not a truncation, because a truncated header
block is a signature break with extra steps.

| Limit | Value | Why |
|---|---|---|
| Message size | `max_message_size` (existing) | already enforced by `DataReader` |
| Header block | 1 MiB | a header block larger than this is an attack, not mail |
| Header count | 1000 | bounded work in the parser and the signer |
| `Received:` hops | 100 (`MAX_HOPS`, existing) | loop backstop, already in `pigeon-smtp` |
| ARC sets | 50 | RFC 8617 §4.2.1 |
| DKIM signatures verified | 10, **aligned first** | each is a DNS lookup and a body hash |

The last one matters more than it looks, and a plain "first ten" is a hole
rather than a limit. DKIM verification is attacker-triggered work — two hundred
`DKIM-Signature` headers is a request for two hundred DNS lookups and two
hundred body hashes from anyone who can send mail — but capping by *position*
lets an attacker prepend ten bogus signatures and push the one that matters
past the cap. The DMARC-aligned signature is the only one whose result changes
the outcome, so it must not be the one dropped.

So the work is ordered before it is bounded:

1. Parse all `DKIM-Signature` headers cheaply — `d=`, `s=`, `a=` only, no DNS,
   no hashing. This is bounded by the header-count limit above.
2. Sort: signatures whose `d=` aligns with the `RFC5322.From` domain first,
   relaxed alignment included, then the rest in order of appearance.
3. Verify at most 10, in that order.

An unaligned signature that goes unverified costs nothing that matters: it
cannot produce a DMARC pass. Dropping the aligned one loses the message.

---

## 5. SRS

### 5.1 Format

Classic SRS, because interoperability is not optional for something that has to
survive a round trip through a stranger's bounce generator.

```text
SRS0=HHHHHHHH=TT=origdomain=origlocal@forward.example
SRS1=HHHHHHHH=firsthop==HHHHHHHH=TT=origdomain=origlocal@forward.example
```

`SRS1` exists for the double-forward case: rewriting an `SRS0` address again
would bury the original sender one layer deeper on every hop, and the address
would grow without bound.

**`SRS1` carries no timestamp of the wrapping host's own**, and that is the
classic layout rather than an omission. Implementation raised the question —
without one, this host's tag on a wrapped address never expires — and the
ruling is that **interoperability wins**: expiry already exists one hop away.
The tail is an `SRS0` address issued by the host named in `firsthop`, carrying
that host's tag and timestamp, and a bounce reaching the wrapper is sent onward
to exactly that host, which applies its own window.

So the consequence is recorded rather than removed: our tag on an `SRS1`
address authenticates that this host produced the wrapper, and nothing about
when. A replayed one lands at the first hop, where the timestamp that governs
it lives.

### 5.2 What the HMAC covers, exactly

Classic SRS concatenates timestamp, domain and local part and hashes the
result. That is ambiguous: `a@b.c` and `a=b@c` can produce the same input, and
an ambiguous MAC input is a forgery primitive rather than a style question.

**Covered bytes**, in this order and no other:

```text
HMAC-SHA-256( key, TT || 0x00 || lowercase(origdomain) || 0x00 || origlocal )
```

- `TT` is the timestamp characters exactly as they appear in the address.
- The domain is lowercased; it is authoritative-case per RFC 5321 §2.4, and the
  same rule `M1-SCHEMA.md` C5 applies to routing.
- The local part is **raw bytes, case preserved** — folding it would make
  `User@x` and `user@x` interchangeable in a return path, which is a decision
  the original domain gets to make and Pigeon does not.
- `0x00` is the separator because it cannot occur in either field, which makes
  the encoding injective without length prefixes.

The first **5 bytes** of the MAC become 8 Base32 characters (RFC 4648 alphabet,
uppercase, no padding).

**Comparison is constant-time.** A byte-at-a-time comparison of an 8-character
tag leaks its prefix to anyone who can measure a bounce, and 40 bits recovered
one character at a time is 8 × 32 attempts rather than 2⁴⁰. `subtle::ConstantTimeEq`,
which is pure Rust and already the standard answer.

### 5.3 Field encoding, and escaping the separators

`=` is valid in a local part (RFC 5321 atext), so a raw local part can forge a
field boundary. Fields are therefore escaped before assembly and unescaped
after:

| Byte | Encoded as |
|---|---|
| `%` | `%25` |
| `=` | `%3D` |
| `@` | `%40` |
| anything outside atext | `%XX` |

`%` is escaped first, which is what makes the transform reversible. After
escaping, no field contains a raw `=`, so decoding splits on `=` unambiguously
and the parser needs no lookahead.

The MAC covers the **unescaped** bytes, so a change in escaping cannot alter a
tag, and a re-encoding by an intermediate that normalises `%3D` to `=` fails
verification rather than silently rewriting the sender.

### 5.4 The key ring

`srs_secret_file` is currently a single `0600` file, validated at startup. That
is enough to sign and not enough to rotate: a secret that cannot be rotated
without invalidating every outstanding return path is a secret that never gets
rotated.

The file becomes a small ring, newest first:

```text
# id  created              stopped_signing_at   secret (base64, 32 bytes)
2     2026-08-01T00:00:00Z -                    4f...==
1     2026-02-01T00:00:00Z 2026-08-01T00:00:00Z 9a...==
```

- **Signing** always uses the first entry, which must have no
  `stopped_signing_at`.
- **Verification** tries every entry and accepts on the first match. The wire
  format carries no key identifier, so this is not a design choice — it is what
  the format leaves available.
- **`stopped_signing_at` is recorded, not inferred.** Deletion eligibility is
  measured from when a key stopped *signing*, and `created` cannot express that:
  a key created two years ago and displaced yesterday is a key whose addresses
  are still arriving.
- **At most 8 keys.** Every verification is one HMAC per key, and a ring is an
  attacker-visible work multiplier for anything that can trigger a verification.
  A ninth entry is a refusal at startup, not a warning.
- **Ordering is by position, not by parsed date.** The dates are for the
  operator; making them load-bearing would let a mistyped year change which key
  signs.

### 5.5 The timestamp, the window, the wrap, and the clock

Classic SRS uses two Base32 characters: days since the SRS epoch modulo 1024.
**Pigeon uses three** — modulo 32768, about 89 years. See R-3.

Two characters wrap every 2.8 years, and the consequence is not a rejected
address but an accepted one: a captured SRS address becomes *current again* on
its wrap anniversary, and if any key that could verify it is still in the ring,
it verifies. The window does not save it, because the window is computed on the
wrapped value. Three characters cost one octet of an already tight budget
(§5.7) and remove the replay class outright.

- **Window**: 21 days, comfortably exceeding the ~5 day retry schedule
  `pigeon-spool` documents. A return path must outlive the queue that might
  still be using it.
- **Modular comparison regardless**: `(now - then) mod 32768 <= window`. The
  arithmetic is the same shape at either width, and a plain subtraction is
  wrong at both. Tested by injecting the day number, never by waiting.
- **Clock**: UTC wall clock, deliberately — it must agree with itself across
  restarts, and a monotonic clock does not. **One day of future tolerance** for
  a peer whose clock is behind.
- A clock that jumps backwards past the tolerance rejects addresses Pigeon
  itself issued, and is logged distinctly: the operator's fix is NTP, not mail.

### 5.6 Rotation and retirement

Rotation state is advanced **before any address is generated**, not lazily on
first use. A signer that rotates as a side effect of signing has a window in
which two processes disagree about which key is current, and the addresses they
produce are both valid and unattributable.

A key may be **deleted** only once

```text
now > stopped_signing_at + verification_window + max_queue_lifetime
```

which with the defaults is 21 + 5 = 26 days, documented as **30**. Deleting
earlier breaks bounces for mail already in flight — silently, because the
failure surfaces at a stranger's MTA as an unroutable address and nothing in
Pigeon's logs says a key went missing.

`pigeon srs rotate` prints the earliest safe deletion date for the key it
displaces; `pigeon srs keys` shows it per key. Neither deletes. An operator
does, or does not, and the date is on record either way.

**Queue retries reuse the address, not the algorithm.** The return path is
computed once, at acceptance, and stored with the message. A retry that
recomputed it would produce a different address — a newer timestamp, possibly a
newer key — while a bounce generated against the *first* one is still in
flight. One message has one return path for its whole life, including across a
rotation.

### 5.7 The 64-octet budget, computed

Fixed overhead, counted rather than estimated:

```text
"SRS0="  5
hash     8   -> 13
"="      1   -> 14
TT       3   -> 17
"="      1   -> 18      <- octets before origdomain
origdomain
"="      1              <- separator before origlocal
origlocal
```

**18 octets before the original domain, 19 fixed in total.** (The first draft
said 15, which was simply wrong arithmetic; with the classic two-character
timestamp it would be 17 and 18.)

RFC 5321 caps a local part at 64 octets, so:

```text
len(origdomain) + len(origlocal escaped) <= 45
```

That is a real constraint, not a corner: `firstname.lastname@a-department.example.edu`
is 43 and fits with two octets to spare; one escaped character pushes it over.
R-4 settles what happens then, and §7 makes it a refusal *before* acceptance
rather than a problem discovered after Pigeon has already said `250`.

---

## 6. Dependency boundary

### 6.1 RSA signing must not use the `rsa` crate

`deny.toml` says so already, in the exception it carries:

> REVISIT AT MILESTONE 2, when DKIM *signing* arrives. Signing is a private key
> operation over attacker-influenceable content, and it must use `ring` rather
> than this crate.

This design honours that. `mail-auth`'s default `ring` feature provides signing
and verification; the `rsa` crate stays confined to `pigeon-auth::dkim::generate`
and key inspection, which take no attacker input and run once per domain.

So the exception's argument is **unchanged**, which is the point — it was
written to be re-checkable rather than permanent.

**What must be added is a guard, not an assertion.** `mail-auth` can pull `rsa`
in through its `generate` or `rust-crypto` features, and a future
`cargo add`-style edit could enable one without anybody noticing that the
security argument for an ignored advisory had quietly become false. CI gains a
check that the only path to `rsa` in the dependency graph is `pigeon-auth`:

```bash
cargo tree -e features --invert rsa | grep -q mail-auth && exit 1
```

That belongs beside the existing decryption grep, and it is the same kind of
guard: a *use* check, not an absence check.

### 6.2 `mail-auth` 0.12.1, not 0.7

```toml
mail-auth = { version = "0.12.1", default-features = false,
              features = ["ring", "arc"] }
```

The 0.7 analysis in the first draft was correct about 0.7 and wrong about what
to use. Resolved and inspected here rather than assumed:

| Property | 0.7 | **0.12.1 with `ring`, `arc`** |
|---|---|---|
| hickory | 0.25, not optional | **0.26.1** — one DNS stack |
| `rsa` in the graph | no | **no** |
| `zip` / `quick-xml` | via default `report` | **no** |
| `rustls-pemfile` feature | exists | **gone**; keys load via `RsaKey::from_rsa_pem` |
| edition | 2021 | 2024 (needs ≥ 1.85; MSRV stays 1.88) |

`default-features = false` is **mandatory, not tidiness**: 0.12.1's default
feature set is `["aws-lc-rs", "report", "dns-hickory"]`, and `aws-lc-rs` is on
`deny.toml`'s ban list — it is the cmake-requiring C crypto library `ring` was
chosen over. Taking the defaults would fail the dependency gate.

**Downgrading to 0.25 is now a security regression, not just duplication.** Two
advisories in the local RustSec database:

| Advisory | Affects | Patched |
|---|---|---|
| RUSTSEC-2026-0119 (`hickory-proto`) | 0.25.x | `>= 0.26.1` |
| RUSTSEC-2026-0118 (`hickory-proto`) | 0.25.x | **none** — unaffected only `< 0.25.0-alpha.3` or `>= 0.26.0-beta.1` |

So R-6 resolves to 0.12.1 and one hickory: the unification the first draft
wanted, without the downgrade it wrongly proposed to get there.

**What this does not establish.** The probe here fetched the graph and read the
lock and the feature map; the user separately reports a successful compile on
1.88. Neither is evidence about resolver *semantics*. The NXDOMAIN-versus-NODATA
classification tests still run against a real resolver, and the full workspace
gates still run, before this is adopted — finding 13 was a semantics bug that a
successful build would have hidden.

### 6.3 `ring` pulls a certificate probe onto the deny list

Found while verifying the above, and it blocks the milestone until settled.

`mail-auth`'s `ring` feature is not only a crypto selection. It expands to:

```text
ring = ["dep:ring", "dns-hickory",
        "hickory-resolver/tls-ring",
        "hickory-resolver/dnssec-ring",
        "hickory-resolver/rustls-platform-verifier"]
```

Feature unification then applies those to *Pigeon's* resolver too, and the
workspace comment claiming `default-features = false` keeps a TLS stack out of
the DNS layer stops being true. On the Linux target the chain is:

```text
openssl-probe 0.2.1
└── rustls-native-certs 0.8.4
    └── rustls-platform-verifier 0.7.0
        └── hickory-net 0.26.1 -> hickory-resolver 0.26.1
```

`openssl-probe` was on `deny.toml`'s ban list, so **M2 could not pass the
dependency gate as the policy stood.** Inspected before proposing anything, and
described precisely, because "two environment reads" undersells it:

- `probe()` reads `SSL_CERT_FILE` and `SSL_CERT_DIR`, then **stats a
  compiled-in list of well-known certificate files and directories** and
  returns what exists.
- The crate also exposes `try_init_openssl_env_vars`, an `unsafe` helper that
  **sets** those two variables — process-global mutation, and the reason the
  function is `unsafe`.
- **Pigeon's path does not reach it.** `rustls-native-certs-0.8.4/src/unix.rs:4`
  calls `probe()`, and that is the only call site anywhere in the graph. No
  linking, no loading, no FFI, no environment mutation.
- No `build.rs`, no `links` key, no dependencies.

That matters because of *why* the ban exists. `deny.toml` says the concern "is
not C code as such. It is the system-library coupling that comes with it" —
locating a shared object, matching versions across hosts, inheriting a
distribution's patch schedule. `openssl-probe` has none of those properties, so
it was caught by a rule whose stated rationale does not apply to it.

**Ruled (R-9): removed from the ban list, alone.** Every actual OpenSSL,
native-TLS and AWS-LC name stays. The review is recorded beside the entry in
`deny.toml`, including the call path and the re-audit trigger — a version bump,
or anything in the graph starting to call the environment-mutating helper.

---

## 7. Failure classification

The governing rule: **an authentication verdict is a fact to record, not
usually a reason to refuse mail.** A forwarder that rejects on its own inability
to verify something loses mail for a stranger's DNS outage.

| Condition | Verdict | SMTP | Log |
|---|---|---|---|
| DKIM signature invalid | `dkim=fail` | accept | debug |
| DKIM key DNS lookup fails transiently | `dkim=temperror` | accept | debug |
| DKIM key absent / malformed | `dkim=permerror` | accept | debug |
| SPF fail on the inbound hop | `spf=fail` | accept | debug |
| Inbound chain already `cv=fail` | no new set (§3.1) | accept | debug |
| Pigeon finds the chain invalid | failure set appended | accept | debug |
| DMARC evaluates to `reject` | recorded in A-R | accept in M2 (R-5) | info |
| More than 10 DKIM signatures | aligned verified first (§4.4) | accept | warn once |
| Header block over limit | — | `552 5.3.4` | warn |
| **SRS address would exceed 64 octets** | — | **`550` at RCPT, before acceptance** | error |
| ARC sealing fails locally | forwarded **without** a new set | accept | error + alert |
| **`rewrite_from` signing fails** | — | **never forwarded rewritten-and-unsigned** | error + alert |

`Authentication-Results` is written **whenever authentication was evaluated**,
not only when something failed. A recipient that accepts a message despite
`p=reject` — which local disposition permits, RFC 7489 §6.7 — needs the verdict
that led there, and a header present only on failure is a header nobody can
rely on.

Three rows are load-bearing.

**The over-long SRS address is refused before acceptance**, at `RCPT TO` where
the forwarding domain is already known, with a permanent failure. The upstream
MTA then owns the DSN, which is correct: it has the original message and a
relationship with the sender. Pigeon generating its own DSN would mean
generating mail, and bounce generation is Milestone 3 — it needs the queue to
be safe. Discovering this *after* `250` would leave a message that cannot be
forwarded and cannot be bounced.

**ARC sealing failure degrades; `rewrite_from` signing failure does not.** These
were one row in the first draft and they are not the same risk. A missing ARC
set drops a recovery path — the pre-ARC status quo, survivable. A rewritten
`From:` that goes out unsigned fails DMARC on a domain *Pigeon controls*, which
is worse than not rewriting at all: it converts a message that would have been
delivered on the original signature into one that is refused on Pigeon's own
identity.

So `rewrite_from` without a usable key is unreachable by construction — startup
and reload validation refuse a configuration whose `rewrite_from` domains lack
active keys, the same shape as M1's rule that no mutation commits a
configuration that will not build. A runtime failure past that point retains or
refuses the message, or falls back to an unchanged `Preserve` forward. It never
sends the rewrite unsigned.

**Nothing about an authentication result reaches the SMTP client.** Reply text
is attacker-visible and, per finding 21, attacker-influenceable; verdicts go to
the log and the headers. A `550` reading "dkim=fail for example.com" is a free
oracle.

---

## 8. To measure before implementing

The project's rule: verify against the real thing, then design. These are open
and must be answered by experiment, not by reading documentation.

1. **How does `mail-auth` canonicalise a body containing a bare LF?** Decides
   whether R-1's normalisation changes any verdict. Feed one message with
   interior bare LFs and a signature computed over the CRLF form, and both
   answers are informative.
2. ~~Does ARC sealing accept a chain with `cv=fail`?~~ **Answered while
   reviewing.** `ArcSealer::seal` returns `Error::Arc(ArcError::InvalidCV)` when
   `arc_output.can_be_sealed()` is false, which is RFC 8617's rule enforced by
   the library. §3.1 handles the refusal; there is nothing left to measure.
3. **Does `classify` still separate NXDOMAIN from NODATA** once `mail-auth`
   shares the resolver? The version does not change (§6.2), but the feature set
   does — `ring` forces `dnssec-ring` and `tls-ring` on, and a validating
   resolver can turn a NODATA into a different error entirely. Re-run against a
   real resolver, not a stub.
4. **Does DMARC evaluation still work without `report`?** Compilation is not
   the question — that is already established. The test evaluates a real policy
   record end to end, because `report` gating an evaluation path would be
   invisible to `cargo build`.
5. **Measured size of a sealed message** versus the original, for the header
   block limit in §4.4.
6. **A real `SRS0` round trip through a third-party bounce generator** — the
   encoding is only correct if somebody else's MTA can send to it. Three-
   character timestamps and percent-escaped fields are both departures from
   what other implementations emit; nobody else parses them, but somebody
   else's *address validator* sees them.

---

## 9. Rulings — settled, and the design is frozen

All nine are ruled. What follows is the decision, not the argument for it;
where a ruling came with conditions, the conditions are in the section named.

**R-1 — normalise after verification. Approved, widened.** Bare CR and bare LF
become CRLF across the **entire DATA payload, headers included** — not the body
alone, because a bare CR inside a header is read as a line break by some parsers
and as an octet by others, which is header injection by disagreement. Exactly
once, after inbound authentication and before Pigeon adds or signs anything,
which is where RFC 6376 §5.3 puts transport conversion. §2. The body-contract
table, `ForwardPolicy::Preserve`, `pigeon-auth`'s module docs and the roadmap
all now say that nonconforming input is not byte-preserved.

**R-2 — 8 Base32 characters, 40 bits. Approved with the five conditions
specified in §5.2 and §5.3:** exact MAC input with `0x00` separators that cannot
occur in either field, percent-escaping that makes the field split unambiguous,
the MAC taken over unescaped bytes, constant-time tag comparison, and a hard
ring cap of 8 keys.

*Arithmetic corrected*: fixed overhead is **18 octets before the original
domain, 19 in total** with the three-character timestamp — 17 and 18 with the
classic two. The first draft's 15 was wrong. §5.7.

**R-3 — 21-day window, 30-day deletion barrier. Approved, with the wrap
closed.** `stopped_signing_at` is recorded per key, because `created` cannot
express when a key stopped signing and deletion eligibility is measured from
that. The two-character timestamp wraps every 1024 days, and a captured address
becomes *current again* on its wrap anniversary while any key that can verify it
remains — so the timestamp widens to **three characters** (32768 days). Rotation
state advances **before** any address is generated. A queued message keeps the
return path it was accepted with; retries never recompute it. §5.5, §5.6.

**R-4 — refuse before acceptance; no Pigeon-generated DSN in M2.** An SRS
address that would exceed 64 octets is detected at `RCPT TO`, where the
forwarding domain is known, and refused permanently. The upstream MTA owns the
DSN. Opaque tokens are M3 work, with the queue that makes bounce generation
safe. §5.7, §7.

**R-5 — record DMARC, do not enforce. Approved**, and
`Authentication-Results` becomes **unconditional whenever authentication was
evaluated** rather than optional: local disposition may differ from published
policy (RFC 7489 §6.7), and a recipient accepting mail despite `p=reject` needs
the recorded verdict. §7.

**R-6 — `mail-auth` 0.12.1, one hickory at 0.26.1.** Not a downgrade to 0.25:
that would import RUSTSEC-2026-0119 and RUSTSEC-2026-0118, the second of which
has no patched version. `default-features = false` is mandatory — the default
set pulls `aws-lc-rs`, which `deny.toml` bans. §6.2.

**R-7 — build without `report`. Approved**, with a real DMARC evaluation test
rather than a compile as the evidence. §8.4.

**R-8 — DKIM signing of a rewritten `From:` is mandatory M2 work. Approved.**
The pipeline is verify → normalise → rewrite → sign → seal → spool, with the
ARC set covering Pigeon's own DKIM signature. §3.

**R-9 — NEW, and it blocks the milestone. `openssl-probe` on the deny list.**
`mail-auth`'s `ring` feature forces `hickory-resolver/rustls-platform-verifier`,
which on Linux reaches `openssl-probe` through `rustls-native-certs`. That crate
is banned by name in `deny.toml`, so M2 cannot pass the dependency gate as the
policy stands.

Inspected rather than argued: no `build.rs`, no `links`, no dependencies, no
FFI — a table of certificate directory paths and two environment-variable reads,
named after OpenSSL's filesystem conventions. The ban's own stated rationale is
"not C code as such… the system-library coupling that comes with it", and this
crate has none of that coupling.

**Ruled: `openssl-probe` is removed from the ban list, and nothing else is.**
Every actual OpenSSL, native-TLS and AWS-LC name stays — the alternative to
`ring` is `aws-lc-rs`, which is banned for reasons that genuinely apply.

The justification recorded in `deny.toml` states the call path rather than a
character reference for the crate: `rustls-native-certs` calls `probe()`, not
the `unsafe` environment-mutating helper, and that distinction is what the
allowance rests on. It is therefore re-auditable, and marked to be re-audited on
a version bump or a change of call path.

## 10. Tests

### 10.1 Properties, with the mutation that must fail each

| Property | Mutation that must break a test |
|---|---|
| Verify runs before any mutation | move the `Received:` prepend above verification |
| DMARC uses the original `From:` | evaluate against the SRS envelope instead |
| The ARC set seals the relayed form | seal before the header block is prepended |
| A dead chain is not extended | append a set when the inbound chain says `cv=fail` |
| A newly-detected failure IS recorded | skip the failure set when Pigeon finds the chain invalid |
| Payload bytes are unchanged apart from R-1 | drop a byte; flip a CRLF; refold a header |
| Normalisation covers headers too | normalise the body only |
| The aligned signature is verified first | sort by position instead of alignment |
| A rewritten `From:` is never sent unsigned | forward the rewrite when signing fails |
| The seal covers Pigeon's DKIM signature | seal before signing |
| An over-long SRS address is refused at RCPT | detect it after `250` instead |
| The marker CRLF is added only when needed | append it unconditionally |
| SRS timestamps compare modularly | replace with a plain subtraction |
| The MAC input is unambiguous | drop the `0x00` separators and rely on concatenation |
| Escaping is reversible | escape `=` before `%` |
| Tag comparison is constant-time | **not testable** — `==` is functionally identical and differs only in timing. Guarded in CI by matching the executable expression inside `match_tag`, with comment lines stripped, because a guard that greps the file matches the comment explaining the call and passes with the call deleted. The guard is itself tested against that mutation. |
| A queued message keeps its original return path | recompute the address on retry |
| Rotation happens before signing | advance the ring lazily, after the address is built |
| Verification accepts any ring key | verify against the newest key only |
| Signing uses the newest key | sign with the last entry |
| A retired-but-undeleted key still verifies | drop retired keys from the ring at load |
| The DKIM signature count is bounded | remove the cap |
| Header limits refuse rather than truncate | truncate instead |

Every row is a test that fails when the line is reverted — the discipline the
M1 work settled into, and the reason those reviews found tests that passed for
the wrong reason.

### 10.2 Fixtures

`pigeon-testkit` gains signed-message fixtures with *known-good* and
*known-broken* signatures, generated once and committed, plus a DNS stub serving
the corresponding public keys. The stub must not share code with the resolver
under test, for the same reason the scripted SMTP peer does not depend on
`pigeon-smtp`: an implementation that agrees with itself proves nothing.

### 10.3 Exit criteria

Forwarded mail is accepted with passing authentication by every major receiving
provider, verified against real mailboxes rather than local tests.

Concretely, and each is a check somebody performs rather than a claim:

1. A message from a strict-DMARC sender (`p=reject`, DKIM-signed), forwarded to
   **Gmail, Outlook, Yahoo and Proton**, lands in the inbox with `dmarc=pass`
   in the receiver's own `Authentication-Results`.
2. A message that arrives at Pigeon with **DKIM valid**, and whose signature is
   then broken by the forwarding transformation itself, lands with Pigeon's ARC
   set evaluated and honoured at receivers that honour ARC.

   The first draft had this test start from an already-broken signature, which
   cannot work: ARC attests to what authenticated *on arrival*, so a message
   broken before Pigeon saw it has nothing for Pigeon to attest to. The only
   other admissible form of this test starts with a valid upstream ARC chain
   recording the earlier pass — worth adding as a second case, since a
   list-then-forward path is exactly where real ARC chains come from.
3. A bounce sent to the SRS return path arrives back at the original sender.
4. An SRS address issued before a key rotation still verifies after it.
5. A message with a `.` at the start of a body line arrives with exactly one.
6. A message whose final line is unterminated arrives with the single CRLF §2.5
   describes, and nothing else changed.

Criteria 1–4 need real mailboxes and a real domain. They are the milestone.
