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

## 2. The body contract

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
| **Verification → relay form** | receipt bytes + normalisation (R-1) + prepended headers |
| **Relay form → spool** | byte-identical to the relay form |
| **Spool → wire** | dot-stuffed; CRLF added before the marker if not at a line start |

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

### 2.3 The bare-LF problem is outbound, not inbound

Pigeon cannot be smuggled *into*: the reader accepts only `CRLF.CRLF`. What it
can do is *carry* a smuggling primitive. A body containing `LF . LF` relayed
verbatim to a receiver whose parser is lax terminates that receiver's DATA early
and injects everything after it as a new message, from Pigeon's IP, with
Pigeon's reputation.

This is the 2023–24 SMTP smuggling class, and a forwarder is the ideal
amplifier for it: it is precisely a machine that takes bytes from a stranger and
re-emits them from a trusted host.

Three responses, and they are not equally good — see R-1.

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
4. record               build Authentication-Results / ARC-AAR from step 2-3
5. mutate               normalise (R-1), rewrite envelope via SRS,
                        prepend Received, prepend AAR
6. seal                 ARC-Message-Signature over the mutated message,
                        ARC-Seal over the chain
7. spool                exactly what step 6 produced
```

**Verify before mutate.** Any header Pigeon prepends is a header the original
DKIM signature did not cover, and an `h=` list that oversigns an absent header
turns an added one into a break. Normalising the body before verification would
be worse still: the verdict would describe a message that never arrived.

**DMARC against the original identities.** After step 5 the envelope sender is
an SRS address in a Pigeon-owned domain, and evaluating alignment against that
would return a meaningless pass. DMARC alignment is computed against the
`From:` domain as received, with the SPF and DKIM results from step 2.

**Seal last, and seal what is sent.** The ARC set attests to the message Pigeon
relays. Sealing before step 5 would sign a message that does not exist on the
wire; sealing after spooling would mean the spooled bytes are not the signed
bytes. There is exactly one correct position and it is between them.

**The chain instance number** is `existing ARC sets + 1`, and a chain that
already fails stays failed — `cv=fail` is sealed honestly rather than repaired.
A forwarder that reports a chain as passing because it wants the message
delivered is the reason receivers stopped trusting ARC from some sources.

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
Authentication-Results: ...       <- optional, R-5
<original message, untouched>
```

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
| DKIM signatures verified | 10 | each is a DNS lookup and a body hash |

The last one matters more than it looks: DKIM verification is attacker-triggered
work. A message carrying two hundred `DKIM-Signature` headers is a request for
two hundred DNS lookups and two hundred body hashes, from anyone who can send
mail.

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

### 5.2 The key ring

`srs_secret_file` is currently a single `0600` file, validated at startup. That
is enough to sign and not enough to rotate: a secret that cannot be rotated
without invalidating every outstanding return path is a secret that never gets
rotated.

The file becomes a small ring, newest first:

```text
# id  created (RFC 3339)  secret (base64, 32 bytes)
2  2026-08-01T00:00:00Z  4f...==
1  2026-02-01T00:00:00Z  9a...==
```

- **Signing** always uses the first entry.
- **Verification** tries every entry and accepts on the first match. The classic
  SRS wire format carries no key identifier, so this is not a design choice —
  it is what the format leaves available. The cost is one HMAC per key, bounded
  by the ring size.
- **Ordering is by position, not by parsed date.** The date is documentation for
  the operator; making it load-bearing would mean a mistyped year could silently
  change which key signs.

### 5.3 Hash length

**8 base32 characters (40 bits)**, not the classic 4.

Nobody else has to verify these addresses, so the length is Pigeon's to choose,
and 20 bits is forgeable at a few hundred thousand attempts — which buys an
attacker the ability to send mail *through* the forwarder to any original
sender, with Pigeon's reputation attached. The cost of the extra four characters
is address length, which §5.6 has to bound anyway.

### 5.4 The timestamp, the window, and the clock

`TT` is two base32 characters: days since the SRS epoch, modulo 1024.

- **Window**: 21 days by default, matching the convention and comfortably
  exceeding the ~5 day retry schedule `pigeon-spool` documents. A return path
  must outlive the queue that might still be trying to use it.
- **Wrap-around is not optional to handle.** 1024 days is under three years, and
  the comparison is modular: `(now - then) mod 1024 <= window`. A naive
  subtraction rejects every address for 21 days once every 2.8 years, which is
  the kind of bug that ships because nobody runs a test for three years. It is
  tested by injecting the day number, not by waiting.
- **Clock**: UTC wall clock, deliberately, because it must agree with itself
  across restarts and a monotonic clock does not. A **1 day future tolerance**
  is allowed, for a receiver whose clock is behind ours.
- A clock that jumps *backwards* by more than the tolerance rejects addresses
  Pigeon itself issued. That is logged distinctly rather than as a generic
  verification failure, because the operator's fix is NTP, not mail.

### 5.5 Retirement safety

A key may stop signing at any time. It may only be **deleted** once

```text
now > stopped_signing_at + verification_window + max_queue_lifetime
```

which with the defaults above is 21 + 5 = 26 days, rounded up to **30 days** as
the documented rule. Deleting earlier silently breaks bounces for mail already
in flight — silently, because the failure appears at a stranger's MTA as an
unroutable address, and nothing in Pigeon's logs says a key went missing.

`pigeon srs rotate` therefore prints the earliest safe deletion date for the key
it displaces, and `pigeon srs keys` shows it per key. The tool does not delete;
an operator does, or does not, and either way the date is on record.

### 5.6 The 64-octet problem

`SRS0=HHHHHHHH=TT=` is 15 octets before the original address, and RFC 5321
limits a local part to 64. An original sender of
`some.very.long.address@a-long-domain.example` overflows it.

Not a rare edge: it is a normal address at a company with a long domain. The
options are recorded in R-4, because none of them is free.

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

### 6.2 `mail-auth` features

```toml
mail-auth = { version = "0.7", default-features = false,
              features = ["ring", "rustls-pemfile"] }
```

Dropping the default `report` feature removes `quick-xml` and `zip`. DMARC
*aggregate report* parsing and generation is not Milestone 2 — evaluating a
DMARC policy and producing an XML report for a domain owner are different jobs,
and only the first one is needed to make forwarded mail land. When reporting
arrives, the feature comes back with it.

`rustls-pemfile` stays: DKIM private keys are stored as PEM under the `keys`
root, and that is what reads them.

### 6.3 The duplicate DNS stack — measured

| Crate | hickory | features |
|---|---|---|
| `pigeon-dns` | 0.26 | `tokio`, `system-config`, defaults off |
| `mail-auth` 0.7 | **0.25**, not optional | `tls-ring`, `dnssec-ring` |

`MessageAuthenticator` is `pub struct MessageAuthenticator(pub TokioResolver)` —
a public newtype over hickory's resolver, with no trait seam for supplying DNS
answers from elsewhere. So the choice is not whether to have hickory 0.25; it is
whether to *also* keep 0.26. See R-6.

Two facts that bear on it, both checked rather than assumed:

- `deny.toml` sets `multiple-versions = "warn"`, so two hickory versions do not
  fail CI today. They do mean two resolvers, two caches, two sets of timeouts,
  and an operator question — "which one made that query?" — with two answers.
- Finding 13's fix reads `response_code` off `hickory_resolver::net::DnsError`.
  Hickory 0.25 carries the same `NoRecordsFound { response_code, .. }` data at a
  different path, so unifying is a rewrite of one function — small, and
  **exactly the function that was already wrong once**. It does not get moved
  without re-running the NXDOMAIN-versus-NODATA test against a real resolver.

MSRV: 1.88 is pinned *by* hickory 0.26. Dropping to 0.25 may permit a lower
MSRV; it does not require one, and this design does not lower it.

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
| ARC chain already `cv=fail` | sealed as `cv=fail` | accept | debug |
| DMARC evaluates to `reject` | recorded | accept in M2 (R-5) | info |
| More than 10 DKIM signatures | verify first 10, rest ignored | accept | warn once |
| Header block over limit | — | `552 5.3.4` | warn |
| Pigeon's own key missing/unreadable | — | accept, forward **unsealed** | **error + alert** |
| Sealing fails for any other reason | — | accept, forward **unsealed** | **error + alert** |
| SRS encoding impossible (§5.6) | — | R-4 | error |

Two rows are the interesting ones.

**Pigeon's own signing failure does not reject the message.** Rejecting would
convert a local configuration fault into refused mail; forwarding unsealed
degrades to the pre-ARC behaviour, which is the status quo for most forwarded
mail and is survivable. It is an `error` with an alert precisely because it is
silent otherwise — the mail keeps flowing and the protection is gone.

**Nothing about an authentication result reaches the SMTP client.** Reply text
is attacker-visible and, per finding 21, attacker-influenceable; the verdicts go
to the log and to the headers, where they belong. A `550` that said
"dkim=fail for example.com" would be a free oracle.

---

## 8. To measure before implementing

The project's rule: verify against the real thing, then design. These are open
and must be answered by experiment, not by reading documentation.

1. **How does `mail-auth` canonicalise a body containing a bare LF?** Decides
   whether R-1's normalisation changes any verdict. Feed one message with
   interior bare LFs and a signature computed over the CRLF form, and both
   answers are informative.
2. **Does `mail-auth` 0.7's ARC sealing accept a chain with `cv=fail` and seal
   it honestly**, or refuse? Determines whether §3's "seal the failure" is a
   configuration or a wrapper.
3. **What exactly does hickory 0.25's error type look like** along the path
   `classify` walks, and does the NXDOMAIN/NODATA distinction survive the move?
   Blocking for R-6.
4. **Does dropping `report` compile and pass mail-auth's own DMARC evaluation
   path?** If DMARC evaluation is entangled with report generation, R-7 changes.
5. **Measured size of a sealed message** versus the original, for the header
   block limit in §4.4.
6. **A real `SRS0` round trip through a third-party bounce generator** — the
   encoding is only correct if somebody else's MTA can send to it.

---

## 9. Rulings required before implementation

**R-1 — the bare-LF body.** Three options:

- **(a) Preserve.** Bytes are exactly what arrived. Ships the smuggling
  primitive (§2.3) and makes Pigeon an amplifier.
- **(b) Reject at DATA.** Refuse a body containing a bare LF or bare CR with a
  permanent failure. Safest, and rejects mail that most receivers accept today.
- **(c) Normalise once, after verification.** Bare LF → CRLF and bare CR → CRLF
  at step 5, before anything is signed or spooled. Verification still describes
  what arrived; the relay form is canonical; the primitive does not leave.

**Recommended: (c).** It is the only one that both keeps the verdict honest and
refuses to re-emit the attack. The cost is real and must be stated in
`ForwardPolicy::Preserve`: a message that arrived with bare LFs is *not*
forwarded byte-for-byte, and if its signature covered those bytes, it will fail
downstream — having been recorded as passing in the ARC set, which is exactly
what ARC is for.

**R-2 — SRS hash length 8 (40 bits)** rather than the classic 4. §5.3.

**R-3 — SRS window 21 days, key deletion barred for 30.** §5.4, §5.5.

**R-4 — over-long SRS addresses (§5.6).** Options: (a) refuse the forward
permanently and DSN the original sender; (b) fall back to a database-stored
opaque token, which needs a table and belongs with the M3 queue; (c) truncate,
which is not an option — it silently forges a different sender.
**Recommended: (a) for M2**, with (b) recorded as the M3 improvement, because a
DSN to a sender who can read it beats a bounce address nobody can route.

**R-5 — does an inbound DMARC `p=reject` verdict refuse the message?**
**Recommended: no in M2** — evaluate and record only. Forwarding spoofed mail
harms reputation, and enforcement is an abuse-policy decision with its own
milestone; making it here would couple the go/no-go milestone to a policy call.
The risk is explicit rather than deferred silently.

**R-6 — the DNS stack.** (a) two hickory versions; (b) unify on 0.25 and share
one resolver with `mail-auth`; (c) keep 0.26 and wait for `mail-auth` to move.
**Recommended: (b)**, conditional on measurement 3 — one resolver, one cache,
one place to answer "what did Pigeon ask DNS?". Not adopted before `classify` is
re-verified against a real resolver, because that function has been wrong once
and the failure mode was permanently refused mail.

**R-7 — `mail-auth` without `report`.** §6.2, conditional on measurement 4.

**R-8 — DKIM signing for the `rewrite_from` path.** When `forward_policy` is
`rewrite_from`, the `From:` becomes a Pigeon-owned address, and an unsigned
rewrite is strictly worse than no rewrite: it fails DMARC on a domain Pigeon
controls. So `rewrite_from` requires signing with that domain's key.
**Recommended: yes**, which makes DKIM signing part of M2 rather than a later
addition, and is why §6.1's `ring` boundary has to be settled now.

---

## 10. Tests

### 10.1 Properties, with the mutation that must fail each

| Property | Mutation that must break a test |
|---|---|
| Verify runs before any mutation | move the `Received:` prepend above verification |
| DMARC uses the original `From:` | evaluate against the SRS envelope instead |
| The ARC set seals the relayed form | seal before the header block is prepended |
| A failed chain stays failed | seal `cv=pass` when the chain is broken |
| Body bytes are unchanged apart from R-1 | drop a byte; flip a CRLF; refold a header |
| The marker CRLF is added only when needed | append it unconditionally |
| SRS timestamps compare modularly | replace with a plain subtraction |
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
2. The same message with its DKIM signature deliberately broken upstream lands
   with the ARC chain evaluated and honoured at receivers that honour it.
3. A bounce sent to the SRS return path arrives back at the original sender.
4. An SRS address issued before a key rotation still verifies after it.
5. A message with a `.` at the start of a body line arrives with exactly one.
6. A message whose final line is unterminated arrives with the single CRLF §2.5
   describes, and nothing else changed.

Criteria 1–4 need real mailboxes and a real domain. They are the milestone.
