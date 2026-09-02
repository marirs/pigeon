# External acceptance

Everything in this repository is evidence that Pigeon does what its authors
believe it does. This document is the one procedure that produces evidence of
what **other people's mail systems** think of it, which is a different question
and the only one that decides whether the software works.

Status at the time of writing: **implementation complete, external acceptance
pending.** No production claim is made about a release until a run of this
procedure passes and its artifacts are attached to the tag.

---

## What is actually being tested

Not "does mail arrive" — that passes trivially and proves almost nothing. Three
things that only a real receiver can answer:

1. **Authentication survives forwarding.** Pigeon rewrites the envelope sender
   (SRS), signs with DKIM, and seals with ARC. A receiver has to agree that the
   result authenticates, and its `Authentication-Results` header is the only
   place that answer exists.
2. **Placement.** A message that authenticates and lands in spam has failed. The
   distinction is invisible from this side: the SMTP transaction returns `250`
   either way.
3. **Bounces get home.** An SRS return path is only worth having if the bounce
   addressed to it is accepted, reversed, and delivered to the original sender.
   That path is exercised by nothing in the test suite that a real bounce
   exercises — a real one comes from a real MTA, in that MTA's format, to an
   address this host issued days earlier.

---

## Preconditions

A run is only meaningful with all of these. A partial run is worth recording as
a partial run; it is not worth recording as a pass.

- A host deployed per [DEPLOY.md](DEPLOY.md), on a **static address with correct
  reverse DNS** and port 25 reachable both ways.
- A **real domain** with published MX, SPF, DKIM and DMARC records, and
  `pigeon domains check` clean.
- **Receiving mailboxes** at the providers under test, forwarded to by that
  domain.
- **Sending accounts** at each provider, to originate the test messages from.
- The tag under test built with `--locked`, so what ran is what was released.

### The providers that matter

| Provider | Why it is on the list |
|---|---|
| Gmail | largest receiver; strictest about forwarded mail without ARC |
| Outlook / Microsoft 365 | separate reputation system; the one most likely to silently junk a new IP |
| Yahoo | third independent DMARC implementation |
| Fastmail | strict, transparent, and reports its reasoning in headers |
| Proton | rewrites and re-checks; catches ARC sealing mistakes others tolerate |

A run covering only Gmail is a Gmail result. Say so in the manifest rather than
generalising it.

---

## The procedure

### 1. Pin what is being tested

```sh
git describe --tags --always > /dev/null   # confirm a clean, tagged checkout
scripts/acceptance-capture.sh init v0.1.0
```

`init` records the commit, the binary versions, the schema version, the routing
checksum and `domains check` output. Evidence that does not say what it tested
is not evidence.

### 2. Forwarding, per provider

For each provider, from an account **at that provider**, send to the forwarding
address. Then, in the destination mailbox, **show the original** and save the
complete headers:

```sh
scripts/acceptance-capture.sh headers gmail < ~/Downloads/original_msg.txt
```

Complete, not excerpted. The judgement lives in `Authentication-Results`,
`ARC-Authentication-Results` and `Received-SPF`, and an excerpt chosen by
somebody who already believes the result is not an independent check.

Record placement as the mailbox actually showed it:

```sh
scripts/acceptance-capture.sh placement gmail inbox
scripts/acceptance-capture.sh placement outlook junk
```

**A pass is `dkim=pass` on the forwarder's signature, `arc=pass` on the seal,
`dmarc=pass`, and delivery to the inbox.** Anything else is a finding, including
`spf=fail` with `dmarc=pass` — that is SRS and ARC working as intended, and it
should be recorded as such rather than filed as a defect later.

### 3. The delivery side, from here

```sh
scripts/acceptance-capture.sh delivery <spool-id>
```

The far end's `250` line, with its queue ID, is what ties the provider's copy to
this host's record of sending it. Get the spool id from the daemon log or
`pigeon queue list`.

### 4. The SRS bounce

The one that has to be provoked deliberately, because nothing generates it on
its own. From a provider account, send to the forwarding address for a
destination that will **reject after acceptance** — a mailbox that is full, has
been deleted, or is over quota. A rejected-at-RCPT destination does not test
this: the point is a bounce that arrives later, by mail, addressed to the SRS
return path this host issued.

Then, at the *original sender's* mailbox, the bounce should arrive:

```sh
scripts/acceptance-capture.sh bounce < ~/Downloads/bounce_original.txt
```

This proves the whole chain: the return path was accepted by the bouncing MTA,
routed back here by DNS, verified against the SRS key ring, reversed to the
original sender, and delivered. A failure anywhere in it is silent — the sender
simply never learns their mail did not arrive — which is why it is a gate rather
than a nice-to-have.

Keep the daemon log for the window:

```sh
journalctl -u pigeond --since "-2h" > evidence/<run>/pigeond.log
```

### 5. Seal it

```sh
scripts/acceptance-capture.sh finish
```

Writes `MANIFEST` with a SHA-256 of every artifact, so a later reader can tell
that the evidence is the evidence that was collected, and attaches nothing on
its own — publishing is a decision, not a side effect.

---

## Reading the result

**Pass** — every provider under test authenticates and places in the inbox, and
the bounce arrived at the original sender. Attach `evidence/<run>/` to the
release and change the status line in [ROADMAP.md](ROADMAP.md).

**Placement failure with clean authentication** is usually IP reputation, not a
defect: a new address sending its first mail is untrusted everywhere. It is
still a finding, recorded as one, and the answer is usually warm-up or a
smarthost rather than a code change.

**Authentication failure is a defect**, and the headers say which one:

| Header says | Means |
|---|---|
| `dkim=fail` on this host's `d=` | signed body does not match what arrived — a transformation after signing |
| `dkim=none` | not signed at all; the key is inactive or the domain has none |
| `arc=fail` | the seal does not validate; sealing order or a chain broken on the way |
| `dmarc=fail` with `spf=fail`, `dkim=pass` | alignment: the signing domain is not the From domain |
| `spf=fail` on the SRS domain | the SRS domain's SPF does not name this host |

**Do not fix a header failure and call the run passed.** Fix it, then run the
whole procedure again from step 1 — a fix invalidates every artifact taken
before it, since they describe a build that is no longer the one shipping.
