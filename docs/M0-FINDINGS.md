# Milestone 0 review findings

A review of the Milestone 0 code, read as delivered rather than as intended. Ten findings, ordered by what they cost if left alone.

All ten are addressed. This document is kept because the reasoning is worth more than the diffs — several of these are mistakes that look correct until a specific thing happens.

---

## 1. No `Received:` header — anywhere

**Severity: high. Specification violation.**

RFC 5321 §4.4 requires an SMTP server to prepend a `Received:` line to every message it relays. Pigeon added none.

Two consequences. The obvious one is compliance, and receivers do penalise mail arriving with no trace path. The less obvious one matters more: the `Received` chain is the standard loop guard. Configuration-time loop detection catches cycles among domains Pigeon manages, but a message that leaves through a system Pigeon cannot see and re-enters is invisible to it. Counting hops is how that is caught, and there was nothing to count.

Prepending `Received` is safe for DKIM — signatures do not cover headers added above them — so there was never a reason to defer it.

**Fixed:** the server builds the header from the peer address, the client's greeting, its own hostname and the time, and hands it to the sink alongside the body.

**Design note.** The header is carried separately from the body rather than prepended into it. Prepending into a `Vec` means copying the whole message to make room at the front, which for a large message is a real cost paid for a few hundred bytes of text. The sink writes the two in sequence; the delivery client stuffs across both as one stream.

## 2. SMTPUTF8 was advertised and then refused

**Severity: high. Actively misleading.**

`session.rs` advertised `SMTPUTF8` in its EHLO response. `command.rs` rejected any command line containing a non-ASCII byte.

So Pigeon told senders it accepted internationalised addresses and answered 500 when they used them. This is worse than not advertising: a correct sender takes the advertisement at its word, and the failure is one Pigeon invited.

**Fixed:** removed from the advertised list. It goes back when there is an implementation behind it.

## 3. SIZE was not advertised

**Severity: low. Wasted bandwidth.**

`max_message_size` existed and was enforced, and `reply::ehlo_ok` already supported advertising it — a test in `reply.rs` demonstrated `SIZE 52428800` — but the session never included it.

Without the advertisement a sender transmits an entire oversized message before learning it will be refused.

**Fixed:** advertised from the configured limit.

## 4. Spool files were never deleted

**Severity: high. The disk fills.**

`pigeond` wrote `.eml` and `.envelope` files and nothing ever removed them. The documented design is "pure relay, nothing retained"; the implementation retained everything, permanently.

The gap between a design document and the code is worth noticing on its own. Anyone reading `ARCHITECTURE.md` would have believed this was already handled.

**Fixed:** both files are removed after a forward succeeds. A failed forward leaves them, which is deliberate — with no retry queue yet, the spool copy is the only thing standing between a transient failure and a lost message.

## 5. Outbound concurrency was unbounded

**Severity: medium-high.**

Every accepted message spawned a forwarding task with no limit. Inbound connections were capped at 256, so 256 concurrent messages could open 256 simultaneous outbound connections, with more arriving behind them.

Capping one direction and not the other leaves the process just as exhaustible; it only changes which resource runs out first.

**Fixed:** outbound holds its own semaphore, defaulting to 32 concurrent deliveries.

## 6. Duplicate recipients were not deduplicated

**Severity: medium. Amplification.**

`RCPT TO:` for the same address twice produced two entries in the envelope and two deliveries of one message to one mailbox. A hundred repetitions produced a hundred.

That is an amplification vector reachable by any anonymous sender, and the fix is a containment check.

**Fixed:** repeats are still answered `250`, as the specification requires, but recorded once. Comparison is case-insensitive on the whole address, which is stricter than the specification requires for local parts and is the safer direction.

## 7. The error counter never reset

**Severity: low-medium. Disconnects legitimate clients.**

`errors` was set to zero when a session was created and only ever incremented. The intent was to drop a client sending nothing but garbage; the effect was to drop any long-lived connection that accumulated ten errors over its lifetime, however much valid traffic sat between them.

A busy sender holding a connection open for hours will do exactly that.

**Fixed:** counts *consecutive* errors, reset by any successful command.

## 8. No cap on total session duration

**Severity: medium. Defeats both existing defences.**

The command timeout resets on every command, so a client sending `NOOP` every four minutes held its slot indefinitely. With `max_connections` at 256, 256 such clients close the server to everyone else.

The connection cap and the command timeout were tested together as a pair, and this walks through both. The hostile-client tests missed it because they tested silence, and the attack is patient noise.

**Fixed:** a total session lifetime, defaulting to one hour, independent of activity.

## 9. A comment contradicted the code it described

**Severity: low.**

`client.rs` carried a comment explaining why one recipient per delivery keeps the accounting honest, directly above a loop sending every recipient in the envelope.

Left alone, the next reader believes the comment and reasons from a guarantee that does not hold.

**Fixed:** the comment now describes what the code does — all recipients in one transaction, all required to succeed — and why per-recipient splitting belongs to the queue in Milestone 3.

## 10. The zero-copy address type was unused

**Severity: medium. Unvalidated input.**

`pigeon-types::Address` exists, parses without allocating, and has a test asserting it borrows rather than copies. The session never used it: envelope paths were stored as raw strings and never validated, so `RCPT TO:<garbage>` was accepted and passed to the sink as a recipient.

Two problems in one. Malformed addresses reached routing, and the zero-copy parsing that was written carefully and tested carefully was decorative — it sat beside the hot path rather than on it.

**Fixed:** `MAIL FROM` and `RCPT TO` paths are parsed and rejected with `501` when malformed. The null sender is exempt, being valid and not an address.

---

## What this review did not find

Worth stating, because a review that only lists faults gives no sense of proportion.

The protocol layer held up. The command parser, session state machine, codecs and MX ordering had no correctness bugs — the boundary cases they were written for are the ones they handle. Separating pure logic from I/O paid for itself: every finding above is in the wiring, the configuration, or the specification surface, and none is in the parsing.

The two test harnesses also did their job, having already found a client that could hang forever and an error misclassification before this review started.

---

# Second round: independent review

The first round was a self-review, and it read the code the way its author remembered writing it. This round was done by two reviewers with no prior context, reading only what was on disk. They found fifteen more, several of them worse than anything in the first round.

That is the finding underneath the findings, and it is worth stating plainly: **a self-review of fresh work catches the things you already suspected.** It does not catch the things you believe are true.

## 11. None of the code was in version control, and CI had never run

**Severity: critical.**

`.gitignore` opened with a blanket `.*` rule. That excluded `.github/` entirely, so the workflow was never committed and no gate — formatting, clippy, tests, the OpenSSL ban, the MSRV floor — had ever executed anywhere but a laptop. `deny.toml` and `Cargo.lock` were untracked for the same reason, and so was every source file written after the initial docs commit.

Every claim of the form "CI enforces this" was false for the whole of Milestone 0.

**Fixed:** the blanket rule is gone, replaced by explicit entries with a comment saying why it must not come back. `spool/` and `.wrangler/` are now ignored deliberately rather than by accident.

## 12. Recipient de-duplication merged distinct mailboxes

**Severity: high. Silent mail loss.**

Comparison folded case across the whole address. RFC 5321 §2.4 reserves interpretation of the local part to the destination host and requires relays to preserve its case — `Bob@x.com` and `bob@x.com` may be different people, and a relay cannot know.

The second `RCPT TO` was answered `250`, accepting responsibility, and then dropped from the envelope. No copy, no bounce, no log line.

Worse, the test added in the first round **asserted this behaviour was correct**. A test can enshrine a bug as firmly as it can prevent one.

**Fixed:** `Address::same_mailbox` folds the domain only, and the test now asserts the opposite of what it used to.

## 13. NODATA was misclassified as NXDOMAIN, making the implicit-MX fallback dead code

**Severity: high. Silent mail loss.**

The resolver classified errors by matching their text — flagged in round one as something to tighten, judged safe because it erred toward "transient". It did not err that way.

hickory reports NXDOMAIN and NODATA as the same `NoRecordsFound` variant, whose `Display` is "no records found for {query}" in both cases. So a domain that exists and has an A record but publishes no MX matched `"no record"`, became `NoSuchDomain`, and was refused permanently.

The consequence is precise: the implicit-MX fallback — the code whose comment reads *"skipping it loses mail to small domains that never published one"* — could never execute. Mail to exactly those domains was refused and, per finding 14, never seen again.

**Fixed:** classification reads `response_code` off the error kind. The distinction was available all along; string matching threw it away.

## 14. Failed forwards were black-holed

**Severity: high. Silent mail loss.**

Nothing ever read the spool after startup. No scan, no timer, no reaper. So every failure path — permanent rejection, null MX, unreachable hosts, the misclassification above — left a file that nothing would open again, after the sender had been told `250` and discarded its own copy.

The comment claiming the crash window "has now closed" was true only on success.

**Fixed:** startup counts what is stranded and warns loudly, naming the path and saying nothing will retry. That is not a queue — Milestone 3 is — but an operator who is never told has no way to find out except by looking.

## 15. Delivery permits were acquired inside the spawned task

**Severity: high.**

The semaphore bounded concurrent *connections* and not the number of *pending tasks*, each of which pins a whole message in memory. A sender looping 50 MB messages grows the process without limit while permits trickle through.

The inbound path gets this right, taking its permit before spawning. The outbound path copied the shape and not the placement.

**Fixed:** acquired before spawn, so backpressure reaches the SMTP session.

## 16. No write was bounded in time

**Severity: high.**

Every read had a timeout; no write did. A client that pipelines commands and stops reading fills the kernel send buffer and parks `write_all` forever — and because the session lifetime is only checked at the top of the read loop, control never returns to notice. One 8 KB read of pipelined `EHLO` produces roughly 100 KB of replies, so it is cheap to arrange and it defeats the session cap and the connection cap together.

**Fixed:** replies carry a write timeout.

## 17. `tls_available: true` produced a silent plaintext downgrade

**Severity: high, latent.**

Setting the flag made the server advertise STARTTLS, answer `220 Ready to start TLS`, and then continue reading plaintext — parsing the client's handshake as SMTP commands. `tls_established()` was never called outside tests.

The comment claimed adding TLS "is a compile error here rather than a silent no-op." It was exactly the silent no-op it disclaimed.

**Fixed:** `serve` refuses to start with the flag set. Failing at startup is the only version of that promise the code can actually keep.

## 18. Outbound dot-stuffing disagreed with the reader about line starts

**Severity: medium. Body corruption.**

The writer treated a bare LF as the start of a line; the reader requires CRLF. A body containing `\n.` was stuffed on the way out and not unstuffed on the way in, adding one character to every affected line of every Unix-generated message — silently, permanently, and in direct contradiction of the promise that the body arrives "exactly as it arrived… otherwise untouched."

The round-trip test could not catch it because every case in it used CRLF.

**Fixed:** the writer now requires CRLF too, and the round-trip test carries bare-LF cases.

## 19. A single rejected recipient discarded the message for all of them

**Severity: medium-high.**

A `550` on the seventh of ten recipients abandoned the delivery before DATA and returned `Permanent`, instructing the caller to give up on all ten. With no retained copy, nine recipients lost the mail.

**Fixed:** reported as *transient* when the envelope has several recipients. A retry sends to all ten again, which is duplication — and duplication is the recoverable failure. The real fix is one recipient per delivery, which needs the Milestone 3 queue to make a partial outcome representable.

## 20. Smaller, and all fixed

- **Addresses admitted control characters.** A bare CR survives command framing and was interpolated into `Received:` headers and outbound `RCPT TO:` commands. Angle brackets and whitespace reached the same places through the unbracketed path form.
- **`SIZE` was advertised and its parameter discarded.** The same "an advertisement is a promise" argument made three lines above it in the same file.
- **The `Received:` loop guard did not exist.** The header was written; nothing counted it. Now refused at 100 hops, counting only the leading header block so a body quoting trace headers cannot forge a loop.
- **Syntactically invalid recipients got `550 No such user`** because routing was consulted before validation — and the unit test asserting `501` passed because it called the session directly and never went through the server.
- **Recipient refusals bypassed the error budget entirely**, so directory harvesting was free.
- **Spool IDs restarted at zero every boot** and `File::create` truncates, so a collision would destroy already-acknowledged mail. Now carries a per-run component and uses `create_new`.
- **A malformed `PIGEON_FORWARD_TO` was accepted at startup** and failed every message, contrary to the module's own stated gating policy.
- **`deliver` had no overall budget** — the per-phase timeouts sum to roughly nine hours — and `QUIT` could hold a slot for five minutes for a reply that is discarded.
- **Null MX was detected as "exactly one record"** rather than "every record is null", and required preference 0.
- **The MSRV job could not fail**: `rust-toolchain.toml` pins `stable`, and rustup's directory override beats the toolchain the action installs.
- **The OpenSSL grep was weaker than the policy it backed up** — host target only, and missing several banned crates.
- **`deny.toml` claimed `ring` was banned** while `Cargo.toml` deliberately selected it.

---

# Third round: auditing the fixes

The second round's fixes were then audited by two more reviewers, one checking each claimed remedy against the code, one hunting for bugs the remedies introduced. Twenty-three of twenty-five held. Three did not, and one of those was a regression created by the fix itself.

## 21. The delivery permit blocked the SMTP session

**Severity: high. Regression introduced by finding 15's fix.**

Moving the semaphore acquisition before `tokio::spawn` did bound pending tasks — but the `await` sits inside `MessageSink::deliver`, which the SMTP session awaits. So the session parked on the outbound pool, which is precisely what the comment four lines above says the design exists to avoid.

It is not covered by any timeout: not `max_session`, which is checked only at the top of the read loop, nor the command or data timeouts. With 32 permits and a one-minute forward, the 256th session waits eight minutes for its `250` — past the sender's own acknowledgement window. The sender times out and retries, and since the message is already spooled *and* already queued, the retry is a **duplicate delivery**. With every session parked, the listener stops accepting.

An unbounded-memory bug was traded for an unbounded stall.

**Fixed properly:** the spawned task carries an identifier, not a message, and re-reads the body from the spool file that was just fsynced. Pending deliveries now cost a few hundred bytes each, so the permit can go back inside the task where it does not block anything.

## 22. The dot-stuffing terminator guard was not fixed, only its neighbour

**Severity: high.**

Finding 18 corrected line-start tracking to require CRLF. The guard that decides whether to insert a newline *before* the terminator still tested "did the last byte happen to be LF" rather than "are we at a line start".

So a body ending in a bare LF got `.\r\n` written mid-line. The receiver — which requires CRLF — never sees end-of-data, and the delivery hangs until the acknowledgement timeout, reports transient, and repeats against the next MX host.

The test could not catch it. Every bare-LF case added in the previous round ends in CRLF.

## 23. The refusal counter was reset by the next successful command

**Severity: medium-high.**

Finding 20e routed recipient refusals through the error budget. But that budget clears on any successful reply, and a directory harvest is `RCPT`, `NOOP`, `RCPT`, `NOOP` — every refusal followed by something that succeeds. The counter never reached its limit.

The test issued ten *consecutive* refusals, which is the one pattern a resettable counter does catch.

**Fixed:** refusals now have their own cumulative counter for the life of the connection, set well above what ordinary mail produces. There is a second test asserting a sender with a few stale addresses is not hung up on.

## 24. Smaller, and all fixed

- **The EHLO name was still unvalidated** where it lands in the `Received:` header. Finding 20a hardened `Address::parse` with a docstring naming this exact hazard and left the other value in the same header untouched. Now sanitised and length-limited.
- **`create_new` prevented nothing.** It applied to the temporary file, and `rename` replaces its destination unconditionally. The final name is now checked explicitly.
- **The duplicate scan ran before the recipient cap**, so a client sitting at the limit paid for a full pass on every further `RCPT`. Reordered, and the common case now compares strings before parsing.
- **`Cargo.lock` was still untracked**, so CI resolves dependencies fresh on every run and the MSRV floor is checked against whatever happens to resolve that day.
- Two more comments claiming properties the code lacks: the `StartTls` arm in `emit` repeating the "compile error" claim that had just been corrected 270 lines above, and the null-MX comment describing a case the code does not handle.

## What the third round actually showed

Three fixes passed tests that were shaped to pass. Not by accident and not by carelessness — each test was written immediately after the fix, from the same mental model, and so it probed the case the author already had in mind rather than the one they had missed.

That is a stronger version of the pattern named in round two. A self-review misses what you believe; a self-written test *confirms* what you believe. Both failure modes were only caught by someone who had not formed the belief.

---

## The pattern worth keeping

Four of these were comments asserting a guarantee the code did not provide: the TLS compile error, the loop guard, the closed crash window, the SIZE advertisement. All four were written in good faith, describing an intention.

An aspirational comment is worse than no comment. It reads as a fact that has been checked, and it stops the next reader — including the person who wrote it — from checking.

---

---

# Fourth round: an external reviewer, and the compiler

Two things happened between rounds. The eight round-three fixes had never been
compiled, and a reviewer outside the project read the tree cold.

## 25. Two of the round-three fixes did not pass

**Found by `cargo test`, not by a reader.**

Round three ended predicting that a fourth round would not come back empty. It
did not, and the first two findings needed no reviewer at all — the round-three
fixes were written, documented as fixed, and never run.

**Finding 22's fix was correct and its test was impossible.** Making the
terminator guard test `at_line_start` is right on the wire, but the round-trip
test asserts byte-identical recovery, and a body whose last line ends in a bare
LF *must* gain a CRLF before the terminator. The test asserted a property SMTP
forbids. The expectation now accounts for it, and the exception is recorded in
`ForwardPolicy::Preserve` and the roadmap rather than absorbed by an assertion —
it is DKIM-safe, RFC 6376 §3.4.3 has the signer add the same CRLF, but
"byte-for-byte" was stated twice without qualification.

**Finding 24c's fix was a behaviour regression.** Moving the recipient cap above
the duplicate scan meant a client at the limit resending an address already in
the envelope got `452` instead of `250`. The duplicate adds nothing; telling the
client to retry it is wrong. Now three steps: a byte-identical pass before the
cap, the cap, then the parsing pass — which keeps the intent, since what needed
bounding was the parsing and not the string compare.

## 26. Spool files were world-readable

**Severity: high. Security.**

`OpenOptions` was never given a mode, so files were created 0666 masked by the
umask — typically 0644. Every message body and envelope on the host was readable
by any local account. `SECURITY.md` states "messages should be created with
restrictive permissions"; the code did not, and nothing checked.

**Fixed:** 0600 on every spool file, with a test asserting the mode. The spool
directory is checked at startup and a permissive one is logged rather than
silently accepted — tightening a directory the operator may have deliberately
grouped is not the daemon's decision.

## 27. The accept list folded the local part

**Severity: medium.**

`PIGEON_ACCEPT` lowercased entries on the way in and the recipient on the way
out, so `Bob@example.com` in the list also authorised `bob@example.com` — a
different mailbox, and one the operator never named.

This is finding 12 again, in the other half of the same invariant. That fix
corrected `Address::same_mailbox` and the dedup path and left the acceptance
path folding both halves. Over-accepting is not mail loss, which is why it
survived, but a rule applied in one place and not its neighbour is not a rule.

**Fixed:** both sides parse and compare through `same_mailbox`. Unparseable
accept-list entries now stop startup, since an entry that can never match
presents as mail refused for no stated reason.

## 28. `Address::parse` accepted addresses that cannot be delivered to

**Severity: medium-high.**

The domain check was a length bound and `contains('.')`. `x@.` satisfies both.
So does `x@..`, `x@-example.com` and `x@example..com`. The local part was bounded
in length and screened for `<`, `>` and control characters, which admits
`a b@example.com` — an unquoted space, which ends the address in every command
and header it is later written into, so the two ends of a relay disagree about
where the address stops.

The startup guard on `PIGEON_FORWARD_TO` calls this function, and its whole
purpose is to refuse a destination that would fail every delivery. With `x@.`
accepted, the guard passes and the daemon starts, answers `250` to everything,
and fails every forward — the exact outcome its comment says it exists to
prevent. A guard is only as strong as the predicate behind it.

**Fixed:** domain labels validated individually (non-empty, ≤63 octets,
alphanumeric and hyphen, no leading or trailing hyphen); local part validated as
either an RFC 5321 dot-string of `atext` atoms or a well-formed quoted string.
Address literals (`[192.0.2.1]`) are now refused explicitly rather than by
accident, and the reason is written down: a forwarder resolves MX records for
named domains, and accepting a form nothing downstream handles only moves the
failure later.

## 29. The spool writability check did not check writability

**Severity: medium.**

`create_dir_all` succeeds on a directory that already exists and is read-only.
The module opens by declaring an unwritable spool a startup-aborting failure;
what it actually verified was that the path could be created if absent.

**Fixed:** a probe that writes, fsyncs, links and removes by the same route a
message takes, before the listener binds. That is the only way to learn that the
path is writable, that fsync works on it, and that the filesystem is not out of
space or inodes — rather than discovering it after a sender has been told `250`.

## 30. The collision check was a race, and `rename` ignored it

**Severity: medium.**

Finding 24b replaced `create_new` on the temporary with a `try_exists` check on
the final name. Two problems. `unwrap_or(false)` turns an inspection error —
`EACCES`, `EIO` — into "absent", after which `rename` replaces the destination
unconditionally. And even when it reads correctly, there is a window between the
check and the rename.

**Fixed:** `hard_link` instead of `rename`. It fails with `AlreadyExists` if the
destination is taken, atomically, which is the property that was wanted both
times. The temporary is removed either way.

## 31. `Cargo.lock` was listed as fixed and was still untracked

Finding 24d recorded it under "all fixed". `git status` disagreed. Now tracked.

## 32. The documentation had drifted past the code, in both directions

- **`README.md` presented three unimplemented commands as "a working setup".**
  `pigeon` prints `not yet implemented` and exits. The section now says so before
  describing the intended interface.
- **The daemon's module doc claimed Milestone 0 performs no onward delivery.**
  It forwards.
- **`ROADMAP.md` and this document both still described the resolver as
  classifying errors by text**, which finding 13 corrected. This is the
  aspirational-comment failure running backwards: a document asserting a defect
  that is no longer there sends the next reader to audit code that is already
  right.
- **`ARCHITECTURE.md` omitted wildcard aliases from the precedence diagram**,
  which the roadmap and README both include.

## 33. The daemon had no tests at all

The M0 spine — spooling, durable writes, collision handling, cleanup, startup
recovery, recipient acceptance — lived entirely in `pigeond` and was covered by
nothing. Every integration test stopped at a synthetic sink, so the code that
actually decides whether an accepted message survives had never been executed by
a test.

Three of the findings above are in that code. Two of them are the kind a first
test would have caught immediately.

**Fixed:** thirteen tests over the spine. What is still missing is one
listener-to-scripted-peer test that exercises the whole path in a single run.

## 34. The delivery budget bounded a connection, not a delivery

**Severity: medium-high.**

`pigeon_smtp::deliver` carries a 30-minute total budget, and `forward` calls it
once per MX host in a loop. A destination publishing ten exchanges that accept
TCP and then go silent held one of 32 delivery permits for five hours. Enough of
them and forwarding stops, with no error anywhere — every task is inside a
timeout that has not expired yet.

This is finding 5 in a different costume. Bounding one thing and not the thing
above it does not make the process harder to exhaust; it changes which resource
runs out first.

**Fixed:** a deadline for the whole forward, checked before each host and used
to shorten every wait beneath it. The budget is a field rather than a constant,
because a half-hour bound cannot be asserted against in a test suite — and a
defence with no test is the specific thing this document keeps being about. The
test drives three stalling hosts against a 400 ms budget; with the deadline
removed it takes 60 seconds and fails.

## 35. `forward` flattened typed errors into `String`

**Severity: medium. Deferred capability, not a live fault.**

The delivery client distinguishes permanent from transient with some care, and
`forward` consumed `is_permanent()` internally to decide whether to try the next
host — then returned `Result<String, String>`, discarding it. Nothing downstream
could tell a refused recipient from an unreachable network.

Nothing needed to yet, which is why it survived. Milestone 3's queue chooses
between retry and dead-letter on exactly this distinction, and a seam that has
to be reintroduced later is more disruptive than one carried early.

**Fixed:** `ForwardError::Permanent | Transient`, with the mapping stated at each
site — null MX permanent, NXDOMAIN permanent, resolver fault transient, no usable
host transient. The log line now carries the verdict so an operator can tell
whether a stranded message is worth resending by hand.

## 36. Abandoned temporaries were invisible

A crash between `create_new` and the link leaves a `.partial` file that nothing
reads and nothing counts. Inert — `boot` differs per run, so no later identifier
reuses the name — but a crash loop consumes disk for reasons the startup report
did not mention.

**Fixed:** the startup survey counts them separately and says what they are.
They are still not deleted, and that is the decision rather than an omission: a
sweep cannot distinguish an abandoned temporary from one another instance is
writing this instant, and deleting the second destroys mail in flight to reclaim
a few kilobytes.

## 37. Nothing exercised the whole path

The integration tests in `pigeon-smtp` stop at a synthetic sink, and the daemon
tests added earlier in this round each stop at a function boundary. No test
walked listener → session → spool → resolver → delivery client → receiving
server in one run, which is the only arrangement in which the components have to
agree with each other.

**Fixed:** three end-to-end tests against a scripted peer, with the resolver
faked and the port injected so nothing leaves loopback and no DNS is consulted —
every other component is the production one. They assert that a message is
readdressed to the configured destination, that the trace header leads the body,
that a refused recipient never reaches the spool *and* never triggers an
outbound connection, and that a message the receiver rejects is left in the
spool rather than deleted.

## 38. The `cargo deny` gate failed the first time it was ever run

**Severity: medium.**

`deny.toml` was written, committed, and wired into CI, and `cargo deny check`
had never been executed against the repository it governs — the tool was not
even installed. Running it produced ten errors, all `wildcard`, all against the
workspace's own crates.

The rule is right: a dependency with no upper bound defers a supply-chain
decision to whatever resolves next. What it caught was the twelve internal
crates referring to each other by path, which carry no version and are not meant
to — they are one unit, versioned together, never resolved from a registry. So
the rule fired twelve times on the project's own layout and zero times on a
third-party crate, which is what it exists to catch.

`allow-wildcard-paths` alone was not enough: cargo-deny applies it only to
crates that cannot be published, since crates.io forbids path dependencies and a
versionless path dep in a publishable crate really would be unresolvable. The
workspace is now marked `publish = false`, which is accurate — nothing here is
published, package publishing is Milestone 10 — and has the side benefit that
`cargo publish` cannot be run by accident on crate names nobody has reserved.

Verified non-vacuous the same way as the rest of this round: adding
`thiserror = "*"` to a crate makes the gate fail.

This is finding 11 with a longer fuse. That one was "CI had never run"; this is
one gate inside CI that had never run even after CI did, because it needed a
tool nobody had installed. **A policy file is not a policy until something
executes it.**

## Every fix in this round was mutation-tested

Round three's lesson was that a test written from the same mental model as the
fix confirms the author's belief rather than the behaviour. The remedy used here
was to break each fix deliberately and confirm its test fails:

| Mutation | Result |
|---|---|
| Forward deadline replaced with the old per-connection budget | fails after 60 s |
| Null MX reported transient | fails |
| Spool file mode set to 0644 | fails, naming the mode |
| `hard_link` reverted to `rename` | fails, original destroyed |
| Outbound envelope not readdressed | fails, printing the transcript |
| `thiserror = "*"` added to a crate | `cargo deny` bans gate fails |

That is not proof the tests are good. It is proof they are not vacuous, which is
the failure mode this document has recorded three times.

## What the fourth round showed

Round three's lesson was that a self-written test confirms what its author
believes. Round four adds a blunter one: **two of the eight round-three fixes
were never compiled.** No amount of review discipline substitutes for running
the thing, and the confidence in that round's write-up was drawn entirely from
the reasoning behind the fixes rather than from any evidence they worked.

The other six findings came from a reviewer with no stake in the code. Three of
them — the accept list, the address validator behind the startup guard, the
spool probe — are cases where an invariant was stated in one place and enforced
in another that did not quite match. Those do not look like bugs while reading
the file that states the invariant.

---

---

# Fifth round: fuzzing

Five targets over everything that consumes untrusted bytes. Two real bugs, both
memory-safe, both returning successfully — a harness that only watched for
crashes would have found neither.

## 39. The command parser let a bare CR through into every value it returned

**Severity: medium-high. Header injection.**

**Found within seconds of the first target's first run.**

`strip_terminator` removes only the *trailing* CRLF, so `EHLO mail.example.com\ri`
parsed cleanly and produced a greeting holding a bare CR. The same held for
`MAIL`/`RCPT` paths and their parameters. Those values are interpolated into the
`Received:` header and into outbound `RCPT TO:` commands, where a lenient reader
treats a CR as a line break.

This is the third appearance of one mistake:

- Finding 20a hardened `Address::parse` against exactly this, with a docstring
  naming the hazard.
- Finding 24a then observed that the EHLO greeting reaching the *same header*
  was still unguarded, and added `sanitise_for_header`.
- The parser itself was never touched, so every new consumer of a `Command`
  inherits the obligation to remember.

**Fixed at the parser.** A `Command` can no longer hold a control character at
all; `sanitise_for_header` stays as the second layer. Sanitising at the point of
use is a rule each future caller has to know, and finding 24a exists precisely
because one did not.

## 40. A receiving server could forge entries in Pigeon's log

**Severity: medium.**

The final reply text is captured into `Accepted::message`, which `pigeond`
writes into a log line with `Display`. `read_reply` trims only the end of each
line, so `250ME\r2` arrived with its CR intact.

Whatever answers on port 25 therefore chooses what Pigeon's operator reads. In a
terminal that is an overwritten line; in a file it is a second entry that never
happened. For a forwarder the peer is usually the operator's own mailbox
provider, which is what keeps this below high — but Milestone 7 delivers to
arbitrary MX hosts, and the reply is attacker-chosen there.

**Fixed:** reply text is sanitised as it is accumulated and bounded to 512
bytes. Same root cause as 39 — only the trailing terminator was ever stripped.

## 41. A wrong assertion, which is also a finding

`line_reader`'s first version asserted that a framed line contains no LF. That
is what `LineReader`'s docstring implied — "Frames CRLF-delimited command
lines". The implementation splits on LF and keeps it, and always has.

The code was right. The docstring had never described it. The assertion was
written from the docstring rather than from the code, which is exactly how a
reader who trusts a comment ends up reasoning from a guarantee that does not
hold — the pattern this document named after round one and has now demonstrated
in the other direction.

The docstring now says what the framer does, and why leniency stops at the
command layer: the *body* terminator requires full CRLF on both the reading and
writing sides, because that is the boundary a smuggled envelope would cross.

## What fuzzing showed

Every finding above is in code that three rounds of human review had already
read, twice under a specific instruction to look for this class of bug. What the
reviewers could not do is enumerate the inputs.

Worth noting what made the targets productive: none of them merely check for
panics. The two strongest are differential — feed the same bytes in different
chunk boundaries and require the same answer — which is the property an
example-based test structurally cannot hold, because its author picks the
splits they thought of. A terminator split across two reads is the bug class
this codebase has already been bitten by twice.

See `fuzz/README.md`.

---

## What to carry into Milestone 1

- `DataReader` still buffers whole messages in memory. At the 50 MB ceiling that is 50 MB per concurrent connection, and it needs to write through to the spool once the spool is real.
- ~~The resolver classifies errors by matching their text.~~ Corrected in round two — see finding 13. This line survived the fix that removed the thing it describes, which is the same failure mode as an aspirational comment, running the other way: a document asserting a defect that is no longer there sends the next reader to audit code that is already correct.
- Forwarding still has no retry. The spool copy is the fallback, and it is a manual one.
- `Address::parse` refuses address literals. Legal RFC 5321, unused by a forwarder, and now refused deliberately rather than by accident — revisit if a real destination needs one.
- Stranded `.partial` files are counted at startup but never swept, because a sweep cannot be told apart from destroying a message another instance is writing.
- ~~The parsers have never been fuzzed.~~ Five targets now cover the command parser, both framers, the address validator and the delivery client — see round five. They are advisory in CI rather than a required gate, and no target has yet run for longer than a few minutes.
- **Milestone 0's exit criterion is still unmet.** No message from a real sender has reached a real mailbox. Everything above was verified against this project's model of SMTP, not against SMTP.
