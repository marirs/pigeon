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

## What to carry into Milestone 1

- `DataReader` still buffers whole messages in memory. At the 50 MB ceiling that is 50 MB per concurrent connection, and it needs to write through to the spool once the spool is real.
- The resolver classifies errors by matching their text, which fails safe in one direction only.
- Forwarding still has no retry. The spool copy is the fallback, and it is a manual one.
