# Alerting

Pigeon has no dashboard. When a domain stops carrying mail, the operator finds out by email.

That sounds circular, and in one specific way it is. This document covers how to make it work anyway, and where it still cannot be relied on.

## Configuration

```toml
[alerts]
enabled  = true
identity = "pigeon@ops.example.com"
to       = "me@example.net"

confirm_checks    = 3      # consecutive failures before a domain counts as failing
cooldown          = "6h"   # minimum gap between alerts for one domain
breaker_threshold = 0.5    # share of domains failing at once that implicates the resolver
```

Per-domain override:

```bash
pigeon domain notify example.com ops@example.net
pigeon domain notify example.com --clear
```

## The alert identity must not be a domain under test

An alert is never sent as the domain it reports on.

Take `example.com`, whose DKIM record was deleted. Sending `alerts@example.com` to the operator produces an unsigned message, from a domain publishing `p=reject`, to a receiver that honours it. The message is discarded.

The alert is destroyed by precisely the fault it exists to report. The operator sees nothing, and silence is indistinguishable from health.

So `alerts.identity` names one address on a domain the operator keeps healthy, and Pigeon treats it as machine identity rather than mail-domain configuration. It lives in TOML, not SQLite, and it is validated at startup: an unusable alert path is a critical local failure and aborts the boot.

Two further consequences:

- The alert identity's own domain is never gated by the health of any other domain.
- If a domain's only `notify` address is on that same domain, Pigeon falls back to the global operator address rather than attempting a delivery it expects to fail.

## Storms

Domain health is not independent. A resolver outage fails all of them in the same check cycle, so the naive implementation sends one alert per domain per cycle for as long as the outage lasts.

Four filters, in order of how much noise they remove:

**Transitions, not states.** Alert when a domain moves healthy → failing. A domain that is still failing is not news. Every alert corresponds to a change.

**Confirmation window.** A transition counts only after `confirm_checks` consecutive failures. One resolver timeout is noise.

**Circuit breaker.** If more than `breaker_threshold` of domains fail in a single cycle, the fault is the resolver, not the domains. Per-domain alerts are suppressed and one message is sent instead:

```text
Subject: [Pigeon] Resolver may be unavailable — 38 of 42 domains failing

38 of 42 domains failed DNS validation in the same check cycle.

This pattern usually indicates a resolver or network fault rather than
38 simultaneous DNS misconfigurations.

Per-domain alerts are suppressed until the rate returns to normal.

  Resolver:  127.0.0.53
  First seen: 2026-08-26 03:14:22 UTC
  Affected:  38 domains

Mail for affected domains is being refused. Run `pigeon domains check`.
```

**Cooldown.** At most one alert per domain per `cooldown`, however much it flaps.

## Recovery notices

Sent on the transition back to healthy, and not optional.

Without them the operator cannot distinguish a fixed domain from a forgotten one, and quickly learns to ignore the channel — at which point the alerting system is worse than none, because it produces false confidence.

```text
Subject: [Pigeon] example.com recovered

example.com passed all checks and is ACTIVE again.

  Failing for:  1h 12m
  Resolved at:  2026-08-26 04:26:10 UTC

Mail is being accepted normally.
```

## Failure alert

Alert bodies reuse the `pigeon domain check` diff, which already states what was observed, what was expected, and the exact record to publish.

```text
Subject: [Pigeon] example.com gated — MX record incorrect

Mail for example.com is being REFUSED as of 2026-08-26 03:14:22 UTC.

✗ MX

  Observed:  mx.old-provider.net
  Expected:  mx1.yourserver.net

  Publish:

    Type:      MX
    Name:      @
    Priority:  10
    Value:     mx1.yourserver.net

✓ SPF    ✓ DKIM    ✓ DMARC    ✓ TLS

Failing since:  2026-08-26 03:14:22 UTC
Confirmed over: 3 consecutive checks

Other domains on this host are unaffected.

Verify with:  pigeon domain check example.com
```

The impact line comes first on purpose. "MX record incorrect" is a fact; "mail is being refused" is why the operator should stop what they are doing.

## Delivery path

Alerts are delivered out of band and never traverse the routing engine.

Routing them normally would allow an alert to be swallowed by a catch-all, to loop between two Pigeon-managed domains, or to be gated by the health of the very domain it concerns.

They are also exempt from per-domain outbound enablement, and are rate-limited globally and independently of mail traffic.

## Testing the alert path

The alert channel fails silently by construction: if it stops working, the symptom is an absence of messages, which looks exactly like everything being fine.

So test it explicitly, both after setup and periodically.

```bash
pigeon alerts test
```

```text
Sending test alert...

  Identity:   pigeon@ops.example.com
  Recipient:  me@example.net              (global operator)
  Path:       out-of-band, direct to MX

✓ Resolved MX for example.net    → mx.example.net
✓ Connected                       203.0.113.10:25
✓ STARTTLS                        TLS 1.3
✓ Accepted                        250 2.0.0 Ok: queued as 4bXk2m

Test alert delivered.
```

Target a specific domain's configured recipient rather than the global one:

```bash
pigeon alerts test --domain example.com
```

```text
  Recipient:  ops@example.net             (domain notify)
```

On failure the command reports where the path broke and exits non-zero, so it can be run from a cron job or an external monitor:

```text
✓ Resolved MX for example.net    → mx.example.net
✓ Connected                       203.0.113.10:25
✗ Rejected                        550 5.7.1 SPF check failed

The alert identity's domain does not authorise this host.

Publish on ops.example.com:

  Type:   TXT
  Name:   @
  Value:  v=spf1 mx -all

Alert path is NOT working.
```

An alert path that is broken and untested is the failure mode this whole document exists to prevent. Run `pigeon alerts test` from the same monitor that watches the daemon.

## Diagnostic send

Separate from alerting, for verifying the outbound path as a normal sending identity:

```bash
pigeon send test --from hello@example.com --to you@example.net
```

This goes through the real submission path — sender authorisation, DKIM signing, delivery mode — so it exercises what actual mail will do. `pigeon alerts test` deliberately does not, because the alert path is out of band by design.

Both are configuration diagnostics. Neither is a general-purpose send command.

## What this channel cannot tell you

Email alerting about email infrastructure shares a failure domain with the thing it monitors.

If outbound port 25 is blocked, the host is blocklisted, or the alert identity's domain regresses, alerts stop arriving — and the silence is indistinguishable from health.

Email is therefore the convenient channel, not the authoritative one. `pigeon status`, the exit codes and the structured log remain the source of truth. An operator who genuinely depends on alerts should add a channel that does not share this failure domain: an external monitor polling `pigeon domains check --json`, or a webhook.

## Non-DNS alerts

The same machinery carries the other conditions worth waking someone for:

| Alert | Trigger |
|---|---|
| `CertificateExpiring` | 30, 7 and 1 days before expiry |
| `QueueBacklog` | queue growing faster than it drains, over a sustained window |
| `DiskPressure` | spool filesystem below a configured threshold |
| `ResolverSuspect` | circuit breaker tripped |

Certificate expiry deserves particular attention. It is entirely predictable, entirely preventable, and takes down submission completely when missed.
