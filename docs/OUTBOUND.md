# Outbound Sending

## Goal

Allow authenticated users and applications to send mail as explicitly authorized identities on verified Pigeon domains.

Outbound sending is a first-class Pigeon capability, but it is deliberately separate from alias forwarding.

## Submission

Pigeon exposes authenticated message submission on TCP/587.

Recommended baseline:

```text
Port:       587
Encryption: STARTTLS required
Auth:       required
```

Unauthenticated submission must not relay internet mail.

## Client flow

```text
Mail.app / Thunderbird / application
            │
            │ SMTP AUTH + STARTTLS
            ▼
          Pigeon
            │
            ├── authenticate credential
            ├── authorize sender
            ├── validate domain ACTIVE
            ├── validate envelope
            ├── validate From policy
            ├── spool
            └── queue
                    │
                    ├── direct
                    │     ↓
                    │ recipient MX:25
                    │
                    └── relay
                          ↓
                      smarthost
```

## Identity model

There are three separate concepts:

1. inbound alias
2. outbound sender identity
3. authenticated principal

Example:

```text
alias:
  billing@example.com → founder@example.net

sender identity:
  hello@example.com

principal:
  macbook-mail
```

`macbook-mail` may be granted:

```text
hello@example.com
founder@example.com
```

It cannot send as `billing@example.com` unless separately authorized.

This prevents inbound routing configuration from accidentally expanding outbound authority.

## SMTP envelope policy

For every submission Pigeon validates:

- authenticated principal exists and is enabled
- envelope sender domain is managed by Pigeon
- domain is ACTIVE
- outbound is enabled
- sender identity is allowed
- header `From:` satisfies configured policy
- message is within size/rate limits

A safe default is to require the visible From domain to be one of the authenticated principal's allowed domains.

## DKIM signing

Pigeon signs originated outbound mail using the active DKIM key for the From domain.

Recommended behavior:

- sign after all Pigeon-owned modifications
- include stable, appropriate headers
- do not expose private key material
- support selector rotation
- make signing failure fatal before external delivery

## SPF

SPF is determined by the IP/host that performs final SMTP delivery.

### Direct mode

The domain must authorize the Pigeon egress IP.

### Relay mode

The domain must authorize the upstream relay as required by its sending architecture.

The CLI should print mode-specific DNS guidance.

## DMARC alignment

Pigeon should verify its intended outbound configuration is capable of producing DMARC-aligned mail.

At least one aligned authentication mechanism should pass in normal operation, with DKIM being under Pigeon's direct control when Pigeon signs.

## Delivery mode: direct

```text
Pigeon
  ↓ MX lookup
recipient MX
```

Requirements:

- outbound TCP/25
- stable public IP
- PTR
- hostname/A consistency
- TLS
- queue/retry
- reputation management
- bounce processing

Direct mode is the pure self-hosted option.

## Delivery mode: relay

```text
Pigeon
  ↓ authenticated SMTP
upstream relay
  ↓
recipient
```

Use cases:

- cloud provider blocks TCP/25
- operator prefers managed IP reputation
- operator wants provider-specific deliverability infrastructure

Relay configuration is named:

```text
relay: primary
relay: backup
```

Domains can choose:

```bash
pigeon domain delivery example.com relay primary
```

## Credentials

Submission credentials are application-style credentials, not mailbox passwords.

Properties:

- generated random username
- high-entropy password/token
- password stored as a slow password hash where interactive authentication semantics allow it
- revoke
- rotate
- last-used timestamp
- optional source IP restrictions later

Secrets must never be printed again after creation.

## Abuse prevention

Even a private/self-hosted tool must assume credentials can leak.

Controls:

- per-principal rate limits
- per-domain rate limits
- connection limits
- message size limits
- maximum recipients/message
- daily optional safety cap
- anomaly logging
- credential revoke
- optional allowlisted source networks
- no unauthenticated relay

## Queue

Outbound submissions are acknowledged after durable queueing, not after final recipient delivery.

A successful submission means:

> Pigeon accepted responsibility for delivery.

Not:

> the remote mailbox accepted the message.

## Bounce processing

Pigeon must correlate delivery failures with queued recipients.

Permanent failures:

```text
5xx → BOUNCED
```

Transient failures:

```text
4xx / timeout / temporary DNS → DEFERRED
```

Retry schedule should be configurable within sensible bounds.

## Diagnostic send

A later CLI feature may support:

```bash
pigeon send test \
  --from hello@example.com \
  --to you@example.net
```

This is for configuration diagnostics, not intended to become a general campaign-send CLI.

## Mail client compatibility

The submission service should target standard SMTP clients such as:

- Apple Mail
- Thunderbird
- Outlook
- application SMTP libraries

No Pigeon-specific client protocol should be required.

## Optional future API

An HTTP send API is explicitly not required for the initial headless architecture.

It can be considered later as an optional module without changing the core SMTP submission path.
