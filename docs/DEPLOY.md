# Deploying Pigeon

From nothing to mail arriving, in the order that works. Roughly twenty minutes,
most of it waiting for DNS.

---

## Before you start

You need:

- A host with a **static address** and **port 25 reachable in both directions**.
  Most residential connections and several cloud providers block outbound 25;
  check before anything else, because everything downstream assumes it. If it is
  blocked, you need a [smarthost](#sending-through-a-smarthost).
- **Reverse DNS** for that address, pointing at the name this host will call
  itself. Set it with whoever gave you the address; you cannot set it yourself.
- **Control of the DNS** for the domains you want to forward.
- A **mailbox somewhere else** to forward to. Pigeon does not hold mail.

---

## 1. Install

```bash
cargo build --release --locked
sudo install -m0755 target/release/pigeond /usr/local/bin/
sudo install -m0755 target/release/pigeon  /usr/local/bin/

sudo useradd --system --home /var/lib/pigeon --create-home pigeon
sudo install -d -m0700 -o pigeon -g pigeon /var/lib/pigeon/keys
sudo install -d -m0700 -o pigeon -g pigeon /var/lib/pigeon/secrets
sudo install -d -m0700 -o pigeon -g pigeon /var/lib/pigeon/spool
sudo install -d -m0755 /etc/pigeon
```

Or use the container: `docker build -f packaging/Dockerfile -t pigeon .`

## 2. Configure

`/etc/pigeon/pigeon.toml`:

```toml
# The name this host calls itself. It goes in every Received: header and every
# EHLO, and its forward and reverse DNS must agree with your address.
hostname = "mx.example.com"

# Only consulted if the process starts as root. Under the packaged systemd unit
# it never does.
user = "pigeon"

database = "/var/lib/pigeon/pigeon.db"
spool    = "/var/lib/pigeon/spool"
keys     = "/var/lib/pigeon/keys"
secrets  = "/var/lib/pigeon/secrets"
srs_secret_file = "/var/lib/pigeon/srs.key"

[smtp.inbound]
listen = "0.0.0.0:25"
# Opportunistic: senders that can encrypt will, senders that cannot still get
# through. Omit both and STARTTLS is not offered at all.
tls_certificate = "/etc/letsencrypt/live/mx.example.com/fullchain.pem"
tls_private_key = "/etc/letsencrypt/live/mx.example.com/privkey.pem"

[alerts]
enabled  = true
# Must NOT be on a domain this host carries: an alert about a broken domain
# cannot be sent from the domain it is reporting on.
identity = "pigeon@some-other-domain.example"
to       = "you@your-mailbox.example"
```

Generate the SRS secret, which signs return paths:

```bash
sudo -u pigeon sh -c 'head -c32 /dev/urandom | base64 > /var/lib/pigeon/srs.key'
sudo chmod 0600 /var/lib/pigeon/srs.key
```

Startup validates all of this and refuses to run if a directory is too
permissive or a file is missing. That is deliberate: running half-configured is
worse than not running.

## 3. Add a domain

```bash
export PIGEON_CONFIG=/etc/pigeon/pigeon.toml
sudo -u pigeon pigeon domain add example.com --to you@your-mailbox.example
```

This generates a DKIM key and prints the record to publish. Then publish, at
your DNS provider:

```text
example.com.                 IN MX   10 mx.example.com.
example.com.                 IN TXT  "v=spf1 mx ~all"
pigeon._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=…"   # as printed
_dmarc.example.com.          IN TXT  "v=DMARC1; p=none; rua=mailto:you@…"
```

Start with `p=none` on DMARC. Move to `quarantine` or `reject` once you have
seen reports and know your mail passes.

## 4. Check before starting

```bash
sudo -u pigeon pigeon domain check example.com
```

Everything it complains about, it also tells you how to fix. Wait for
propagation and run it again; a `FATAL` here means mail will not arrive.

## 5. Start

```bash
sudo install -m0644 packaging/pigeond.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pigeond
sudo -u pigeon pigeon health
sudo -u pigeon pigeon alerts test
```

Run `alerts test` now rather than later: the channel that reports failures can
fail silently, and its silence looks exactly like health.

## 6. Send yourself a message

From an external account, to `anything@example.com`. Then:

```bash
sudo -u pigeon pigeon queue list          # should be empty: it went straight out
journalctl -u pigeond -n 50               # "accepted" and "forwarded"
```

Check the received headers at the far end. `dkim=pass` and an ARC set that
validates are what you are looking for.

---

## Sending through a smarthost

If outbound port 25 is blocked, or your address has no sending reputation:

```bash
sudo -u pigeon sh -c 'printf %s "the-password" > /var/lib/pigeon/secrets/upstream.pw'
sudo chmod 0600 /var/lib/pigeon/secrets/upstream.pw

sudo -u pigeon pigeon relay add upstream smtp.provider.example \
    --username you@example.com --secret upstream.pw
sudo -u pigeon pigeon domain relay example.com upstream
```

`--secret` is the *name* of a file in the secrets directory. Credentials are
sent only over TLS: a smarthost that offers no STARTTLS is one Pigeon defers to
rather than logging in to.

## Accepting mail from your own applications

Submission on 587, for a phone or a script that needs to *send*:

```toml
[smtp.submission]
listen = "0.0.0.0:587"
tls_certificate = "/etc/letsencrypt/live/mx.example.com/fullchain.pem"
tls_private_key = "/etc/letsencrypt/live/mx.example.com/privkey.pem"
```

```bash
sudo -u pigeon pigeon auth add phone
sudo -u pigeon pigeon auth allow phone you@example.com
```

The password is printed once. A credential can send nothing until an address is
allowed.

## Certificates

Pigeon does not obtain them — use `certbot`, `lego`, or whatever already renews
certificates on the host. It reloads the file when it changes, so a renewal
needs no restart, and it alerts two weeks before expiry.

Issuance stays outside on purpose: it needs an HTTP-01 responder on port 80 or a
DNS-01 credential with write access to your zone, and a mail server holding
either would be holding the keys to its own DNS to save one cron entry.

---

## Common first problems

**Nothing arrives, `domain check` is clean.** Check that port 25 is reachable
*inbound*: `nc -zv mx.example.com 25` from elsewhere. Cloud firewalls block it
by default more often than not.

**Mail arrives but lands in spam.** Check reverse DNS
(`pigeon domain check` reports it), and that SPF names this host. Give DMARC
reports a week before changing anything else.

**`domain check` says the DKIM record does not match.** The record is compared on
its `p=` tag, so this is a real difference rather than formatting. The usual
cause is a provider that split the record and dropped a character; re-paste it.

**Everything is refused with 452.** The spool filesystem is below the disk floor.
`pigeon health` shows the free space.

**The daemon will not start.** It says why on stderr and exits non-zero. Every
startup failure is local and unambiguous by design: a permission, a missing
file, a listener that will not bind.
