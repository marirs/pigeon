# Two nodes

Consolidating every domain you own onto one host makes that host a single point
of failure for all of your mail. This is how to run a second one.

---

## The design, in one paragraph

Two independent Pigeons. Each has its own database, its own spool, its own
queue, and neither knows the other exists. Both MX records point at both;
senders pick one and retry the other when it does not answer. A message belongs
entirely to the node that answered `250` for it, and that node delivers it.

Nothing is shared and nothing is replicated at runtime. That works because a
forwarder has no shared mutable state: there are no mailboxes to keep in step,
no read-your-writes to honour, and no message that two nodes could both be
responsible for.

**Adding a second MX record alone is not this.** Without the configuration on
both nodes, the second one refuses recipients the first accepts, which looks to
a sender like intermittent rejection and to you like nothing at all.

---

## What has to match

The read-mostly half: which domains are carried, where their mail goes, and
which keys sign it.

```
# on the node you edit
pigeon config export /tmp/routing.csv
pigeon config checksum

# copy /tmp/routing.csv and the keys directory to the other node, then
pigeon import csv /tmp/routing.csv --replace
pigeon config checksum      # must match
```

The checksum covers domains, aliases, destinations and the active DKIM
selectors. It does **not** cover the private keys, which are not in the database
at all: two nodes with matching checksums and different key files sign
differently, and the published DNS record matches only one of them. Copy
`keys/` with the configuration, and copy `srs.key` too — a bounce is delivered
to whichever node the sender's MTA picks, and a node that cannot verify the
return path it did not issue will reject it.

There is deliberately no replication protocol. One would mean a listener, an
authentication scheme and a conflict rule for simultaneous edits: three new
failure modes on a host whose configuration changes whenever somebody adds an
alias. Copying a file and comparing a checksum has one failure mode, and you can
see it.

**Pick one node to edit on.** Nothing enforces that, and nothing merges two
divergent configurations — the last `--replace` import wins, in full.

---

## What does *not* have to match

Everything per-node: the database's queue tables, the spool, the metrics
endpoint, the TLS certificate (each node needs one for its own name if you
publish per-node names). Node A's queue is not Node B's business.

---

## Duplicates

Two nodes do not produce duplicates by themselves. A sending server delivers to
exactly one MX, so only one node ever accepts a given message.

What does produce them is the same thing that produces them on one node: a lost
`250`. If Pigeon commits the queue rows and the acknowledgement is lost on the
way back, the sender retries — possibly at the other node — and the message is
delivered twice. This is inherent to at-least-once SMTP and every MTA has it.
Pigeon does not suppress it, and `M3-DESIGN.md` §6.2 says why: content-based
suppression silently discards legitimately repeated mail, and a duplicate the
recipient can see beats a message nobody can find.

---

## Failing over

There is nothing to fail over *to*: both nodes are always live and senders
already know about both. What you do when one dies:

**Nothing, for the mail arriving now.** Senders retry the other MX within
minutes. That is the whole point of the second node.

**For the mail already accepted by the dead node** — the queue it was working
through — nothing else can deliver it: that spool and that database are on that
machine. It is not lost, it is *stopped*. When the host comes back, the daemon
starts, leases expire, and the queue drains. If the host is not coming back:

```
# on a replacement, with the dead node's database and spool restored
pigeon verify /var/lib/pigeon/pigeon.db
systemctl start pigeond
pigeon queue list
```

Restoring a queue onto a *different* machine is safe because a claim is fenced
by a token: the dead node's workers cannot come back and complete rows that the
new node has since taken.

**If the host is gone and the queue with it**, mail accepted in the last five
days is lost without a bounce. That is the one case a second node does not cover
and backups do not either, since a backup taken before acceptance does not
contain the message. It is the reason the queue exists rather than an argument
against it: the window is minutes, not days, for anything that was going to
deliver normally.

---

## Rolling upgrade

One node at a time, and check between them.

```
# node A
systemctl stop pigeond       # drains: stops accepting, finishes what is in flight
install -m0755 pigeond /usr/local/bin/pigeond
systemctl start pigeond
pigeon health                # schema version, queue age

# then node B, once A is healthy
```

While A is down, B carries everything: senders retry, and no mail is refused.
This is the property that makes the second node worth having even if you never
lose a machine.

**Migrations run forwards on start and are not reversible.** A node upgraded to
a newer schema cannot be downgraded, and an older binary refuses a database it
does not recognise rather than guessing. Upgrade one node, run it for a while,
then do the other — that ordering means a bad release is one node's problem
rather than both.

**Do not run two different versions for longer than a change window.** Nothing
breaks — the nodes do not talk — but a routing feature that exists on one and
not the other means mail is accepted or refused depending on which MX the sender
picked, which is the most confusing failure this design has.

---

## Checking both

```
pigeon health                # per node: prints the node's own name first
pigeon config checksum       # must be identical
pigeon domains check         # both nodes, since DNS is per-domain not per-node
```

`pigeon health` prints the machine's hostname rather than the configured mail
hostname, because both nodes share the mail hostname deliberately — that is what
makes them interchangeable to a sender, and it is exactly why it cannot tell you
which one answered.
