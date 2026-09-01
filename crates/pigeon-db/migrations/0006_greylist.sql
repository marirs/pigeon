-- Greylisting: who has tried before, and when they first tried.
--
-- The bet is that a real MTA retries and a spam engine does not. It costs the
-- first message from a new sender a delay, and nothing after that — which is
-- why the triplet is remembered rather than the message: delaying every message
-- from a known-good sender would be a permanent tax for a one-off benefit.
--
-- The triplet is (client address, envelope sender, recipient), the classic
-- form. Narrower than the address alone, because a large provider's outbound
-- pool has hundreds of addresses and the one that retries is rarely the one
-- that tried first — so the address alone would greylist forever. Wider than
-- the message, because a message id would let a sender bypass the delay by
-- changing it.
CREATE TABLE greylist (
    -- The client address as text, normalised by the caller: an IPv4-mapped
    -- IPv6 form and its plain form are one host, and two rows for it would be
    -- two delays.
    address    TEXT NOT NULL,
    sender     TEXT NOT NULL,
    recipient  TEXT NOT NULL,

    -- When this triplet was first refused. The delay is measured from here, so
    -- a sender that retries promptly waits the configured time once, and one
    -- that retries a day later is admitted immediately.
    first_seen INTEGER NOT NULL,

    -- When it was last seen at all, refused or admitted. Retention reads this:
    -- a triplet nobody has used for a long time is not evidence of anything.
    last_seen  INTEGER NOT NULL,

    -- Set once the triplet has been admitted, so a later message skips the
    -- delay without re-deriving it from the timestamps.
    passed_at  INTEGER,

    PRIMARY KEY (address, sender, recipient)
) STRICT;

-- Retention scans by age, and the table is otherwise only ever read by key.
CREATE INDEX greylist_by_last_seen ON greylist(last_seen);
