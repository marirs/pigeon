-- Milestone 3: the durable queue.
--
-- Design and reasoning: `M3-DESIGN.md` §3. The short version of why the shape
-- is what it is:
--
-- A message is a *finished* thing. Milestone 2 fixes its bytes, its envelope
-- sender, its policy and its signing identity at acceptance, so delivery moves
-- bytes and never re-derives them. What varies per destination is the outcome,
-- which is why `delivery` exists as its own table rather than as columns on the
-- message: a partial outcome has to be representable, which is exactly what
-- finding 19 in `M0-FINDINGS.md` could not express.

CREATE TABLE message (
    id                  INTEGER PRIMARY KEY,

    -- The spool file, by generated name. Never sender or recipient text:
    -- `pigeon-spool` refuses to build a path from either.
    spool_id            TEXT NOT NULL UNIQUE,

    -- The envelope sender as it will be transmitted: the SRS return path,
    -- computed once at acceptance and stored, so no retry recomputes it under a
    -- different key or a later timestamp. Empty for a bounce Pigeon sends.
    return_path         TEXT NOT NULL,

    -- What the sender used. For the log and the DSN; never used to address
    -- anything.
    original_sender     TEXT NOT NULL,

    size_bytes          INTEGER NOT NULL CHECK (size_bytes >= 0),
    received_at         INTEGER NOT NULL,

    -- Which routing state accepted this. Diagnostic only — a queued message is
    -- never re-resolved (R-1). The fingerprint is stored *with* the revision
    -- because a revision alone is ambiguous after a restore, which is the exact
    -- condition `M1-RELOAD.md` C-2 exists for: the same number over different
    -- rows.
    routing_revision    INTEGER NOT NULL,
    routing_fingerprint BLOB NOT NULL,

    -- Set once the body has actually been removed from disk. Not part of the
    -- terminal transition: SQLite cannot commit an unlink, so the two are
    -- separate steps and a sweep finishes the pairs a crash separated.
    body_deleted_at     INTEGER
) STRICT;

-- The recipients the sender named, before routing resolved anything.
--
-- RFC 3464 requires a DSN to associate a failure with the recipient the sender
-- *specified*, which after forwarding is not the destination that failed.
-- Without this a report would tell a sender that delivery failed to a mailbox
-- they have never heard of.
CREATE TABLE original_recipient (
    id         INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    address    TEXT NOT NULL,
    UNIQUE (message_id, address)
) STRICT;

CREATE TABLE delivery (
    id               INTEGER PRIMARY KEY,
    message_id       INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,

    -- One row per resolved destination: the unit of retry and of outcome.
    destination      TEXT NOT NULL,

    state            TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','delivering','deferred','delivered','failed','expired')),

    -- Whether a DSN is owed, and whether it exists yet. Separate from `state`
    -- because the two answer different questions: a state meaning both "the
    -- remote refused" and "the sender was told" makes a crash between them look
    -- like a report that was sent.
    notification     TEXT NOT NULL DEFAULT 'none'
        CHECK (notification IN ('none','owed','enqueued')),

    -- The DSN reporting this failure, once one exists. Durable grouping: a
    -- crash partway through notifying several failures cannot report one twice,
    -- because the ones already committed carry the id.
    notified_by      INTEGER REFERENCES message(id) ON DELETE SET NULL,

    attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),

    -- Meaningful only while there is a next attempt to schedule.
    next_attempt_at  INTEGER,

    claimed_by       TEXT,
    lease_expires_at INTEGER,
    last_code        INTEGER,
    last_response    TEXT,
    terminal_at      INTEGER,

    UNIQUE (message_id, destination),

    -- A claim is both columns or neither. Written separately from the
    -- equivalence below because the equivalence alone permits half a claim:
    -- `claimed_by` set with no expiry makes the right-hand side false, which
    -- matches a non-delivering row, so the pair passes while leaving an owner
    -- recorded for a row nobody owns.
    CHECK ((claimed_by IS NULL) = (lease_expires_at IS NULL)),

    -- A claim and the state that has one are the same fact. Allowing a deferred
    -- row to keep a claim would leave a row no expiry sweep reclaims and no
    -- worker touches.
    CHECK (
        (state = 'delivering')
        = (claimed_by IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CHECK ((state IN ('delivered','failed','expired')) = (terminal_at IS NOT NULL)),
    CHECK ((state IN ('queued','deferred')) = (next_attempt_at IS NOT NULL)),

    -- Nothing is owed for a success, and a report cannot exist without having
    -- been owed first.
    CHECK (notification = 'none' OR state IN ('failed','expired')),
    CHECK ((notification = 'enqueued') = (notified_by IS NOT NULL))
) STRICT;

-- Which of the sender's recipients led to which delivery.
--
-- Many-to-many because both directions happen: one alias fans out to several
-- destinations, and several aliases deduplicate onto one. A DSN needs both ends
-- — the address the sender wrote and the destination that refused it.
CREATE TABLE recipient_delivery (
    original_recipient_id INTEGER NOT NULL REFERENCES original_recipient(id) ON DELETE CASCADE,
    delivery_id           INTEGER NOT NULL REFERENCES delivery(id) ON DELETE CASCADE,
    PRIMARY KEY (original_recipient_id, delivery_id)
) STRICT;

-- Due work, and nothing else. Partial because the queue is mostly terminal rows
-- after a day, and scanning those to find the few that are due is the
-- difference between a query and a table scan.
CREATE INDEX delivery_due ON delivery(next_attempt_at)
    WHERE state IN ('queued','deferred');

-- Owed notifications, for the same reason.
CREATE INDEX delivery_owed ON delivery(message_id)
    WHERE notification = 'owed';

-- Leases that may have expired. A worker that died leaves rows here.
CREATE INDEX delivery_leases ON delivery(lease_expires_at)
    WHERE state = 'delivering';

-- Finding the deliveries for a message, which every terminal transition and
-- every DSN does.
CREATE INDEX delivery_by_message ON delivery(message_id);

CREATE TABLE delivery_event (
    id          INTEGER PRIMARY KEY,
    delivery_id INTEGER NOT NULL REFERENCES delivery(id) ON DELETE CASCADE,
    at          INTEGER NOT NULL,
    kind        TEXT NOT NULL
        CHECK (kind IN ('attempt','defer','deliver','fail','expire','notify','claim_expired')),
    code        INTEGER,
    response    TEXT,
    remote      TEXT
) STRICT;

CREATE INDEX delivery_event_by_delivery ON delivery_event(delivery_id, at);
