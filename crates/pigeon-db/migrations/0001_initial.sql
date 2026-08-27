-- Pigeon initial schema.
--
-- Design and reasoning: docs/M1-SCHEMA.md. Every constraint here exists
-- because of a case in §7 of that document, and several of them refuse things
-- that look harmless.
--
-- IMMUTABLE ONCE RELEASED (M1-SCHEMA.md I2). The runner checksums these exact
-- bytes and refuses to start if they change. Corrections go in a new migration.
--
-- Pragmas are not set here: they are per-connection or non-transactional, and
-- the runner owns them.
--
-- `schema_migration` is not here either. The runner has to read that table to
-- discover whether this migration has run, so it cannot be created by it.
-- It is the runner's own contract rather than part of the schema it manages.

CREATE TABLE setting (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE destination (
    id      INTEGER PRIMARY KEY,
    local   TEXT NOT NULL,                  -- case preserved: see C5
    domain  TEXT NOT NULL COLLATE NOCASE,
    UNIQUE (local, domain)
) STRICT;

CREATE TABLE relay (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL DEFAULT 587,
    username   TEXT,
    -- A *name*, not a path. Resolved against the configured `secrets` root
    -- and required to stay inside it — see §5. A path column would carry the
    -- traversal problem that motivated a root for `keys`, with nothing
    -- constraining it, so a hand-edited row could name any readable file.
    secret_ref TEXT,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE domain (
    id                      INTEGER PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE COLLATE NOCASE,

    -- DNS lifecycle only. `suspended` is deliberately absent: see below.
    status                  TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','pending_dns','ready','active','error')),

    inbound_enabled         INTEGER NOT NULL DEFAULT 1 CHECK (inbound_enabled IN (0,1)),
    outbound_enabled        INTEGER NOT NULL DEFAULT 0 CHECK (outbound_enabled IN (0,1)),

    delivery_mode           TEXT NOT NULL DEFAULT 'direct'
        CHECK (delivery_mode IN ('direct','relay')),
    relay_id                INTEGER REFERENCES relay(id) ON DELETE RESTRICT,

    default_destination_id  INTEGER REFERENCES destination(id) ON DELETE RESTRICT,

    catchall_enabled        INTEGER NOT NULL DEFAULT 0 CHECK (catchall_enabled IN (0,1)),
    catchall_destination_id INTEGER REFERENCES destination(id) ON DELETE RESTRICT,

    plus_addressing         INTEGER NOT NULL DEFAULT 1 CHECK (plus_addressing IN (0,1)),
    forward_policy          TEXT NOT NULL DEFAULT 'preserve'
        CHECK (forward_policy IN ('preserve','rewrite_from')),

    notify_destination_id   INTEGER REFERENCES destination(id) ON DELETE RESTRICT,

    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL,

    -- Catch-all is never enabled implicitly, and a destination for a disabled
    -- catch-all is a contradiction that would route mail after a later enable.
    CHECK (catchall_enabled = 1 OR catchall_destination_id IS NULL),

    -- An enabled catch-all must have somewhere to go: its own destination, or
    -- the domain default it inherits. Without this, clearing a default silently
    -- leaves a catch-all accepting every address on the domain and routing it
    -- nowhere. Row CHECKs are re-evaluated on UPDATE, so this blocks the
    -- clearing path and not merely the creating one.
    CHECK (catchall_enabled = 0
           OR catchall_destination_id IS NOT NULL
           OR default_destination_id IS NOT NULL),

    -- Equivalence, not implication. The one-way form permitted a domain in
    -- direct mode still carrying a relay_id, which reads as configured relay
    -- delivery to anything inspecting the row.
    CHECK ((delivery_mode = 'relay') = (relay_id IS NOT NULL))
) STRICT;

CREATE INDEX domain_by_relay        ON domain(relay_id);
CREATE INDEX domain_by_default_dest ON domain(default_destination_id);
CREATE INDEX domain_by_catchall_dest ON domain(catchall_destination_id);
CREATE INDEX domain_by_notify_dest  ON domain(notify_destination_id);

CREATE TABLE alias (
    id          INTEGER PRIMARY KEY,
    domain_id   INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,

    -- Lowercased on write (C5), and COLLATE NOCASE so the database enforces it
    -- rather than trusting every writer to have remembered. Without it, `Hello`
    -- and `hello` coexist as separate aliases on one domain and only one of
    -- them ever matches.
    pattern     TEXT NOT NULL COLLATE NOCASE,
    kind        TEXT NOT NULL DEFAULT 'forward' CHECK (kind IN ('forward','reject')),

    -- Generated, not stored by the application, so it cannot drift from the
    -- pattern it describes.
    is_wildcard INTEGER GENERATED ALWAYS AS (instr(pattern, '*') > 0) VIRTUAL,

    created_at  INTEGER NOT NULL,
    UNIQUE (domain_id, pattern)
) STRICT;

CREATE TABLE alias_destination (
    alias_id       INTEGER NOT NULL REFERENCES alias(id)       ON DELETE CASCADE,
    destination_id INTEGER NOT NULL REFERENCES destination(id) ON DELETE RESTRICT,
    PRIMARY KEY (alias_id, destination_id)
) STRICT;

-- The primary key indexes `alias_id` (leading), but not `destination_id`.
-- SQLite does not index foreign-key children automatically, so without this
-- every ON DELETE RESTRICT check and every `destination list` count scans the
-- whole table.
CREATE INDEX alias_destination_by_destination ON alias_destination(destination_id);

CREATE TABLE dkim_key (
    id               INTEGER PRIMARY KEY,
    domain_id        INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
    selector         TEXT NOT NULL,
    algorithm        TEXT NOT NULL DEFAULT 'rsa2048' CHECK (algorithm IN ('rsa2048','ed25519')),
    public_key       TEXT NOT NULL,   -- base64 SPKI, for rendering the TXT record
    private_key_path TEXT NOT NULL,   -- on disk, 0600; never in this database
    state            TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','retiring','retired')),
    created_at       INTEGER NOT NULL,
    retired_at       INTEGER,
    UNIQUE (domain_id, selector),

    -- A retired key with no retirement time, or a live key carrying one, is a
    -- row whose state cannot be trusted by rotation logic.
    CHECK ((state = 'retired') = (retired_at IS NOT NULL))
) STRICT;

-- "At most one active key per algorithm" was prose in the first draft, which
-- means it was not a rule. Two active RSA keys for one domain would make the
-- signer's choice arbitrary and the published TXT record wrong for half the
-- mail it signs.
CREATE UNIQUE INDEX dkim_key_one_active
    ON dkim_key(domain_id, algorithm) WHERE state = 'active';

CREATE TABLE sender_identity (
    id         INTEGER PRIMARY KEY,
    domain_id  INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
    local      TEXT NOT NULL COLLATE NOCASE,   -- authoritative: C5
    created_at INTEGER NOT NULL,
    UNIQUE (domain_id, local)
) STRICT;

CREATE TABLE principal (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL UNIQUE,     -- generated, e.g. pg_7N...
    password_hash TEXT NOT NULL,            -- Argon2id; never the password
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
) STRICT;

CREATE TABLE principal_grant (
    id           INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL REFERENCES principal(id) ON DELETE CASCADE,
    domain_id    INTEGER NOT NULL REFERENCES domain(id)    ON DELETE CASCADE,
    -- NULL means the whole domain: `pigeon auth allow name '*@example.com'`.
    local        TEXT COLLATE NOCASE,
    created_at   INTEGER NOT NULL,

    -- A grant naming a local part must name a real sender identity. Without
    -- this, a grant can authorise an identity that is not on the domain's
    -- allowlist at all — and removing the identity leaves the grant behind, so
    -- re-adding it later silently restores an authority nobody re-granted.
    --
    -- Composite and nullable: SQL skips a foreign key when any of its columns
    -- is NULL, so a domain-wide grant is exempt without needing a special case.
    FOREIGN KEY (domain_id, local)
        REFERENCES sender_identity(domain_id, local) ON DELETE CASCADE
) STRICT;

-- Neither foreign-key child column is indexed by the partial indexes below,
-- which lead with `principal_id`.
CREATE INDEX principal_grant_by_domain ON principal_grant(domain_id, local);

-- Two partial indexes, not one UNIQUE constraint. See below — this is the one
-- place in this schema where the obvious spelling is silently wrong.
CREATE UNIQUE INDEX principal_grant_identity
    ON principal_grant(principal_id, domain_id, local) WHERE local IS NOT NULL;

CREATE UNIQUE INDEX principal_grant_domain_wide
    ON principal_grant(principal_id, domain_id) WHERE local IS NULL;
