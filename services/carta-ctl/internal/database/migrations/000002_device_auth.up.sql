-- Device authentication tables. This is the schema currently created by
-- EnsureTables on the device-auth branch.
--
-- The CREATE TABLE statements use IF NOT EXISTS so this migration can also run
-- against databases that were already created by an earlier revision of this
-- branch before migrations were introduced.

-- key_fingerprint is the base64url SHA-256 of the client's raw Ed25519 public key.
-- It identifies the login attempt; possession of the private key authenticates the client.
CREATE TABLE IF NOT EXISTS auth_pending (
    key_fingerprint    TEXT        PRIMARY KEY,
    client_public_key  TEXT        NOT NULL,
    request_ip         TEXT        NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,

    -- Server time (Unix seconds) of the last accepted poll (enforces the
    -- polling interval against the server clock and bounds replay)
    last_poll_ts       BIGINT,

    -- Set once the user has authenticated and linked the key to their account
    username           TEXT,
    linked_at          TIMESTAMPTZ,

    -- Authentication source used for the link ("pam", "oidc")
    source             TEXT,

    -- OIDC offline token (AES-GCM encrypted) and the expiry of the upstream
    -- access token issued with it; NULL for non-OIDC logins
    oidc_refresh_token BYTEA,
    oidc_access_expiry TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    key_fingerprint    TEXT        PRIMARY KEY,
    client_public_key  TEXT        NOT NULL,
    username           TEXT        NOT NULL,

    -- Authentication source that created the session ("pam", later "oidc")
    source             TEXT        NOT NULL DEFAULT 'pam',

    oidc_refresh_token BYTEA,                 -- AES-GCM encrypted; NULL for non-OIDC sessions
    oidc_access_expiry TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL,
    last_used_at       TIMESTAMPTZ,

    -- Client timestamp of the last accepted signed request (prevents replay)
    last_request_ts    BIGINT,
    revoked            BOOLEAN     NOT NULL DEFAULT FALSE
);

-- CREATE TABLE IF NOT EXISTS does not modify an existing table, so also bring
-- tables created by earlier revisions of this branch up to date. The defaults
-- on NOT NULL columns make the statements work on tables that contain rows.

-- Earlier revisions keyed pending logins by a poll handle and device code.
-- Rename the key so the rows can still be addressed, then drop the unused
-- NOT NULL device code so new inserts do not have to supply it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'auth_pending' AND column_name = 'poll_handle'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'auth_pending' AND column_name = 'key_fingerprint'
    ) THEN
        ALTER TABLE auth_pending RENAME COLUMN poll_handle TO key_fingerprint;
    END IF;
END $$;

ALTER TABLE auth_pending DROP COLUMN IF EXISTS device_code;

ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS client_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS request_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS last_poll_ts BIGINT;
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS linked_at TIMESTAMPTZ;
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS oidc_refresh_token BYTEA;
ALTER TABLE auth_pending ADD COLUMN IF NOT EXISTS oidc_access_expiry TIMESTAMPTZ;

-- Earlier sessions were keyed by an opaque session token; later revisions key
-- them by the client key fingerprint.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'auth_sessions' AND column_name = 'session_token'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'auth_sessions' AND column_name = 'key_fingerprint'
    ) THEN
        ALTER TABLE auth_sessions RENAME COLUMN session_token TO key_fingerprint;
    END IF;
END $$;

ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS client_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'pam';
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS oidc_refresh_token BYTEA;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS oidc_access_expiry TIMESTAMPTZ;
ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS last_request_ts BIGINT;

-- Older definitions required an OIDC token, but PAM sessions store NULL.
ALTER TABLE auth_sessions ALTER COLUMN oidc_refresh_token DROP NOT NULL;

-- Support per-IP rate limiting of pending device logins and the purge of
-- expired rows.
CREATE INDEX IF NOT EXISTS idx_auth_pending_request_ip
ON auth_pending (request_ip);

CREATE INDEX IF NOT EXISTS idx_auth_pending_expires_at
ON auth_pending (expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_username
ON auth_sessions (username);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at
ON auth_sessions (expires_at) WHERE NOT revoked;
