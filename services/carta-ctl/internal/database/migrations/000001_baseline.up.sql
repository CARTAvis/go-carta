-- Baseline schema as created by EnsureTables on the main branch.
--
-- All statements are idempotent so this migration can also be applied to an
-- existing database that was created before migrations were introduced.
--
-- The matching down migration is intentionally a no-op: this schema predates
-- the migration system, so rolling it back would destroy user data.

CREATE TABLE IF NOT EXISTS preferences (
    username TEXT PRIMARY KEY,
    content  JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS layouts (
    name     TEXT NOT NULL,
    username TEXT NOT NULL,
    content  JSONB NOT NULL,
    PRIMARY KEY (name, username)
);

CREATE TABLE IF NOT EXISTS snippets (
    name     TEXT NOT NULL,
    username TEXT NOT NULL,
    content  JSONB NOT NULL,
    PRIMARY KEY (name, username)
);

CREATE TABLE IF NOT EXISTS workspaces (
    name     TEXT NOT NULL,
    username TEXT NOT NULL,
    id       UUID NOT NULL DEFAULT gen_random_uuid(),
    content  JSONB NOT NULL,

    -- Whether the workspace is shared with other users
    shared   BOOLEAN,

    -- Keep top-level 'id' out of the JSON content to avoid confusion
    CONSTRAINT no_top_level_id CHECK (NOT (content ? 'id')),

    -- But ensure it remains unique (if defined)
    CONSTRAINT unique_workspace_id UNIQUE (id),

    PRIMARY KEY (username, name)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_username
ON workspaces (username);
