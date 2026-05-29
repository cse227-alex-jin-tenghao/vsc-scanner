-- vsc-scanner: Supabase schema for the marketplace-wide scan.
-- Run once against an empty database. Idempotent via IF NOT EXISTS.

CREATE TYPE claim_status AS ENUM ('unclaimed', 'claimed', 'completed');

-- One row per marketplace extension. `idx` is the 0-based offset into
-- marketplace_extensions_full.json — preserved so the node can look up
-- metadata (URLs, last_updated, etc.) without us storing it twice.
CREATE TABLE IF NOT EXISTS main (
    idx              integer PRIMARY KEY,
    extension_id     text    NOT NULL UNIQUE,
    preprocessing    jsonb,
    dep_visibility   jsonb,
    semgrep_output   jsonb,
    retire_output    jsonb,
    osv_output       jsonb,
    gitleaks_output  jsonb,
    errors           jsonb,
    scanner_version  text,
    completed_at     timestamptz
);

-- Fast "has this row been scanned yet?" check used by claim() to skip
-- already-populated rows after a partial-group failure.
CREATE INDEX IF NOT EXISTS main_completed_at_idx ON main (completed_at)
    WHERE completed_at IS NOT NULL;

-- 1241 groups of 100 extensions each (124,100 / 100 — no partial group).
-- group_idx N covers main rows where idx / 100 = N.
CREATE TABLE IF NOT EXISTS manager (
    group_idx    integer PRIMARY KEY,
    status       claim_status NOT NULL DEFAULT 'unclaimed',
    claimed_at   timestamptz,
    claimed_by   text,
    attempts     integer NOT NULL DEFAULT 0,
    completed_at timestamptz
);

-- Lets claim() find a candidate group cheaply without scanning the whole table.
CREATE INDEX IF NOT EXISTS manager_claimable_idx
    ON manager (group_idx)
    WHERE status <> 'completed';
