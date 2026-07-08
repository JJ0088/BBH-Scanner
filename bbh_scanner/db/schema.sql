-- Schema BBH-Scanner v2 — SQLite. Multi-piattaforma: quasi tutto è namespaced
-- per (platform, program_handle). Migrazioni gestite via PRAGMA user_version.

CREATE TABLE IF NOT EXISTS programs (
    platform          TEXT NOT NULL,
    handle            TEXT NOT NULL,
    name              TEXT,
    url               TEXT,
    offers_bounties   INTEGER,          -- 0/1
    submission_state  TEXT,             -- open|closed|...
    state             TEXT,
    open_scope        INTEGER,          -- 0/1
    last_fetch_at     TEXT,
    scope_count       INTEGER DEFAULT 0,
    scope_hash        TEXT,
    enabled           INTEGER DEFAULT 1, -- lo monitoriamo?
    PRIMARY KEY (platform, handle)
);

CREATE TABLE IF NOT EXISTS scopes (
    id                    TEXT PRIMARY KEY,          -- "<platform>:<handle>:<asset>"
    platform              TEXT NOT NULL,
    program_handle        TEXT NOT NULL,
    asset_identifier      TEXT NOT NULL,
    asset_type            TEXT,
    eligible_for_bounty   INTEGER,
    eligible_for_submission INTEGER,
    max_severity          TEXT,
    instruction           TEXT,
    created_at            TEXT,
    updated_at            TEXT,
    normalized_type       TEXT,          -- url|api|domain|wildcard
    normalized_value      TEXT,
    first_seen_at         TEXT,
    last_seen_at          TEXT,
    UNIQUE (platform, program_handle, asset_identifier)
);

CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(platform, program_handle);
CREATE INDEX IF NOT EXISTS idx_scopes_type ON scopes(normalized_type);
CREATE INDEX IF NOT EXISTS idx_scopes_updated ON scopes(updated_at);

-- Asset SCOPERTI dal recon (sottodomini, host vivi), distinti dagli scope dichiarati.
CREATE TABLE IF NOT EXISTS assets (
    id                TEXT PRIMARY KEY,   -- "<platform>:<handle>:<kind>:<value>"
    platform          TEXT NOT NULL,
    program_handle    TEXT NOT NULL,
    scope_id          TEXT,               -- scope d'origine (se noto)
    kind              TEXT NOT NULL,      -- subdomain|host|url
    value             TEXT NOT NULL,
    source            TEXT,               -- subfinder|httpx|dnsx|seed
    alive             INTEGER,            -- 0/1/NULL
    meta              TEXT,               -- json
    first_seen_at     TEXT,
    last_seen_at      TEXT,
    UNIQUE (platform, program_handle, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(platform, program_handle);

-- Coda di lavoro con macchina a stati: rende il 24/7 ripartibile.
CREATE TABLE IF NOT EXISTS jobs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    kind              TEXT NOT NULL,      -- sync|recon_passive
    platform          TEXT,
    program_handle    TEXT,
    target            TEXT,               -- scope_id/handle a seconda del kind
    state             TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed
    priority          INTEGER DEFAULT 0,  -- più alto = prima
    attempts          INTEGER DEFAULT 0,
    next_due_at       TEXT,
    sig               TEXT,               -- hash input: skip se invariato
    error             TEXT,
    created_at        TEXT,
    started_at        TEXT,
    finished_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state, priority DESC, next_due_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_dedup
    ON jobs(kind, platform, program_handle, target)
    WHERE state IN ('queued', 'running');

-- Delta di recon (estendibile ai findings nuclei in futuro).
CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    platform          TEXT,
    program_handle    TEXT,
    kind              TEXT NOT NULL,      -- new_subdomain|new_host|host_down|new_tech
    fingerprint       TEXT NOT NULL UNIQUE, -- dedup
    severity          TEXT DEFAULT 'info',
    title             TEXT,
    data              TEXT,               -- json
    status            TEXT DEFAULT 'new', -- new|known|resolved
    first_seen_at     TEXT,
    last_seen_at      TEXT,
    notified_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(platform, program_handle);

-- Audit / osservabilità interrogabile.
CREATE TABLE IF NOT EXISTS events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                TEXT NOT NULL,
    level             TEXT NOT NULL,      -- INFO|WARN|ERROR
    component         TEXT,
    job_id            INTEGER,
    program_handle    TEXT,
    message           TEXT,
    data              TEXT                -- json
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

-- Cursori incrementali per i collector.
CREATE TABLE IF NOT EXISTS sync_state (
    key               TEXT PRIMARY KEY,
    value             TEXT,
    updated_at        TEXT
);
