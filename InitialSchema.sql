-- Migration 001: initial schema. Requires SQLite 3.38 or newer (STRICT, json_type).
-- Times are TEXT in UTC, format YYYY-MM-DDTHH:MM:SSZ. Booleans are INTEGER 0 or 1.
--
-- ===========================================================================
-- How to read this file (SQLite notes)
-- ===========================================================================
--
-- SQLite is a database stored in a single file (here /data/asma.db). There is
-- no database server: the application opens the file with Python's sqlite3
-- module. Some SQLite behaviour differs from other databases and is used below:
--
-- STRICT
--   By default SQLite lets any value go into any column (a text into an
--   INTEGER column, for example). "STRICT" at the end of a table switches that
--   off, so every column only accepts its declared type: INTEGER, TEXT, etc.
--
-- INTEGER PRIMARY KEY
--   A column declared exactly like this becomes the row's internal id. When a
--   row is inserted without a value for it, SQLite assigns the next free number.
--
-- No date, boolean or JSON types
--   SQLite has no dedicated types for these, so this schema uses conventions:
--   * times are TEXT like 2026-10-21T13:39:06Z (UTC). In this fixed format,
--     sorting the text also sorts by time, so comparisons and ORDER BY work;
--   * booleans are INTEGER 0 (false) or 1 (true), enforced with CHECK;
--   * JSON is TEXT, checked with json_valid() (is it valid JSON?) and
--     json_type(...) = 'object' (is it a {...} object rather than a list or number?).
--
-- NULL and NOT NULL
--   NULL means "no value". Columns without NOT NULL may be left empty.
--   Comparisons with NULL are never true with = or <>, so triggers below use
--   "IS" and "IS NOT", which treat two NULLs as equal and NULL as different
--   from any value.
--
-- CHECK (...)
--   A condition that every row must satisfy. An INSERT or UPDATE that breaks
--   it fails with an error and changes nothing. A CHECK placed after the
--   columns can compare several columns of the same row.
--
-- UNIQUE
--   No two rows may have the same value (or combination of values). SQLite
--   creates an index for every UNIQUE constraint automatically.
--
-- REFERENCES (foreign keys)
--   "col REFERENCES other (id)" means col must contain an id that exists in
--   table other (or be NULL).
--
-- COLLATE NOCASE
--   Text comparisons on that column ignore upper/lower case (ASCII letters),
--   so "Anna" and "anna" count as the same username for UNIQUE.
--
-- GLOB
--   Pattern matching with shell-style wildcards: * is any text, [^a-z0-9]
--   is one character that is NOT a lowercase letter or digit. GLOB is case
--   sensitive.
--
-- CREATE INDEX
--   An index makes lookups by its columns fast, like a book index. Without
--   one, SQLite reads the whole table. "Partial" indexes (with WHERE) only
--   contain some rows; SQLite uses them only when a query's WHERE clause
--   clearly implies the index's WHERE clause.
--
-- CREATE TRIGGER ... BEFORE INSERT / UPDATE
--   Code that SQLite runs automatically before a row is inserted or updated.
--   NEW is the row as it would be written, OLD the row as it was (UPDATE
--   only). The WHEN clause decides whether the trigger body runs, and
--   RAISE(ABORT, 'message') cancels the statement with that error message.
--   Triggers are used here for rules a CHECK cannot express, such as rules
--   that look at another table or forbid changing a column.
--
-- WITHOUT ROWID
--   Stores a table directly by its primary key instead of an internal row
--   id. Saves space for small link tables whose primary key is the whole row.
--
-- PRAGMA user_version
--   A number stored in the database file that the application uses as the
--   schema version. Migration N sets it to N; at start-up, migrations newer
--   than the stored number are applied in order.
--

-- Only affects the connection running this file, and inside a transaction
-- SQLite ignores it. Kept so the file also enforces foreign keys when run by
-- hand in the sqlite3 shell; the application sets it on every connection.
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Accounts
-- ---------------------------------------------------------------------------

-- People who sign in to the web interface. Two roles: viewers only look at
-- results, operators can do everything, including creating other accounts.
-- Users are never deleted, only deactivated, because other tables reference them.
-- (The foreign keys pointing here have no ON DELETE clause, so a DELETE fails.)
CREATE TABLE users (
    user_id               INTEGER PRIMARY KEY,
    -- Login name; unique regardless of letter case.
    username              TEXT    NOT NULL COLLATE NOCASE UNIQUE
                                  CHECK (length(username) BETWEEN 3 AND 50),
    role                  TEXT    NOT NULL CHECK (role IN ('viewer', 'operator')),
    -- Salted scrypt hash produced by Werkzeug; the password itself is never stored.
    password_hash         TEXT    NOT NULL,
    -- 1 forces a password change at the next sign-in (accounts start with a temporary password).
    must_change_password  INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    -- 0 blocks sign-in and all API keys of the account.
    is_active             INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    -- Sessions issued before this time are rejected.
    password_changed_at   TEXT    NOT NULL,
    last_login_at         TEXT,
    -- Operator who created the account.
    -- NULL only for the first operator, created from the CLI.
    created_by_user_id    INTEGER REFERENCES users (user_id),
    created_at            TEXT    NOT NULL
) STRICT;

-- Credentials for programs (for example n8n) calling the REST API.
-- Keys are credentials of a user and act with the owner's current role.
-- Keys are never deleted, only revoked.
--
-- A key looks like asm_<prefix>_<secret>, e.g. asm_n8n_Vq3l0Zx8...
-- The owner chooses the prefix to tell their keys apart; the system adds the
-- random secret. The key is shown to the user once, at creation. The database
-- stores only the prefix and a hash of the whole key, so a stolen database
-- file does not reveal usable keys.
CREATE TABLE api_keys (
    api_key_id    INTEGER PRIMARY KEY,
    -- Owner. A key cannot exist without the account it belongs to.
    user_id       INTEGER NOT NULL REFERENCES users (user_id),
    -- What the key is for, e.g. "n8n weekly report workflow". Optional;
    -- the prefix below is what tells keys apart.
    description   TEXT    CHECK (description IS NULL OR length(description) BETWEEN 1 AND 200),
    -- 1 limits the key to viewer permissions even when the owner is an operator.
    read_only     INTEGER NOT NULL DEFAULT 0 CHECK (read_only IN (0, 1)),
    -- Public part of the key, chosen by the owner, e.g. "n8n". Not secret.
    -- Shown in the UI and audit log so people can tell keys apart without
    -- seeing secrets. 3 to 32 lowercase letters, digits or hyphens; the GLOB
    -- rejects any other character, in particular "_", which separates the
    -- parts of the key. Unique among the owner's active keys (index below).
    key_prefix    TEXT    NOT NULL CHECK (length(key_prefix) BETWEEN 3 AND 32
                                          AND key_prefix NOT GLOB '*[^a-z0-9-]*'),
    -- SHA-256 of the full key string, as 64 hex characters. A request is
    -- accepted when the hash of the presented key matches this value; the
    -- UNIQUE index on this column is also how the key's row is found.
    key_hash      TEXT    NOT NULL UNIQUE CHECK (length(key_hash) = 64),
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT,
    -- Set when the key is revoked; from then on the key is rejected.
    revoked_at    TEXT
) STRICT;

-- An owner's active keys have distinct prefixes. A revoked key keeps its
-- prefix but no longer blocks it, so "n8n" can be reused after a rotation.
CREATE UNIQUE INDEX ux_api_keys_active_prefix ON api_keys (user_id, key_prefix)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Targets
-- ---------------------------------------------------------------------------

-- What is monitored, set by operators:
-- * domain:  a registered domain, e.g. example.com (squatting and subdomain scans);
-- * keyword: a brand word, e.g. example (feeds the squatting scans of domains);
-- * network: an IPv4 CIDR block or range, e.g. 203.0.113.0/24 (Shodan and nmap).
CREATE TABLE targets (
    target_id           INTEGER PRIMARY KEY,
    kind                TEXT    NOT NULL CHECK (kind IN ('domain', 'keyword', 'network')),
    -- Normalised value. Must be lowercase, so "Example.com" cannot be added
    -- next to "example.com" (UNIQUE below compares case-sensitively).
    -- Network values contain no letters, so the rule holds for them as well.
    value               TEXT    NOT NULL CHECK (length(value) BETWEEN 2 AND 253
                                                AND value = lower(value)),
    -- Display name shown in the UI.
    label               TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    notes               TEXT    CHECK (notes IS NULL OR length(notes) <= 2000),
    -- 0 stops all scans of the target while keeping its history.
    enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    -- Operator who created the target.
    created_by_user_id  INTEGER NOT NULL REFERENCES users (user_id),
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    UNIQUE (kind, value)
) STRICT;

-- Kind, value and creator identify the target in all its history and must not change.
-- (Changing example.com into example.org would attach old results to the wrong domain.)
CREATE TRIGGER trg_targets_immutable
BEFORE UPDATE OF kind, value, created_by_user_id ON targets
WHEN NEW.kind IS NOT OLD.kind OR NEW.value IS NOT OLD.value
  OR NEW.created_by_user_id IS NOT OLD.created_by_user_id
BEGIN
    SELECT RAISE(ABORT, 'target kind, value and creator are immutable');
END;

-- Keywords feeding the squatting report of a domain (many-to-many).
-- One row links one domain target to one keyword target. A keyword such as
-- "example" can feed several domains, and a domain can have several keywords.
-- Deleting either target deletes the link (ON DELETE CASCADE).
CREATE TABLE domain_keywords (
    domain_target_id    INTEGER NOT NULL REFERENCES targets (target_id) ON DELETE CASCADE,
    keyword_target_id   INTEGER NOT NULL REFERENCES targets (target_id) ON DELETE CASCADE,
    -- Operator who created the link.
    created_by_user_id  INTEGER NOT NULL REFERENCES users (user_id),
    created_at          TEXT    NOT NULL,
    -- The pair is the identity of the link, so the same link cannot exist twice.
    PRIMARY KEY (domain_target_id, keyword_target_id)
) STRICT, WITHOUT ROWID;

-- The primary key already serves lookups by domain; this serves lookups by keyword.
CREATE INDEX ix_domain_keywords_keyword ON domain_keywords (keyword_target_id);

-- A link must connect a domain target to a keyword target.
-- (A foreign key can only check that the target exists, not its kind.)
CREATE TRIGGER trg_domain_keywords_kinds
BEFORE INSERT ON domain_keywords
WHEN (SELECT kind FROM targets WHERE target_id = NEW.domain_target_id) IS NOT 'domain'
  OR (SELECT kind FROM targets WHERE target_id = NEW.keyword_target_id) IS NOT 'keyword'
BEGIN
    SELECT RAISE(ABORT, 'domain_keywords requires a domain and a keyword target');
END;

-- ---------------------------------------------------------------------------
-- Schedules and jobs
-- ---------------------------------------------------------------------------
--
-- params (in both tables) are the scanner options as a JSON object, e.g.
-- {"ports": "top100"} for nmap. The application always stores them in one
-- canonical form: defaults filled in, keys sorted, no spaces. That way equal
-- options always produce equal text, which the UNIQUE index on schedules and
-- the fingerprint on jobs rely on.

-- Recurring scans: run one scanner on one target on a cron timetable.
-- Schedules are soft-deleted (deleted_at) so that the jobs they started keep their origin.
-- "Deleting" a schedule in the UI sets deleted_at and hides it; the row stays.
CREATE TABLE schedules (
    schedule_id         INTEGER PRIMARY KEY,
    target_id           INTEGER NOT NULL REFERENCES targets (target_id) ON DELETE CASCADE,
    scanner             TEXT    NOT NULL CHECK (scanner IN ('opensquat', 'hibs', 'dnstwist', 'subfinder',
                                                            'puredns', 'shodan', 'nmap')),
    -- Standard 5-field cron expression, e.g. "0 3 * * 1" (Mondays at 03:00).
    cron                TEXT    NOT NULL CHECK (length(cron) BETWEEN 9 AND 100),
    params              TEXT    NOT NULL DEFAULT '{}'
                                CHECK (json_valid(params) AND json_type(params) = 'object'),
    -- 0 pauses the schedule.
    enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    -- Operator who created the schedule. Jobs it starts are attributed to this user.
    created_by_user_id  INTEGER NOT NULL REFERENCES users (user_id),
    last_run_at         TEXT,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    -- Set instead of deleting the row; NULL means the schedule is live.
    deleted_at          TEXT,
    -- A deleted schedule can never be enabled.
    CHECK (deleted_at IS NULL OR enabled = 0)
) STRICT;

CREATE INDEX ix_schedules_target ON schedules (target_id);
-- No two live schedules may be identical.
-- A deleted schedule does not block re-creating the same schedule.
CREATE UNIQUE INDEX ux_schedules_live ON schedules (target_id, scanner, cron, params)
    WHERE deleted_at IS NULL;

-- One scan run. A series is (target_id, scanner, params_fingerprint); the baseline of a job
-- is the previous completed job of its series and is derived by query, not stored.
--
-- "What changed since last time" compares a job's findings with that baseline.
-- Only jobs of the same series are compared, so e.g. a top-100 port scan is
-- never compared with a full port scan of the same network.
--
-- Status flow: a job starts as queued, becomes running, and ends as
-- completed, failed or cancelled (a queued job can also be cancelled).
-- Jobs still running when the application stops are marked interrupted at the
-- next start. completed, failed, cancelled and interrupted are final states.
CREATE TABLE jobs (
    job_id                   INTEGER PRIMARY KEY,
    target_id                INTEGER NOT NULL REFERENCES targets (target_id) ON DELETE CASCADE,
    -- Origin: started by a schedule or directly by a user, never both.
    -- NO ACTION (default) blocks direct schedule deletes but lets a target delete cascade.
    schedule_id              INTEGER REFERENCES schedules (schedule_id),
    -- User who started the job (web or API); NULL for scheduled jobs.
    created_by_user_id       INTEGER REFERENCES users (user_id),
    scanner                  TEXT    NOT NULL CHECK (scanner IN ('opensquat', 'hibs', 'dnstwist',
                                                 'subfinder', 'puredns', 'shodan', 'nmap')),
    params                   TEXT    NOT NULL DEFAULT '{}'
                                     CHECK (json_valid(params) AND json_type(params) = 'object'),
    -- SHA-256 (64 hex characters) of the canonical params text. Equal options
    -- give an equal fingerprint, which defines the series of the job.
    params_fingerprint       TEXT    NOT NULL CHECK (length(params_fingerprint) = 64),
    status                   TEXT    NOT NULL DEFAULT 'queued'
                                     CHECK (status IN ('queued', 'running', 'completed',
                                                       'failed', 'cancelled', 'interrupted')),
    queued_at                TEXT    NOT NULL,
    started_at               TEXT,
    finished_at              TEXT,
    -- Reason for failure, shown to the user; no stack traces.
    error                    TEXT    CHECK (error IS NULL OR length(error) <= 2000),
    -- Number of findings this job produced.
    finding_count            INTEGER CHECK (finding_count IS NULL OR finding_count >= 0),
    -- Diff summary against the previous completed job of the same series, computed once at completion.
    -- added: found now but not before; removed: found before but not now;
    -- changed: found both times but with different details.
    added_count              INTEGER CHECK (added_count IS NULL OR added_count >= 0),
    removed_count            INTEGER CHECK (removed_count IS NULL OR removed_count >= 0),
    changed_count            INTEGER CHECK (changed_count IS NULL OR changed_count >= 0),
    -- Exactly one origin: "(a IS NULL) <> (b IS NULL)" is true when exactly one of them is set.
    CHECK ((schedule_id IS NULL) <> (created_by_user_id IS NULL)),
    -- finished_at is set exactly when the job is in a final state
    CHECK ((status IN ('completed', 'failed', 'cancelled', 'interrupted')) = (finished_at IS NOT NULL))
) STRICT;

-- At most one queued or running job per series.
-- (Prevents starting the same scan twice at once, and keeps the jobs of a
-- series strictly one after another, which the baseline rule relies on.)
CREATE UNIQUE INDEX ux_jobs_active ON jobs (target_id, scanner, params_fingerprint)
    WHERE status IN ('queued', 'running');
-- Baseline and latest-job lookup.
CREATE INDEX ix_jobs_baseline ON jobs (target_id, scanner, params_fingerprint, finished_at)
    WHERE status = 'completed';
-- Jobs of a target: target page listing and the ON DELETE CASCADE from targets.
-- ux_jobs_active and ix_jobs_baseline start with target_id but are partial, so neither serves this.
CREATE INDEX ix_jobs_target ON jobs (target_id, queued_at);
-- Job queue (next queued job) and the list of running jobs.
CREATE INDEX ix_jobs_status ON jobs (status, queued_at);
-- "Recent changes" overview, newest finished jobs first.
CREATE INDEX ix_jobs_finished ON jobs (finished_at);
-- Jobs started by a schedule.
CREATE INDEX ix_jobs_schedule ON jobs (schedule_id);

-- A scheduled job runs the schedule's scanner on the schedule's target while it isn't deleted.
CREATE TRIGGER trg_jobs_schedule_match
BEFORE INSERT ON jobs
WHEN NEW.schedule_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM schedules AS s
                 WHERE s.schedule_id = NEW.schedule_id
                   AND s.target_id = NEW.target_id
                   AND s.scanner = NEW.scanner
                   AND s.deleted_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'scheduled job must match a live schedule''s target and scanner');
END;

-- What a job runs and who started it are fixed at creation.
-- (The series, the baseline and trg_jobs_schedule_match all assume these
-- columns never change after the insert.)
CREATE TRIGGER trg_jobs_identity_immutable
BEFORE UPDATE OF target_id, schedule_id, created_by_user_id, scanner, params, params_fingerprint ON jobs
WHEN NEW.target_id IS NOT OLD.target_id
  OR NEW.schedule_id IS NOT OLD.schedule_id
  OR NEW.created_by_user_id IS NOT OLD.created_by_user_id
  OR NEW.scanner IS NOT OLD.scanner
  OR NEW.params IS NOT OLD.params
  OR NEW.params_fingerprint IS NOT OLD.params_fingerprint
BEGIN
    SELECT RAISE(ABORT, 'job identity is immutable');
END;

-- A final job's status and finish time are fixed, so derived baselines never shift.
CREATE TRIGGER trg_jobs_final_immutable
BEFORE UPDATE OF status, finished_at ON jobs
WHEN OLD.finished_at IS NOT NULL
 AND (NEW.status IS NOT OLD.status OR NEW.finished_at IS NOT OLD.finished_at)
BEGIN
    SELECT RAISE(ABORT, 'final job state is immutable');
END;

-- ---------------------------------------------------------------------------
-- Results
-- ---------------------------------------------------------------------------

-- One result per row; finding_key is the identity used for diffs.
-- A job produces zero or more findings. Finding the same thing again in a
-- later job creates a new row under that job; the diff matches the two rows
-- by finding_key.
--
-- finding_key per scanner (always normalised by the scanner adapter):
--   opensquat, hibs, dnstwist   lookalike domain       examp1e-login.com
--   subfinder, puredns          subdomain              vpn.example.com
--   shodan                      IPv4 address           203.0.113.10
--   nmap                        IPv4 address:TCP port  203.0.113.10:443
CREATE TABLE findings (
    finding_id   INTEGER PRIMARY KEY,
    job_id       INTEGER NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    -- Tool that produced the finding (always equal to the job's scanner).
    scanner      TEXT    NOT NULL CHECK (scanner IN ('opensquat', 'hibs', 'dnstwist', 'subfinder',
                                                     'puredns', 'shodan', 'nmap')),
    -- Lowercase so that one domain is never stored under two spellings,
    -- which would show up as "removed" and "added" at the same time.
    -- 300 characters fits the longest case: a 253-character name plus ":65535".
    finding_key  TEXT    NOT NULL CHECK (length(finding_key) BETWEEN 1 AND 300
                                         AND finding_key = lower(finding_key)),
    -- Everything known about the finding. Compared in full by the diff, so any change is reported.
    -- e.g. nmap: {"state": "open", "service": "unknown", "fingerprint": "SF-Port8443-TCP:..."}.
    -- Values that change on every run regardless of the service (scan time,
    -- latency) are left out by the adapter. The adapter also truncates long
    -- fields and sets "truncated": true, so the 16 KB cap never aborts a job.
    details      TEXT    NOT NULL DEFAULT '{}'
                         CHECK (json_valid(details) AND json_type(details) = 'object'
                                AND length(details) <= 16384),
    -- Each thing appears at most once per job. This also indexes findings by job.
    UNIQUE (job_id, finding_key)
) STRICT;

-- History of one key across jobs, e.g. every scan that found 203.0.113.10:443.
CREATE INDEX ix_findings_scanner_key ON findings (scanner, finding_key);

-- The tool recorded on a finding must be the tool of its job.
CREATE TRIGGER trg_findings_scanner
BEFORE INSERT ON findings
WHEN NEW.scanner IS NOT (SELECT scanner FROM jobs WHERE job_id = NEW.job_id)
BEGIN
    SELECT RAISE(ABORT, 'finding scanner must match its job''s scanner');
END;

-- Raw output files of a job; deleted by retention after 90 days.
-- The files themselves live on disk under the data directory; this table
-- records where they are and their checksum. Deleting rows (also through
-- ON DELETE CASCADE) does not delete files: the application removes a job's
-- files after deleting its rows, and daily maintenance removes leftovers.
CREATE TABLE artifacts (
    artifact_id  INTEGER PRIMARY KEY,
    job_id       INTEGER NOT NULL REFERENCES jobs (job_id) ON DELETE CASCADE,
    -- File name, e.g. nmap.xml.gz, job.log; unique within a job.
    name         TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    -- Path relative to the data directory, generated by the system.
    rel_path     TEXT    NOT NULL UNIQUE,
    -- Content type sent with downloads, e.g. application/gzip.
    media_type   TEXT    NOT NULL,
    size_bytes   INTEGER NOT NULL CHECK (size_bytes >= 0),
    -- SHA-256 of the file (64 hex characters), to detect corruption or tampering.
    sha256       TEXT    NOT NULL CHECK (length(sha256) = 64),
    created_at   TEXT    NOT NULL,
    UNIQUE (job_id, name)
) STRICT;

-- Retention: find artifacts older than 90 days.
CREATE INDEX ix_artifacts_created ON artifacts (created_at);

-- ---------------------------------------------------------------------------
-- Audit
-- ---------------------------------------------------------------------------

-- Security log; deleted by retention after 365 days.
-- One row per security-relevant action: sign-ins (including failed ones),
-- changes to accounts, keys, targets, schedules and jobs, refused actions,
-- artifact downloads, start-up and daily maintenance. Ordinary page views are
-- not logged. Each event is also written to standard output so it can be
-- collected outside the host.
CREATE TABLE audit_events (
    event_id     INTEGER PRIMARY KEY,
    occurred_at  TEXT    NOT NULL,
    -- Who acted: a signed-in user, a user's API key, an unauthenticated client, or the system.
    actor_type   TEXT    NOT NULL CHECK (actor_type IN ('user', 'api_key', 'anonymous', 'system')),
    -- Acting user; for api_key events the key's owner.
    user_id      INTEGER REFERENCES users (user_id),
    -- Key used; set only for api_key events.
    api_key_id   INTEGER REFERENCES api_keys (api_key_id),
    -- Client address; NULL only for system events (scheduler, maintenance, CLI).
    -- 45 characters fits the longest IPv6 text form.
    source_ip    TEXT    CHECK (source_ip IS NULL OR length(source_ip) <= 45),
    -- Dotted function name, e.g. auth.login, target.delete.
    action       TEXT    NOT NULL CHECK (length(action) BETWEEN 3 AND 64),
    -- success: done; denied: signed in but the role does not allow it;
    -- failed: e.g. wrong password or rejected API key.
    outcome      TEXT    NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
    -- Affected object ids and readable values, changes, failure reasons. Never secrets.
    -- e.g. {"target_id": 12, "value": "example.com"} or {"changes": {"role": ["viewer", "operator"]}}.
    -- Capped at 8 KB because unauthenticated clients can cause rows to be
    -- written (failed sign-ins record the typed username).
    details      TEXT    NOT NULL DEFAULT '{}'
                         CHECK (json_valid(details) AND json_type(details) = 'object'
                                AND length(details) <= 8192),
    -- Actor columns must match the actor type.
    CHECK (
        (actor_type = 'user'      AND user_id IS NOT NULL AND api_key_id IS NULL     AND source_ip IS NOT NULL) OR
        (actor_type = 'api_key'   AND user_id IS NOT NULL AND api_key_id IS NOT NULL AND source_ip IS NOT NULL) OR
        (actor_type = 'anonymous' AND user_id IS NULL     AND api_key_id IS NULL     AND source_ip IS NOT NULL) OR
        (actor_type = 'system'    AND user_id IS NULL     AND api_key_id IS NULL     AND source_ip IS NULL)
    )
) STRICT;

-- Audit log screen (newest first, time filters) and retention.
CREATE INDEX ix_audit_time   ON audit_events (occurred_at);
-- Events from one client address, e.g. failed sign-ins from one IP.
CREATE INDEX ix_audit_source ON audit_events (source_ip, occurred_at) WHERE source_ip IS NOT NULL;

-- Record that the database is now at schema version 1.
PRAGMA user_version = 1;
