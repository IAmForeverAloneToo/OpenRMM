-- Collected triage packages, registry hives and event logs are parsed on
-- the server into tables. One row per collection holds its latest parse;
-- the results are stored like evidence (sha256, size) and count toward the
-- evidence quota.
CREATE TABLE artefact_parses (
 job_id TEXT PRIMARY KEY REFERENCES evidence_jobs(id),
 status TEXT NOT NULL CHECK(status IN ('queued','running','succeeded','failed')),
 outcome TEXT NOT NULL DEFAULT '',
 parser INTEGER NOT NULL DEFAULT 0,
 sha256 TEXT NOT NULL DEFAULT '',
 size INTEGER NOT NULL DEFAULT 0,
 tables_json TEXT NOT NULL DEFAULT '[]',
 attempts INTEGER NOT NULL DEFAULT 0,
 requested_by TEXT NOT NULL,
 queued_at INTEGER NOT NULL,
 started_at INTEGER,
 finished_at INTEGER
) WITHOUT ROWID;
CREATE INDEX artefact_parses_queue ON artefact_parses(status, queued_at);
