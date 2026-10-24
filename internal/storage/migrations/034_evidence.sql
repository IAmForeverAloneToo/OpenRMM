-- Phase 2c: evidence collection. A job collects one file from one device for
-- one case; uploads arrive in chunks, each verified on arrival, and the whole
-- file is verified before it is stored content-addressed (SHA-256) in the
-- evidence directory. Evidence is never pruned automatically.
CREATE TABLE evidence_jobs (
 id TEXT PRIMARY KEY,
 case_id TEXT NOT NULL REFERENCES cases(id),
 device_id TEXT NOT NULL,
 actor TEXT NOT NULL,
 path TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','dispatched','uploading','verifying','succeeded','failed','expired','cancelled')),
 outcome TEXT NOT NULL DEFAULT '',
 chunk_size INTEGER NOT NULL CHECK(chunk_size > 0),
 size INTEGER NOT NULL DEFAULT 0,
 resolved_path TEXT NOT NULL DEFAULT '',
 file_modified INTEGER NOT NULL DEFAULT 0,
 file_created INTEGER NOT NULL DEFAULT 0,
 device_sha256 TEXT NOT NULL DEFAULT '',
 server_sha256 TEXT NOT NULL DEFAULT '',
 verify_attempts INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 dispatched_at INTEGER,
 activity_at INTEGER,
 finished_at INTEGER
);
CREATE INDEX evidence_jobs_device ON evidence_jobs(device_id, status, created_at);
CREATE INDEX evidence_jobs_case ON evidence_jobs(case_id, created_at DESC);
CREATE TABLE evidence_chunks (
 job_id TEXT NOT NULL REFERENCES evidence_jobs(id),
 idx INTEGER NOT NULL CHECK(idx >= 0),
 sha256 TEXT NOT NULL,
 PRIMARY KEY (job_id, idx)
) WITHOUT ROWID;
CREATE TABLE evidence_files (
 sha256 TEXT PRIMARY KEY,
 size INTEGER NOT NULL,
 stored_at INTEGER NOT NULL
) WITHOUT ROWID;
