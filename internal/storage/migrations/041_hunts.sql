-- Phase 4.2: fleet searches (hunts). Each target device gets an evidence job
-- (a response action) tagged with the hunt; hunt_results caches each
-- result's counts for the overview.
CREATE TABLE hunts (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('log_search')),
 case_id TEXT NOT NULL REFERENCES cases(id),
 actor TEXT NOT NULL,
 spec TEXT NOT NULL,
 problems_json TEXT NOT NULL DEFAULT '[]',
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 cancelled_at INTEGER
);
CREATE INDEX hunts_created ON hunts(created_at DESC);
ALTER TABLE evidence_jobs ADD COLUMN hunt_id TEXT NOT NULL DEFAULT '';
CREATE INDEX evidence_jobs_hunt ON evidence_jobs(hunt_id);
CREATE TABLE hunt_results (
 job_id TEXT PRIMARY KEY,
 outcome TEXT NOT NULL,
 events INTEGER NOT NULL,
 more INTEGER NOT NULL,
 skipped INTEGER NOT NULL
);
