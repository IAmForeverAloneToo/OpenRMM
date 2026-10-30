-- NTFS artifacts are evidence jobs of source 'ntfs' (path: a label, query:
-- the volumes). SQLite cannot change a CHECK constraint in place, so the
-- table is rebuilt as in 042; chunk rows referencing it are kept aside
-- meanwhile.
CREATE TEMP TABLE evidence_chunks_053 AS SELECT * FROM evidence_chunks;
DELETE FROM evidence_chunks;
CREATE TABLE evidence_jobs_053 (
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
 finished_at INTEGER,
 kind TEXT NOT NULL DEFAULT 'file' CHECK(kind IN ('file','transcript')),
 source TEXT NOT NULL DEFAULT 'file' CHECK(source IN ('file','hive','evtx','triage','ntfs')),
 meta_json TEXT NOT NULL DEFAULT '',
 parent_id TEXT NOT NULL DEFAULT '',
 action TEXT NOT NULL DEFAULT '',
 session_id TEXT NOT NULL DEFAULT '',
 query TEXT NOT NULL DEFAULT '',
 hunt_id TEXT NOT NULL DEFAULT ''
);
INSERT INTO evidence_jobs_053 (id,case_id,device_id,actor,path,status,outcome,chunk_size,size,resolved_path,file_modified,file_created,device_sha256,server_sha256,verify_attempts,created_at,expires_at,dispatched_at,activity_at,finished_at,kind,source,meta_json,parent_id,action,session_id,query,hunt_id)
 SELECT id,case_id,device_id,actor,path,status,outcome,chunk_size,size,resolved_path,file_modified,file_created,device_sha256,server_sha256,verify_attempts,created_at,expires_at,dispatched_at,activity_at,finished_at,kind,source,meta_json,parent_id,action,session_id,query,hunt_id FROM evidence_jobs;
DROP TABLE evidence_jobs;
ALTER TABLE evidence_jobs_053 RENAME TO evidence_jobs;
CREATE INDEX evidence_jobs_device ON evidence_jobs(device_id, status, created_at);
CREATE INDEX evidence_jobs_case ON evidence_jobs(case_id, created_at DESC);
CREATE INDEX evidence_jobs_session ON evidence_jobs(session_id, created_at DESC) WHERE session_id <> '';
CREATE INDEX evidence_jobs_hunt ON evidence_jobs(hunt_id);
INSERT INTO evidence_chunks SELECT * FROM evidence_chunks_053;
DROP TABLE evidence_chunks_053;
