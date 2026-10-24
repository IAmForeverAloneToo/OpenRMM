-- Phase 3e: live response sessions. Jobs that a session's built-in commands
-- start name the session; jobs of a session without a case belong to this
-- built-in record, which is never listed or shown as a case: such jobs write
-- the audit log instead of a custody log, and their results are kept for 24
-- hours outside the evidence store.
ALTER TABLE evidence_jobs ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
CREATE INDEX evidence_jobs_session ON evidence_jobs(session_id, created_at DESC) WHERE session_id <> '';
INSERT INTO cases(id,title,status,created_by,created_at,updated_at) VALUES('00000000000000000000000000000000','Live response without a case','open','system',0,0);
