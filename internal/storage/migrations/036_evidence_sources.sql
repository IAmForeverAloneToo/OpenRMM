-- Phase 3b: registry hives as an evidence source, what the agent reported
-- about each collected file (method, times, owner, streams), and alternate
-- data streams collected on their own as children of a file's collection.
ALTER TABLE evidence_jobs ADD COLUMN source TEXT NOT NULL DEFAULT 'file' CHECK(source IN ('file','hive'));
ALTER TABLE evidence_jobs ADD COLUMN meta_json TEXT NOT NULL DEFAULT '';
ALTER TABLE evidence_jobs ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
