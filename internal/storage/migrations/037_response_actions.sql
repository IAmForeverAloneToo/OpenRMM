-- Phase 3c: structured response actions are evidence jobs whose result
-- document the agent produces; action holds the canonical action spec
-- (protocol.ResponseAction), empty for collected files and hives.
ALTER TABLE evidence_jobs ADD COLUMN action TEXT NOT NULL DEFAULT '';
