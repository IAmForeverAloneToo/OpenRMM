-- Phase 3a: terminal transcripts are case evidence. They share the evidence
-- job list (and its download) with collected files; kind tells them apart.
ALTER TABLE evidence_jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'file' CHECK(kind IN ('file','transcript'));
