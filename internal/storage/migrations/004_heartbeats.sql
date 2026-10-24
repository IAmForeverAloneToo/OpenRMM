ALTER TABLE devices ADD COLUMN last_contact_at INTEGER;
ALTER TABLE devices ADD COLUMN agent_version TEXT NOT NULL DEFAULT '';
