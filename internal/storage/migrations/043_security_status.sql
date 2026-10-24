-- Phase 4.5: BitLocker, Microsoft Defender and Security Center antivirus
-- status. The newest report per device; a failed report keeps the last good
-- snapshot. The fleet list's summaries are kept in their own columns so
-- listing devices never decodes reports.
CREATE TABLE device_security (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 snapshot_json TEXT NOT NULL DEFAULT '',
 snapshot_at INTEGER,
 bitlocker TEXT NOT NULL DEFAULT '',
 defender TEXT NOT NULL DEFAULT ''
);
