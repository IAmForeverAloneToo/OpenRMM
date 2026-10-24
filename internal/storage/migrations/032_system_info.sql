-- Phase 1c: expanded device information (hardware, CPU, operating system,
-- domain and Entra join, network adapters). The newest report per device; a
-- failed report keeps the last good snapshot. The fleet list's identifiers
-- are kept in their own columns so listing devices never decodes reports.
CREATE TABLE device_system_info (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 snapshot_json TEXT NOT NULL DEFAULT '',
 snapshot_at INTEGER,
 primary_ipv4 TEXT NOT NULL DEFAULT '',
 addresses TEXT NOT NULL DEFAULT '',
 macs TEXT NOT NULL DEFAULT '',
 serial TEXT NOT NULL DEFAULT '',
 manufacturer TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT ''
);
