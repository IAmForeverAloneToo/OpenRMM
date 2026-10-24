-- Phase 4.5: logon history from the Windows Security log (event 4624:
-- interactive, remote and network logons), kept 365 days like the session
-- history. Each logon arrives once; the key ignores a repeated delivery.
CREATE TABLE device_logons (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 collected_at INTEGER,
 more INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE logon_history (
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 logon_at INTEGER NOT NULL,
 record_id INTEGER NOT NULL,
 user_name TEXT NOT NULL,
 domain TEXT NOT NULL,
 sid TEXT NOT NULL,
 logon_type TEXT NOT NULL CHECK(logon_type IN ('interactive','network','network_cleartext','remote','cached')),
 source_ip TEXT NOT NULL,
 source_port INTEGER NOT NULL,
 workstation TEXT NOT NULL,
 auth_package TEXT NOT NULL,
 logon_process TEXT NOT NULL,
 logon_id TEXT NOT NULL,
 elevated INTEGER NOT NULL,
 PRIMARY KEY(device_id, logon_at, record_id)
);
CREATE INDEX logon_history_at ON logon_history(logon_at);
