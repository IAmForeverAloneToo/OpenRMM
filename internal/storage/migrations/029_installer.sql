-- Phase 0.6d: installer downloads. A token is either single-device (deleted
-- when used) or a reusable deployment token with a device limit, which is
-- kept for its list until 30 days after it expired or was revoked. Devices
-- record the token they enrolled with; the installer settings hold the public
-- addresses written into downloaded installers.
ALTER TABLE enrollment_tokens ADD COLUMN id TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_tokens ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_tokens ADD COLUMN reusable INTEGER NOT NULL DEFAULT 0 CHECK(reusable IN(0,1));
ALTER TABLE enrollment_tokens ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1 CHECK(max_devices BETWEEN 1 AND 10000);
ALTER TABLE enrollment_tokens ADD COLUMN used INTEGER NOT NULL DEFAULT 0 CHECK(used>=0);
ALTER TABLE enrollment_tokens ADD COLUMN actor TEXT NOT NULL DEFAULT '';
ALTER TABLE enrollment_tokens ADD COLUMN revoked_at INTEGER;
ALTER TABLE devices ADD COLUMN enrollment_token_id TEXT NOT NULL DEFAULT '';
CREATE TABLE installer_settings(
 id INTEGER PRIMARY KEY CHECK(id=1),
 server_url TEXT NOT NULL DEFAULT '',
 device_url TEXT NOT NULL DEFAULT ''
);
INSERT INTO installer_settings(id) VALUES(1);
