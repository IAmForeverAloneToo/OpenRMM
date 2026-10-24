-- Phase 5: network isolation. A policy may list addresses that stay
-- reachable while a device is isolated; each device keeps the isolation
-- state its agent last reported; each isolation is recorded with its
-- one-time release code (shown to responders for the local break-glass
-- command) and how it ended.
ALTER TABLE monitoring_policies ADD COLUMN isolation_allow_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(isolation_allow_json));
ALTER TABLE devices ADD COLUMN isolation_json TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN isolated INTEGER NOT NULL DEFAULT 0;
CREATE TABLE device_isolations (
 id TEXT PRIMARY KEY,
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 case_id TEXT NOT NULL,
 actor TEXT NOT NULL,
 code TEXT NOT NULL,
 allow_json TEXT NOT NULL,
 release_after INTEGER NOT NULL DEFAULT 0,
 isolate_job TEXT NOT NULL,
 release_job TEXT NOT NULL DEFAULT '',
 requested_at INTEGER NOT NULL,
 isolated_at INTEGER,
 release_requested_at INTEGER,
 release_actor TEXT NOT NULL DEFAULT '',
 released_at INTEGER,
 release_reason TEXT NOT NULL DEFAULT '' CHECK(release_reason IN ('','server','break_glass','timed','failed'))
);
CREATE INDEX device_isolations_device ON device_isolations(device_id, requested_at DESC);
