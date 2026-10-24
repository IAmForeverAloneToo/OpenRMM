CREATE TABLE agent_release_state(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL);
INSERT INTO agent_release_state VALUES(1,1);
CREATE TABLE agent_releases(
 id TEXT PRIMARY KEY CHECK(length(id)=64),signed_json TEXT NOT NULL,public_key TEXT NOT NULL,
 key_id TEXT NOT NULL,sequence INTEGER NOT NULL,created_at INTEGER NOT NULL,actor TEXT NOT NULL,
 withdrawn INTEGER NOT NULL DEFAULT 0,UNIQUE(key_id,sequence)
);
CREATE TABLE device_agent_upgrade_support(
 device_id TEXT PRIMARY KEY REFERENCES devices(id),last_status TEXT NOT NULL,
 reported_at INTEGER NOT NULL,support_json TEXT NOT NULL
);
CREATE TABLE agent_upgrade_jobs(
 id TEXT PRIMARY KEY CHECK(length(id)=32),batch_id TEXT NOT NULL,device_id TEXT NOT NULL REFERENCES devices(id),
 release_id TEXT NOT NULL REFERENCES agent_releases(id),expected_hash TEXT NOT NULL,
 actor TEXT NOT NULL,request_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',
 result_json TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
 dispatched_at INTEGER,finished_at INTEGER,UNIQUE(batch_id,device_id)
);
CREATE INDEX agent_upgrade_jobs_device ON agent_upgrade_jobs(device_id,created_at DESC);
