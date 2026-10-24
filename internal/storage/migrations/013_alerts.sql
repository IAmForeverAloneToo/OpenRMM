CREATE TABLE alert_rules (
 kind TEXT PRIMARY KEY CHECK(kind IN ('offline','disk_space','cpu','memory')),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), threshold INTEGER NOT NULL,
 hold_seconds INTEGER NOT NULL, recovery_seconds INTEGER NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
 email INTEGER NOT NULL CHECK(email IN (0,1)), revision INTEGER NOT NULL
);
INSERT INTO alert_rules VALUES
 ('offline',1,0,180,60,'critical',0,1),
 ('disk_space',1,10,300,60,'critical',0,1),
 ('cpu',1,90,300,60,'warning',0,1),
 ('memory',1,90,300,60,'warning',0,1);
CREATE TABLE alert_runtime (
 id INTEGER PRIMARY KEY CHECK(id=1),offline_after INTEGER NOT NULL DEFAULT 120,
 mail_config TEXT NOT NULL DEFAULT '',mail_paused INTEGER NOT NULL DEFAULT 0 CHECK(mail_paused IN (0,1)),last_sweep INTEGER NOT NULL DEFAULT 0,
 gap INTEGER NOT NULL DEFAULT 0,last_gap INTEGER NOT NULL DEFAULT 0
);
INSERT INTO alert_runtime(id) VALUES(1);
CREATE TABLE alert_samples (
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 device_id TEXT NOT NULL REFERENCES devices(id),kind TEXT NOT NULL,
 status TEXT NOT NULL,data TEXT NOT NULL,received_at INTEGER NOT NULL,contact_at INTEGER
);
CREATE TABLE alert_states (
 device_id TEXT NOT NULL REFERENCES devices(id),kind TEXT NOT NULL REFERENCES alert_rules(kind),
 state_json TEXT NOT NULL,PRIMARY KEY(device_id,kind)
);
CREATE TABLE alerts (
 id TEXT PRIMARY KEY CHECK(length(id)=32),device_id TEXT NOT NULL REFERENCES devices(id),
 hostname TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT NOT NULL,
 threshold INTEGER NOT NULL,hold_seconds INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('active','resolved','closed')),
 opened_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,finished_at INTEGER,
 acknowledged_at INTEGER,acknowledged_by TEXT NOT NULL DEFAULT '',close_reason TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX alerts_one_active ON alerts(device_id,kind) WHERE status='active';
CREATE INDEX alerts_recent ON alerts(opened_at DESC,id);
CREATE TABLE alert_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
 event TEXT NOT NULL CHECK(event IN ('opened','resolved')),config_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','sending','sent','failed','unknown','cancelled')),
 created_at INTEGER NOT NULL,next_attempt INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
 finished_at INTEGER,reason TEXT NOT NULL DEFAULT '',UNIQUE(alert_id,event)
);
