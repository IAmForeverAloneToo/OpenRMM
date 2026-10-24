CREATE TABLE application_state(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL);
INSERT INTO application_state VALUES(1,1);
CREATE TABLE applications(id TEXT PRIMARY KEY CHECK(length(id)=32),created_at INTEGER NOT NULL);
CREATE TABLE application_versions(
 id TEXT PRIMARY KEY CHECK(length(id)=32),application_id TEXT NOT NULL REFERENCES applications(id),
 version INTEGER NOT NULL,definition_json TEXT NOT NULL,
 mutation_runner TEXT NOT NULL UNIQUE REFERENCES script_versions(id),
 verification_runner TEXT NOT NULL UNIQUE REFERENCES script_versions(id),
 created_at INTEGER NOT NULL,actor TEXT NOT NULL,UNIQUE(application_id,version)
);
CREATE TABLE application_deployments(
 id TEXT PRIMARY KEY CHECK(length(id)=32),batch_id TEXT NOT NULL,device_id TEXT NOT NULL REFERENCES devices(id),
 version_id TEXT NOT NULL REFERENCES application_versions(id),
 previous_version_id TEXT REFERENCES application_versions(id),
 operation TEXT NOT NULL CHECK(operation IN ('verify','install','update','uninstall')),
 actor TEXT NOT NULL,request_hash TEXT NOT NULL,known_products_json TEXT NOT NULL,
 run_id TEXT UNIQUE REFERENCES script_runs(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'queued',result_json TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,dispatched_at INTEGER,finished_at INTEGER,
 UNIQUE(batch_id,device_id)
);
CREATE INDEX application_deployments_device ON application_deployments(device_id,created_at DESC);
CREATE TRIGGER application_run_status AFTER UPDATE ON script_runs
BEGIN
 UPDATE application_deployments SET status=NEW.status,result_json=NEW.result_json,
 dispatched_at=NEW.dispatched_at,finished_at=NEW.finished_at WHERE run_id=NEW.id;
END;
