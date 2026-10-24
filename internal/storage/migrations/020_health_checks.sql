CREATE TABLE health_checks (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 device_id TEXT NOT NULL REFERENCES devices(id),
 name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind='service_running'),
 service_name TEXT NOT NULL, service_key TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 hold_seconds INTEGER NOT NULL, recovery_seconds INTEGER NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('warning','critical')),
 email INTEGER NOT NULL CHECK(email IN (0,1)),
 response INTEGER NOT NULL CHECK(response IN (0,1)), cooldown_seconds INTEGER NOT NULL,
 revision INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX health_checks_device ON health_checks(device_id);
CREATE TABLE health_states (
 check_id TEXT PRIMARY KEY REFERENCES health_checks(id),
 device_id TEXT NOT NULL REFERENCES devices(id), state_json TEXT NOT NULL,
 attempt_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE health_samples (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, check_id TEXT NOT NULL REFERENCES health_checks(id),
 revision INTEGER NOT NULL, condition TEXT NOT NULL, received_at INTEGER NOT NULL
);
CREATE TABLE health_guards (
 device_id TEXT NOT NULL REFERENCES devices(id), service_key TEXT NOT NULL,
 last_attempt INTEGER NOT NULL, blocked INTEGER NOT NULL CHECK(blocked IN (0,1)),
 action_id TEXT NOT NULL, PRIMARY KEY(device_id,service_key)
);
CREATE TABLE health_attempts (
 action_id TEXT PRIMARY KEY, check_id TEXT NOT NULL REFERENCES health_checks(id),
 incident_id TEXT NOT NULL, revision INTEGER NOT NULL, device_id TEXT NOT NULL REFERENCES devices(id),
 check_name TEXT NOT NULL, service_name TEXT NOT NULL, service_key TEXT NOT NULL,
 created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
 outcome TEXT NOT NULL DEFAULT '', observed_state TEXT NOT NULL DEFAULT 'unknown',
 finished_at INTEGER, UNIQUE(check_id,incident_id)
);
-- Mirror terminal transitions before bounded service-action history is pruned.
-- A queued action that never executed is safe to cancel/expire. Failed or
-- uncertain dispatched work stays latched; success still requires fresh recovery.
CREATE TRIGGER health_action_result AFTER UPDATE OF status ON service_actions
BEGIN
 UPDATE health_attempts SET status=NEW.status,outcome=NEW.outcome,
  observed_state=NEW.observed_state,finished_at=NEW.finished_at WHERE action_id=NEW.id;
 UPDATE health_guards SET blocked=0 WHERE action_id=NEW.id
  AND NEW.status IN ('succeeded','cancelled','expired');
END;
ALTER TABLE alerts ADD COLUMN label TEXT NOT NULL DEFAULT '';
