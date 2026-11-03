-- Each live check's result from its device's latest services report and
-- that report's snapshot time, written with the report, so the alert sweep
-- need not read every device's service list again.
CREATE TABLE health_current (
 check_id TEXT PRIMARY KEY REFERENCES health_checks(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL,
 condition TEXT NOT NULL CHECK(condition IN ('good','bad','unknown')),
 can_start INTEGER NOT NULL,
 snapshot_at INTEGER
);
