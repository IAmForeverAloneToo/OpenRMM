package storage

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// rollbackFeatureSettings removes migration 28 so older-schema
// reconstruction tests can continue from schema 27.
func rollbackFeatureSettings(t *testing.T, db *sql.DB) {
	t.Helper()
	rollbackInstaller(t, db)
	var n int
	if e := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=28").Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n == 0 {
		return
	}
	for _, q := range []string{"ALTER TABLE devices DROP COLUMN feature_locks_json", "ALTER TABLE monitoring_policies DROP COLUMN features_json", "DELETE FROM schema_migrations WHERE version=28"} {
		if _, e := db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
}

func fullRules(t *testing.T, s *Store) []alerting.Rule {
	t.Helper()
	o, e := s.Organization(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return o.Defaults
}

// A policy's switched-off features reach the device through its
// device policy, else its group policy; heartbeats store local locks.
func TestFeatureSettingsFollowEffectivePolicyAndLocks(t *testing.T) {
	s, d, _, now := upgradeFixture(t)
	ctx := context.Background()
	off, e := s.DisabledFeatures(ctx, d.ID)
	if e != nil || len(off) != 0 {
		t.Fatal("default must be everything on", off, e)
	}
	change := func(c OrganizationChange) OrganizationReview {
		t.Helper()
		o, e := s.Organization(ctx)
		if e != nil {
			t.Fatal(e)
		}
		c.Revision = o.Revision
		r, e := s.ChangeOrganization(ctx, c, "admin", "", now)
		if e != nil {
			t.Fatal("review", c.Action, e)
		}
		if _, e = s.ChangeOrganization(ctx, c, "admin", r.Digest, now); e != nil {
			t.Fatal("apply", c.Action, e)
		}
		return r
	}
	rules := fullRules(t, s)
	o, _ := s.Organization(ctx)
	if _, e := s.ChangeOrganization(ctx, OrganizationChange{Action: "policy-create", ID: "bad", Name: "Bad", Rules: rules, Features: map[string]bool{"nonsense": false}, Revision: o.Revision}, "admin", "", now); e == nil {
		t.Fatal("unknown feature accepted")
	}
	change(OrganizationChange{Action: "policy-create", ID: "quiet", Name: "Quiet", Rules: rules, Features: map[string]bool{"terminal": false, "desktop": false, "files": true}})
	change(OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab", PolicyID: "quiet"})
	r := change(OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab", Tags: []string{}})
	if len(r.Impacts) != 1 || !slices.Equal(r.Impacts[0].Features, []string{"desktop", "terminal"}) {
		t.Fatal("review must list the feature changes", r.Impacts)
	}
	if off, _ = s.DisabledFeatures(ctx, d.ID); !slices.Equal(off, []string{"desktop", "terminal"}) {
		t.Fatal("group policy not applied", off)
	}
	change(OrganizationChange{Action: "policy-create", ID: "open", Name: "Open", Rules: rules})
	change(OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab", PolicyID: "open", Tags: []string{}})
	if off, _ = s.DisabledFeatures(ctx, d.ID); len(off) != 0 {
		t.Fatal("device policy must win over the group policy", off)
	}
	o, _ = s.Organization(ctx)
	for _, p := range o.Policies {
		if p.ID == "quiet" && (len(p.Features) != 2 || p.Features["files"]) {
			t.Fatal("only switched-off features are stored", p.Features)
		}
	}
	h := protocol.Heartbeat{Hostname: d.Hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test.1", Locked: []string{"scripts", "terminal"}}
	if !h.Valid() {
		t.Fatal("valid locks refused")
	}
	if e = s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, h, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	var raw string
	if e = s.db.QueryRow("SELECT feature_locks_json FROM devices WHERE id=?", d.ID).Scan(&raw); e != nil || !strings.Contains(raw, "scripts") {
		t.Fatal("locks not stored", raw, e)
	}
	for _, bad := range [][]string{{"terminal", "scripts"}, {"scripts", "scripts"}, {"nonsense"}} {
		h.Locked = bad
		if h.Valid() {
			t.Fatal("invalid lock list accepted", bad)
		}
	}
}

// rollbackInstaller removes migration 29, the newest layer.
func rollbackInstaller(t *testing.T, db *sql.DB) {
	t.Helper()
	rollbackSessions(t, db)
	var n int
	if e := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=29").Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n == 0 {
		return
	}
	for _, q := range []string{"DROP TABLE installer_settings", "ALTER TABLE devices DROP COLUMN enrollment_token_id", "ALTER TABLE enrollment_tokens DROP COLUMN revoked_at", "ALTER TABLE enrollment_tokens DROP COLUMN actor", "ALTER TABLE enrollment_tokens DROP COLUMN used", "ALTER TABLE enrollment_tokens DROP COLUMN max_devices", "ALTER TABLE enrollment_tokens DROP COLUMN reusable", "ALTER TABLE enrollment_tokens DROP COLUMN label", "ALTER TABLE enrollment_tokens DROP COLUMN id", "DELETE FROM schema_migrations WHERE version=29"} {
		if _, e := db.Exec(q); e != nil {
			t.Fatal(q, e)
		}
	}
}

// rollbackSessions removes migration 30, the newest layer.
func rollbackSessions(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, q := range []string{"DELETE FROM schema_migrations WHERE version=53", "DELETE FROM schema_migrations WHERE version=52", "DROP INDEX IF EXISTS audit_events_time", "DELETE FROM schema_migrations WHERE version=51", "DROP TABLE IF EXISTS backup_settings", "DELETE FROM schema_migrations WHERE version=50", "DROP TABLE IF EXISTS mail_settings", "DELETE FROM schema_migrations WHERE version=49", "DELETE FROM schema_migrations WHERE version=48", "DROP TABLE IF EXISTS server_updates", "DROP TABLE IF EXISTS server_update_settings", "DELETE FROM schema_migrations WHERE version=47", "DROP TABLE IF EXISTS setup_links", "DELETE FROM schema_migrations WHERE version=46", "DROP TABLE IF EXISTS device_isolations", "ALTER TABLE devices DROP COLUMN isolated", "ALTER TABLE devices DROP COLUMN isolation_json", "ALTER TABLE monitoring_policies DROP COLUMN isolation_allow_json", "DELETE FROM schema_migrations WHERE version=45", "DROP TABLE IF EXISTS ioc_lists", "DELETE FROM schema_migrations WHERE version=44", "DROP TABLE IF EXISTS logon_history", "DROP TABLE IF EXISTS device_logons", "DELETE FROM schema_migrations WHERE version=43", "DROP TABLE IF EXISTS device_security", "DELETE FROM schema_migrations WHERE version=42", "DROP TABLE IF EXISTS triage_profiles", "ALTER TABLE devices DROP COLUMN abilities_json", "DELETE FROM schema_migrations WHERE version=41", "DROP TABLE IF EXISTS hunt_results", "DROP TABLE IF EXISTS hunts", "DELETE FROM schema_migrations WHERE version=40", "DELETE FROM schema_migrations WHERE version=39", "DROP TABLE IF EXISTS response_tools", "DELETE FROM schema_migrations WHERE version=38", "DELETE FROM schema_migrations WHERE version=37", "DELETE FROM schema_migrations WHERE version=36", "DELETE FROM schema_migrations WHERE version=35", "DROP TABLE IF EXISTS evidence_chunks", "DROP TABLE IF EXISTS evidence_files", "DROP TABLE IF EXISTS evidence_jobs", "DELETE FROM schema_migrations WHERE version=34", "DROP TRIGGER IF EXISTS custody_append_only_update", "DROP TRIGGER IF EXISTS custody_append_only_delete", "DROP TRIGGER IF EXISTS cases_kept", "DROP TABLE IF EXISTS custody_entries", "DROP TABLE IF EXISTS cases", "DELETE FROM schema_migrations WHERE version=33", "DROP TABLE IF EXISTS device_system_info", "DELETE FROM schema_migrations WHERE version=32", "DROP TABLE IF EXISTS device_local_accounts", "DELETE FROM schema_migrations WHERE version=31", "DROP TABLE IF EXISTS session_history", "DROP TABLE IF EXISTS device_sessions", "DELETE FROM schema_migrations WHERE version=30"} {
		if _, e := db.Exec(q); e != nil {
			t.Fatal(q, e)
		}
	}
}
