package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A live snapshot of a database in use is consistent, and the restore
// changes apply to the current schema: revocations are carried over and
// sessions do not come back.
func TestSnapshotAndReconcileRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, e := Open(ctx, filepath.Join(dir, "data", "openrmm.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	const first, second = "00000000000000000000000000000001", "00000000000000000000000000000002"
	for _, q := range []string{
		"INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint) VALUES('" + first + "','pc1','windows','amd64',1,'public','f1')",
		"INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint,revoked_at) VALUES('" + second + "','pc2','windows','amd64',1,'public','f2',50)",
	} {
		if _, e = s.db.Exec(q); e != nil {
			t.Fatal(q, e)
		}
	}
	// A database that does not exist yet is never created by a backup.
	missing := filepath.Join(dir, "none", "openrmm.db")
	os.MkdirAll(filepath.Dir(missing), 0700)
	if e = SnapshotFile(ctx, missing, filepath.Join(dir, "none", "copy.db")); e == nil {
		t.Fatal("snapshot of a missing database")
	}
	if _, e = os.Stat(missing); e == nil {
		t.Fatal("missing database created")
	}
	snapshot := filepath.Join(dir, "copy", "openrmm.db")
	if e = os.MkdirAll(filepath.Dir(snapshot), 0700); e != nil {
		t.Fatal(e)
	}
	// The store stays open: the server keeps running during a nightly backup.
	if e = SnapshotFile(ctx, filepath.Join(dir, "data", "openrmm.db"), snapshot); e != nil {
		t.Fatal(e)
	}
	if e = CheckFile(ctx, snapshot); e != nil {
		t.Fatal(e)
	}
	live, _ := s.Info(ctx)
	info, e := InspectFile(ctx, snapshot)
	if e != nil || info.InstanceID != live.InstanceID || info.SchemaVersion != live.SchemaVersion {
		t.Fatal("snapshot identity", info, e)
	}
	revoked, e := RevokedDevicesFile(ctx, snapshot)
	if e != nil || len(revoked) != 1 || revoked[second] != 50 {
		t.Fatal("revoked devices", revoked, e)
	}
	if e = ReconcileRestore(ctx, snapshot, map[string]int64{"bad": 1}, time.Now()); e == nil {
		t.Fatal("invalid revocation accepted")
	}
	if e = ReconcileRestore(ctx, snapshot, map[string]int64{first: 70, second: 90}, time.Unix(1800000000, 0)); e != nil {
		t.Fatal(e)
	}
	r, e := Open(ctx, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	got := map[string]int64{}
	rows, e := r.db.Query("SELECT id, revoked_at FROM devices")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var id string
		var at int64
		if rows.Scan(&id, &at) == nil {
			got[id] = at
		}
	}
	rows.Close()
	// An earlier revocation time in the backup is kept.
	if got[first] != 70 || got[second] != 50 {
		t.Fatal("revocations not applied", got)
	}
	var paused bool
	var audits int
	if e = r.db.QueryRow("SELECT mail_paused FROM alert_runtime WHERE id=1").Scan(&paused); e != nil || !paused {
		t.Fatal("alert e-mail not paused", e)
	}
	if e = r.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='restore_reconciled'").Scan(&audits); e != nil || audits != 1 {
		t.Fatal("restore not audited", e)
	}
}
