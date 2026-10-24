package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func batchFixture(t *testing.T) (*Store, []Device, ScriptVersion, time.Time) {
	t.Helper()
	s, d, v, now := scriptFixture(t)
	ctx := context.Background()
	if e := s.SetAdministrator(ctx, Administrator{Username: "admin", PasswordHash: "hash", TOTPCipher: []byte("cipher")}, nil, false, now); e != nil {
		t.Fatal(e)
	}
	other := d
	other.ID = strings.Repeat("3", 32)
	other.Hostname = "Second <device>"
	other.Fingerprint = "second-fp"
	if e := s.NewEnrollmentToken(ctx, "batch-token", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "batch-token", other, now); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordHeartbeat(ctx, other.ID, other.Fingerprint, protocol.Heartbeat{Hostname: other.Hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "enabled"})
	if e := s.RecordScriptSupport(ctx, other.ID, other.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	return s, []Device{d, other}, v, now
}
func batchChange(v ScriptVersion, ds []Device) ScriptBatchChange {
	ids := []string{}
	for _, d := range ds {
		ids = append(ids, d.ID)
	}
	return ScriptBatchChange{ID: strings.Repeat("b", 32), VersionID: v.ID, Name: "Reviewed diagnostics", Devices: ids, Arguments: map[string]string{"Message": "private argument"}}
}
func TestScriptBatchReviewAtomicFailureAndIdempotentConfirmation(t *testing.T) {
	s, ds, v, now := batchFixture(t)
	ctx := context.Background()
	c := batchChange(v, ds)
	review, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, 2*time.Minute)
	if e != nil || len(review.Targets) != 2 || len(review.Problems) != 0 {
		t.Fatal(review, e)
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&n)
	if n != 0 {
		t.Fatal("review queued work")
	}
	changed := c
	changed.Name = "Different request"
	if _, e = s.SubmitScriptBatch(ctx, changed, "admin", review.Digest, now, 2*time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("changed review accepted", e)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER fail_batch_child BEFORE INSERT ON script_runs WHEN NEW.device_id='` + review.Targets[1].ID + `' BEGIN SELECT RAISE(ABORT,'fixture');END`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", review.Digest, now, 2*time.Minute); e == nil {
		t.Fatal("partial batch accepted")
	}
	for _, table := range []string{"script_runs", "script_batches"} {
		s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Fatal("partial batch survived", table, n)
		}
	}
	s.db.Exec("DROP TRIGGER fail_batch_child")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.SubmitScriptBatch(ctx, c, "admin", review.Digest, now, 2*time.Minute); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&n)
	if n != 2 {
		t.Fatal("confirmation replay created work", n)
	}
	b, e := s.ScriptBatch(ctx, c.ID, "admin", now)
	if e != nil || len(b.Targets) != 2 || b.Targets[0].Status != "queued" {
		t.Fatal(b, e)
	}
	if e = s.CancelScriptRun(ctx, b.Targets[0].ID, b.Targets[0].RunID, "admin", now); e != nil {
		t.Fatal(e)
	}
	b, e = s.ScriptBatch(ctx, c.ID, "admin", now)
	if e != nil || b.Targets[0].Status != "cancelled" || !b.Targets[0].CancelRequested {
		t.Fatal("per-device control lost", b, e)
	}
	// Metadata can outlive child results. Reconfirming history must not recreate
	// deleted runs or enlarge the batch after its original selection changed.
	s.db.Exec("DELETE FROM script_runs")
	b, e = s.SubmitScriptBatch(ctx, c, "admin", review.Digest, now, 2*time.Minute)
	if e != nil || b.Targets[0].Status != "history_unavailable" {
		t.Fatal(b, e)
	}
	s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&n)
	if n != 0 {
		t.Fatal("history loss replayed execution")
	}
	if _, e = s.SubmitScriptBatch(ctx, changed, "admin", review.Digest, now, 2*time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("duplicate tamper", e)
	}
	if _, e = s.ScriptBatch(ctx, c.ID, "someone else", now); !errors.Is(e, ErrForbidden) {
		t.Fatal("nonowner batch read", e)
	}
	s.db.Exec("UPDATE script_batches SET restored=1")
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", review.Digest, now, 2*time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("restored batch resubmitted", e)
	}
}
func TestScriptBatchGroupSnapshotAndReadiness(t *testing.T) {
	s, ds, v, now := batchFixture(t)
	ctx := context.Background()
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: ds[0].ID, GroupID: "lab", Tags: []string{}}, now)
	c := batchChange(v, ds[:1])
	c.Groups = []string{"lab"}
	r, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, 2*time.Minute)
	if e != nil || len(r.Targets) != 1 {
		t.Fatal("overlap counted twice", r, e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: ds[1].ID, GroupID: "lab", Tags: []string{}}, now)
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", r.Digest, now, 2*time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("membership change not re-reviewed", e)
	}
	r, e = s.SubmitScriptBatch(ctx, c, "admin", "", now, 2*time.Minute)
	if e != nil || len(r.Targets) != 2 {
		t.Fatal(r, e)
	}
	if _, e = s.db.Exec("UPDATE device_script_support SET reported_at=? WHERE device_id=?", now.Add(-3*time.Minute).Unix(), ds[1].ID); e != nil {
		t.Fatal(e)
	}
	blocked, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, 2*time.Minute)
	if e != nil || blocked.Problems[ds[1].ID] == "" {
		t.Fatal("stale capability appeared ready", blocked, e)
	}
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", r.Digest, now, 2*time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("unavailable target queued", e)
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&n)
	if n != 0 {
		t.Fatal("partial unavailable batch")
	}
	if _, e = s.db.Exec("UPDATE device_script_support SET reported_at=?", now.Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", r.Digest, now, 2*time.Minute); e != nil {
		t.Fatal(e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: ds[1].ID, Tags: []string{}}, now)
	stored, e := s.SubmitScriptBatch(ctx, c, "admin", r.Digest, now, 2*time.Minute)
	if e != nil || len(stored.Targets) != 2 {
		t.Fatal("duplicate changed targets", stored, e)
	}
}
func TestScriptBatchLimitsCapacityAndLocalSystemPolicy(t *testing.T) {
	s, ds, v, now := batchFixture(t)
	ctx := context.Background()
	c := batchChange(v, ds)
	c.Devices = append(c.Devices, c.Devices[0])
	if _, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("duplicate target", e)
	}
	c = batchChange(v, ds)
	c.Groups = []string{"missing"}
	if _, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("unknown group", e)
	}
	c = batchChange(v, ds)
	c.Devices = nil
	for i := range 26 {
		c.Devices = append(c.Devices, fmt.Sprintf("%032x", i+1))
	}
	if _, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("too many targets", e)
	}
	v.ID = strings.Repeat("f", 32)
	v.Definition.RunAs = "system"
	system, e := s.CreateScriptVersion(ctx, v, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "disabled"})
	if e = s.RecordScriptSupport(ctx, ds[1].ID, ds[1].Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	c = batchChange(system, ds)
	r, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, time.Minute)
	if e != nil || r.Problems[ds[1].ID] == "" {
		t.Fatal("SYSTEM policy ignored", r, e)
	}
	c = batchChange(v, ds)
	c.VersionID = strings.Repeat("d", 32)
	r, e = s.SubmitScriptBatch(ctx, c, "admin", "", now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	for i := range 200 {
		if _, e = s.db.Exec(`INSERT INTO script_batches(id,version_id,name,actor,request_hash,change_json,targets_json,created_at)VALUES(?,?,'fixture','admin',?,'{}','[]',?)`, fmt.Sprintf("%032x", i+1000), c.VersionID, strings.Repeat("a", 64), now.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", r.Digest, now, time.Minute); !errors.Is(e, ErrScriptBatch) {
		t.Fatal("recent history capacity ignored", e)
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&count)
	if count != 0 {
		t.Fatal("capacity failure queued children")
	}
}
func TestScriptBatchMigrationRetainsInstallationAndVersions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := s.Info(ctx)
	rollbackFeatureSettings(t, s.db)
	for _, q := range []string{"DROP TABLE IF EXISTS agent_ring_policy", "DELETE FROM schema_migrations WHERE version=27", "DROP TABLE script_batches", "DELETE FROM schema_migrations WHERE version=26"} {
		if _, e = s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	s.Close()
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, _ := s.Info(ctx)
	if before != after || after.SchemaVersion != 48 {
		t.Fatal(before, after)
	}
}

func TestScriptBatchRetentionProtectsActiveChildren(t *testing.T) {
	s, ds, v, now := batchFixture(t)
	ctx := context.Background()
	c := batchChange(v, ds)
	r, e := s.SubmitScriptBatch(ctx, c, "admin", "", now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.SubmitScriptBatch(ctx, c, "admin", r.Digest, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	s.db.Exec("UPDATE script_batches SET created_at=?", now.Add(-31*24*time.Hour).Unix())
	if e = s.PruneScriptBatches(ctx, now); e != nil {
		t.Fatal(e)
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM script_batches").Scan(&n)
	if n != 1 {
		t.Fatal("active batch pruned")
	}
	for _, target := range r.Targets {
		if e = s.CancelScriptRun(ctx, target.ID, target.RunID, "admin", now); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.PruneScriptBatches(ctx, now); e != nil {
		t.Fatal(e)
	}
	s.db.QueryRow("SELECT COUNT(*) FROM script_batches").Scan(&n)
	if n != 0 {
		t.Fatal("terminal old batch retained")
	}
}
