package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The check is on by default; one update may be open at a time;
// the updater's outcome is recorded and audited once; a request the updater
// never answered stops blocking after an hour.
func TestServerUpdates(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	v, e := s.ServerUpdateSettings(ctx)
	if e != nil || !v.CheckEnabled || v.CheckedAt != nil || v.Available != "" {
		t.Fatal(v, e)
	}
	if e = s.SetServerUpdateCheck(ctx, false, "owner", now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordServerUpdateCheck(ctx, `{"x":1}`, "", now); e != nil {
		t.Fatal(e)
	}
	if v, _ = s.ServerUpdateSettings(ctx); v.CheckEnabled || v.CheckedAt == nil || *v.CheckedAt != now.Unix() || v.Available != `{"x":1}` {
		t.Fatal(v)
	}
	u := ServerUpdate{ID: "0123456789abcdef0123456789abcdef", Version: "1.1.0", Sequence: 11, FromVersion: "1.0.0", RequestedBy: "owner"}
	if e = s.StartServerUpdate(ctx, u, now); e != nil {
		t.Fatal(e)
	}
	second := u
	second.ID = "fedcba9876543210fedcba9876543210"
	if e = s.StartServerUpdate(ctx, second, now); !errors.Is(e, ErrServerUpdate) {
		t.Fatal("second open update accepted", e)
	}
	for _, phase := range []string{"accepted", "backing_up", "backing_up", "starting"} {
		if e = s.ApplyServerUpdateStatus(ctx, u.ID, phase, "", "update-1", false, now); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 2; i++ {
		if e = s.ApplyServerUpdateStatus(ctx, u.ID, "rolled_back", "The new version did not become healthy.", "update-1", true, now); e != nil {
			t.Fatal(e)
		}
	}
	// A finished update is not changed by later status.
	if e = s.ApplyServerUpdateStatus(ctx, u.ID, "succeeded", "", "", true, now); e != nil {
		t.Fatal(e)
	}
	list, e := s.ServerUpdates(ctx)
	if e != nil || len(list) != 1 || list[0].Phase != "rolled_back" || list[0].Backup != "update-1" || list[0].FinishedAt == nil {
		t.Fatal(list, e)
	}
	var audits int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='server_update_finished' AND outcome='rolled_back' AND actor='owner'").Scan(&audits)
	if audits != 1 {
		t.Fatal("audit", audits)
	}
	// An unanswered request no longer blocks after an hour.
	if e = s.StartServerUpdate(ctx, second, now); e != nil {
		t.Fatal(e)
	}
	third := u
	third.ID = "00000000000000000000000000000003"
	if e = s.StartServerUpdate(ctx, third, now.Add(30*time.Minute)); !errors.Is(e, ErrServerUpdate) {
		t.Fatal("open update ignored", e)
	}
	if e = s.StartServerUpdate(ctx, third, now.Add(2*time.Hour)); e != nil {
		t.Fatal(e)
	}
	list, _ = s.ServerUpdates(ctx)
	phases := map[string]string{}
	for _, item := range list {
		phases[item.ID] = item.Phase
	}
	if len(list) != 3 || phases[second.ID] != "failed" || phases[third.ID] != "requested" {
		t.Fatal(list)
	}
}
