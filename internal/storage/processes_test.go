package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"testing"
	"time"
)

func TestProcessSnapshotRetainsLastSuccessAndDeviceAuthorization(t *testing.T) {
	s, d, now := processActionFixture(t)
	ctx := context.Background()
	before, e := s.Processes(ctx, d.ID)
	if e != nil || before.Data == nil {
		t.Fatal(e)
	}
	r := protocol.FeatureReport{Capability: processes.Capability, Status: "disabled"}
	if e = s.RecordProcesses(ctx, d.ID, d.Fingerprint, r, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	after, e := s.Processes(ctx, d.ID)
	if e != nil || after.Status != "disabled" || *after.SnapshotAt != *before.SnapshotAt || len(after.Data.Items) != 1 {
		t.Fatal("last success lost", e)
	}
	data, _ := json.Marshal(protocol.Processes{Coverage: processes.Coverage, Items: []protocol.Process{}})
	r.Status = "ok"
	r.Data = data
	if e = s.RecordProcesses(ctx, d.ID, d.Fingerprint, r, now.Add(-time.Second)); e != nil {
		t.Fatal("older report", e)
	}
	after, _ = s.Processes(ctx, d.ID)
	if after.Status != "disabled" || len(after.Data.Items) != 1 {
		t.Fatal("clock rollback changed snapshot")
	}
	if e = s.RecordProcesses(ctx, d.ID, "wrong", r, now.Add(2*time.Second)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong identity", e)
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordProcesses(ctx, d.ID, d.Fingerprint, r, now.Add(2*time.Second)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("revoked write", e)
	}
}
