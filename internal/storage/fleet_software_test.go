package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
)

func TestFleetSoftwareScopeFiltersAndRetainedEvidence(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab", Tags: []string{"test"}}, now)
	x := app(1, "2.0")
	x.Name, x.Publisher = "Éditeur 100%_literal", "München"
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(x, app(2, "1.0")), now); e != nil {
		t.Fatal(e)
	}
	v := technicianFixture(t, s, now, TechnicianAccess{Groups: []string{"lab"}})
	search := func(v Session, f FleetSoftwareFilter) []FleetSoftwareDevice {
		t.Helper()
		rows, e := s.FleetSoftwareForSession(ctx, v, f)
		if e != nil {
			t.Fatal(e)
		}
		return rows
	}
	for _, f := range []FleetSoftwareFilter{{Query: "ÉDITEUR", Version: "2.", Publisher: "MÜNCHEN", Group: "lab", Tag: "test"}, {Query: "%_"}} {
		rows := search(v, f)
		if len(rows) != 1 || rows[0].Matches != 1 || rows[0].Registrations != 2 || rows[0].GroupName != "Lab" || !rows[0].HasSnapshot || len(rows[0].Examples) != 1 {
			t.Fatal("combined Unicode/literal filters or scoped evidence", rows)
		}
	}
	if rows := search(v, FleetSoftwareFilter{Query: "' OR 1=1 --"}); len(rows) != 1 || rows[0].Matches != 0 {
		t.Fatal("literal query interpreted")
	}
	if rows := search(v, FleetSoftwareFilter{Group: "ungrouped"}); len(rows) != 0 {
		t.Fatal("group filter ignored")
	}
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: software.CapabilityV1, Status: "failed"}, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	rows := search(v, FleetSoftwareFilter{Query: "ÉDITEUR"})
	if rows[0].Status != "failed" || rows[0].Matches != 1 || *rows[0].SnapshotAt != now.Unix() {
		t.Fatal("failure erased retained evidence")
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID}, now)
	if rows := search(v, FleetSoftwareFilter{}); len(rows) != 0 {
		t.Fatal("group membership was cached")
	}
	if rows := search(Session{}, FleetSoftwareFilter{}); len(rows) != 1 {
		t.Fatal("owner cannot read")
	}
	if e := s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if rows := search(Session{}, FleetSoftwareFilter{}); len(rows) != 0 {
		t.Fatal("revoked inventory in active fleet")
	}
	for _, f := range []FleetSoftwareFilter{{Query: "\n"}, {Query: strings.Repeat("x", 201)}, {Tag: "a,b"}, {Tag: "UPPER"}, {Group: "bad'"}, {Publisher: " padded"}} {
		if _, e := s.FleetSoftwareForSession(ctx, v, f); !errors.Is(e, ErrFleetSoftware) {
			t.Fatal("invalid filters accepted", f, e)
		}
	}
}

func TestFleetSoftwareBoundsApplyAfterAuthorization(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	tx, e := s.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := range FleetSoftwareDeviceLimit + 1 {
		_, e = tx.Exec(`INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint) VALUES(?,?,'windows','amd64',?,'public',?)`, fmt.Sprintf("%032x", i+1), fmt.Sprintf("hidden-%04d", i), now.Unix(), fmt.Sprint(i))
		if e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if rows, e := s.FleetSoftwareForSession(ctx, v, FleetSoftwareFilter{}); e != nil || len(rows) != 1 {
		t.Fatal("unscoped capacity leaked or hid permitted device", e)
	}
	if _, e = s.FleetSoftwareForSession(ctx, Session{}, FleetSoftwareFilter{}); !errors.Is(e, ErrFleetSoftwareLimit) {
		t.Fatal("oversized fleet silently truncated", e)
	}
	// The byte preflight must reject large inventory before decoding it, and
	// hidden snapshots must not consume the technician's report budget.
	if _, e = s.db.Exec(`DELETE FROM devices WHERE id<>?`, d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`INSERT INTO device_software(device_id,capability_version,last_status,reported_at,snapshot_json,baseline_ready) VALUES(?,1,'ok',?,CAST(zeroblob(?) AS TEXT),1)`, d.ID, now.Unix(), FleetSoftwareByteLimit+1); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FleetSoftwareForSession(ctx, v, FleetSoftwareFilter{}); !errors.Is(e, ErrFleetSoftwareLimit) {
		t.Fatal("byte budget not enforced before decoding", e)
	}
	if rows, e := s.FleetSoftwareForSession(ctx, v, FleetSoftwareFilter{Tag: "missing"}); e != nil || len(rows) != 0 {
		t.Fatal("excluded bytes consume report budget", e)
	}
	if _, e = s.db.Exec(`UPDATE device_software SET snapshot_json='broken'`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FleetSoftwareForSession(ctx, v, FleetSoftwareFilter{}); e == nil {
		t.Fatal("corruption presented as no-match")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.FleetSoftwareForSession(canceled, v, FleetSoftwareFilter{}); e == nil {
		t.Fatal("request cancellation ignored")
	}
}

func TestFleetSoftwareExamplesAreBoundedAndAccountRevisionIsLive(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	entries := []protocol.SoftwareEntry{}
	for i := range 70 {
		entries = append(entries, app(i, "1"))
	}
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(entries...), now); e != nil {
		t.Fatal(e)
	}
	v := technicianFixture(t, s, now, TechnicianAccess{AllDevices: true})
	rows, e := s.FleetSoftwareForSession(ctx, v, FleetSoftwareFilter{})
	if e != nil || len(rows) != 1 || rows[0].Matches != 70 || len(rows[0].Examples) != FleetSoftwareExamples {
		t.Fatal("unbounded/incorrect examples", e)
	}
	if _, e = s.db.Exec(`UPDATE technicians SET revision=revision+1`); e != nil {
		t.Fatal(e)
	}
	if rows, e = s.FleetSoftwareForSession(ctx, v, FleetSoftwareFilter{}); e != nil || len(rows) != 0 {
		t.Fatal("stale technician scope trusted", e)
	}
}

func TestFleetSoftwareDeterministicDeviceOrder(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	if _, e := s.db.Exec(`UPDATE devices SET hostname='z-last-ascii' WHERE id=?`, d.ID); e != nil {
		t.Fatal(e)
	}
	for _, x := range []struct{ id, name string }{{strings.Repeat("b", 32), "Éditeur"}, {strings.Repeat("d", 32), "ALPHA"}, {strings.Repeat("c", 32), "alpha"}} {
		if _, e := s.db.Exec(`INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint) VALUES(?,?,'windows','amd64',?,'public',?)`, x.id, x.name, now.Unix(), x.id); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := s.FleetSoftwareForSession(context.Background(), Session{}, FleetSoftwareFilter{})
	if e != nil || len(rows) != 4 {
		t.Fatal("device order fixture", e)
	}
	for i, id := range []string{strings.Repeat("c", 32), strings.Repeat("d", 32), d.ID, strings.Repeat("b", 32)} {
		if rows[i].Device.ID != id {
			t.Fatal("unstable hostname/ID ordering")
		}
	}
}

// Opt-in performance fixture: representative large payload at the device bound.
// Run with -run '^$' -bench BenchmarkFleetSoftware -benchtime=1x -benchmem.
func BenchmarkFleetSoftware1000Devices(b *testing.B) {
	ctx := context.Background()
	s, e := Open(ctx, b.TempDir()+"/software.db")
	if e != nil {
		b.Fatal(e)
	}
	defer s.Close()
	entries := []protocol.SoftwareEntry{}
	for i := range 48 {
		x := app(i, "2.0-"+strings.Repeat("v", 40))
		x.Name = "Product " + strings.Repeat("N", 400)
		x.Publisher = "Publisher " + strings.Repeat("P", 250)
		entries = append(entries, x)
	}
	raw, e := json.Marshal(protocol.Software{Coverage: software.Coverage, Entries: entries})
	if e != nil {
		b.Fatal(e)
	}
	if len(raw)*FleetSoftwareDeviceLimit > FleetSoftwareByteLimit {
		b.Fatal("fixture exceeds byte budget")
	}
	tx, e := s.db.Begin()
	if e != nil {
		b.Fatal(e)
	}
	for i := range FleetSoftwareDeviceLimit {
		id := fmt.Sprintf("%032x", i+1)
		if _, e = tx.Exec(`INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint) VALUES(?,?,'windows','amd64',1,'public',?)`, id, id, id); e != nil {
			tx.Rollback()
			b.Fatal(e)
		}
		if _, e = tx.Exec(`INSERT INTO device_software(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at,baseline_ready) VALUES(?,1,'ok',1,?,1,1)`, id, string(raw)); e != nil {
			tx.Rollback()
			b.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		b.Fatal(e)
	}
	b.SetBytes(int64(len(raw) * FleetSoftwareDeviceLimit))
	b.ResetTimer()
	for range b.N {
		rows, e := s.FleetSoftwareForSession(ctx, Session{}, FleetSoftwareFilter{Query: "PRODUCT", Publisher: "PUBLISHER"})
		if e != nil || len(rows) != FleetSoftwareDeviceLimit || rows[0].Matches != 48 || len(rows[0].Examples) != FleetSoftwareExamples {
			b.Fatal("bounded fleet search", e)
		}
	}
}
