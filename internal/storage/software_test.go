package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
)

func softwareFixture(t *testing.T) (*Store, Device, time.Time, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "db")
	s, e := Open(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Unix(1800000000, 0)
	d := Device{ID: strings.Repeat("a", 32), Hostname: "software", OS: "windows", Architecture: "amd64", Certificate: "public", Fingerprint: "software-fingerprint"}
	if e = s.NewEnrollmentToken(context.Background(), "software-token", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.EnrollDevice(context.Background(), "software-token", d, now); e != nil {
		t.Fatal(e)
	}
	return s, d, now, path
}
func app(id int, version string) protocol.SoftwareEntry {
	return protocol.SoftwareEntry{ID: fmt.Sprintf("%064x", id), View: "64", Name: "Example", Version: version, Publisher: "Publisher"}
}
func softwareReport(entries ...protocol.SoftwareEntry) protocol.FeatureReport {
	if entries == nil {
		entries = []protocol.SoftwareEntry{}
	}
	b, _ := json.Marshal(protocol.Software{Coverage: software.Coverage, Entries: entries})
	return protocol.FeatureReport{Capability: software.CapabilityV1, Status: "ok", Data: b}
}
func TestSoftwareHistoryAtomicRetryFailureAndReopen(t *testing.T) {
	s, d, now, path := softwareFixture(t)
	ctx := context.Background()
	record := func(r protocol.FeatureReport, offset int) {
		t.Helper()
		if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, r, now.Add(time.Duration(offset)*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	record(softwareReport(app(1, "1"), app(2, "1")), 0)
	h, e := s.SoftwareHistory(ctx, d.ID, now)
	if e != nil || len(h) != 0 {
		t.Fatal("baseline invented installs")
	}
	record(protocol.FeatureReport{Capability: software.CapabilityV1, Status: "failed"}, 5)
	value, _ := s.Software(ctx, d.ID)
	if value.Data == nil || len(value.Data.Entries) != 2 || value.Status != "failed" {
		t.Fatal("failed report erased baseline")
	}
	next := softwareReport(app(1, "2"), app(3, "1"))
	record(next, 10)
	record(next, 11)
	h, e = s.SoftwareHistory(ctx, d.ID, now.Add(time.Minute))
	if e != nil || len(h) != 3 {
		t.Fatal("changes or retry deduplication failed", e, len(h))
	}
	kinds := map[string]bool{}
	for _, c := range h {
		if c.FromAt != now.Unix() || c.ObservedAt != now.Unix()+10 {
			t.Fatal("change timing invented")
		}
		kinds[c.Kind] = true
	}
	if !kinds["added"] || !kinds["removed"] || !kinds["version_changed"] {
		t.Fatal("missing differences")
	}
	record(softwareReport(app(9, "wrong")), 1) // wall-clock rollback cannot replace newer state.
	after, _ := s.Software(ctx, d.ID)
	if after.Data.Entries[0].Version != "2" {
		t.Fatal("clock rollback overwrote newer snapshot")
	}
	if e = s.RecordSoftware(ctx, d.ID, "wrong", next, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("another fingerprint wrote software")
	}
	// Failed transaction must never leave history ahead of its snapshot.
	if _, e = s.db.Exec(`CREATE TRIGGER fail_software BEFORE UPDATE ON device_software BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(app(1, "3")), now.Add(time.Minute)); e == nil {
		t.Fatal("failed snapshot committed")
	}
	h, _ = s.SoftwareHistory(ctx, d.ID, now)
	if len(h) != 3 {
		t.Fatal("history escaped failed transaction")
	}
	s.db.Exec(`DROP TRIGGER fail_software`)
	s.Close()
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, e = s.Software(ctx, d.ID)
	if e != nil || after.Data == nil || !after.BaselineReady || after.Data.Entries[0].Version != "2" {
		t.Fatal("snapshot did not survive reopen")
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordSoftware(ctx, d.ID, d.Fingerprint, next, now.Add(time.Minute)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("revoked device wrote software")
	}
}
func TestSoftwareConcurrentRetriesAndRetention(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	first := softwareReport(app(1, "1"))
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, first, now); e != nil {
		t.Fatal(e)
	}
	next := softwareReport(app(1, "2"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, next, now.Add(time.Second)); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	h, _ := s.SoftwareHistory(ctx, d.ID, now)
	if len(h) != 1 {
		t.Fatal("concurrent retry duplicated history")
	}
	for i := range SoftwareHistoryLimit + 5 {
		if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(app(1, fmt.Sprint(i+10))), now.Add(time.Duration(i+2)*time.Second)); e != nil {
			t.Fatal(e)
		}
	}
	h, e := s.SoftwareHistory(ctx, d.ID, now.Add(time.Hour))
	if e != nil || len(h) != SoftwareHistoryLimit {
		t.Fatal("history not bounded", e, len(h))
	}
	if e = s.PruneSoftwareHistory(ctx, now.Add((SoftwareHistoryDays+1)*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	h, _ = s.SoftwareHistory(ctx, d.ID, now)
	if len(h) != 0 {
		t.Fatal("expired history retained")
	}
}
func TestSoftwareMetadataEmptyAndRestoreBaseline(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(), now); e != nil {
		t.Fatal(e)
	}
	x := app(1, "1")
	s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(x), now.Add(time.Second))
	x.Publisher = "Changed"
	s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(x), now.Add(2*time.Second))
	h, e := s.SoftwareHistory(ctx, d.ID, now)
	if e != nil || len(h) != 2 || h[0].Kind != "metadata_changed" {
		t.Fatal("metadata change absent")
	}
	s.db.Exec(`DELETE FROM software_changes`)
	s.db.Exec(`UPDATE device_software SET baseline_ready=0,last_status='failed'`)
	if e = s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(app(2, "new")), now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	h, _ = s.SoftwareHistory(ctx, d.ID, now)
	if len(h) != 0 {
		t.Fatal("restore baseline invented changes")
	}
}

func TestSoftwareGlobalHistoryCap(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	// Prepare legitimate per-device histories in a single fixture transaction;
	// then exercise the public report path's shared retention enforcement.
	for i := range 26 {
		other := d
		other.ID = fmt.Sprintf("%032x", i+1)
		other.Fingerprint = fmt.Sprint("history-fingerprint-", i)
		token := fmt.Sprint("history-token-", i)
		if e := s.NewEnrollmentToken(ctx, token, now, now.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
		if e := s.EnrollDevice(ctx, token, other, now); e != nil {
			t.Fatal(e)
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	for i := range 26 {
		for range SoftwareHistoryLimit {
			if _, e = tx.Exec(`INSERT INTO software_changes(device_id,from_at,observed_at,kind,before_json,after_json) VALUES(?,?,?,'added','null',?)`, fmt.Sprintf("%032x", i+1), now.Unix()-1, now.Unix(), `{"id":"`+strings.Repeat("1", 64)+`","registry_view":"64","name":"Example","version":"1","publisher":""}`); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(app(1, "1")), now); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = s.db.QueryRow(`SELECT COUNT(*) FROM software_changes`).Scan(&count); e != nil || count != softwareGlobalHistoryLimit {
		t.Fatal("shared history bound failed", e, count)
	}
}

func TestSoftwareDifferencesWithSkippedEntries(t *testing.T) {
	e := func(i int) protocol.SoftwareEntry {
		return protocol.SoftwareEntry{ID: fmt.Sprintf("%064x", i), View: "64", Name: fmt.Sprint("App ", i)}
	}
	kinds := func(old, next protocol.Software) string {
		var out []string
		for _, c := range softwareDifferences(old, next, 1, 2) {
			out = append(out, c.Kind)
		}
		return strings.Join(out, ",")
	}
	a := protocol.Software{Coverage: software.Coverage, Entries: []protocol.SoftwareEntry{e(1), e(2)}}
	// Entry 2 became unreadable: not a removal; the new entry 3 is still added.
	b := protocol.Software{Coverage: software.Coverage, Entries: []protocol.SoftwareEntry{e(1), e(3)}, Skipped: 1}
	if got := kinds(a, b); got != "added" {
		t.Fatal("ambiguous removal recorded", got)
	}
	// Entry 2 became readable again: not an addition; entry 3 really left.
	if got := kinds(b, a); got != "removed" {
		t.Fatal("ambiguous addition recorded", got)
	}
	// A persistently skipped registration does not hide ordinary history.
	c := protocol.Software{Coverage: software.Coverage, Entries: []protocol.SoftwareEntry{e(1)}, Skipped: 1}
	if got := kinds(b, c); got != "removed" {
		t.Fatal("history lost with unchanged skip count", got)
	}
}
func TestSkippedCountsArePersisted(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	b, _ := json.Marshal(protocol.Software{Coverage: software.Coverage, Entries: []protocol.SoftwareEntry{app(1, "1")}, Skipped: 3})
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: software.CapabilityV1, Status: "ok", Data: b}, now); e != nil {
		t.Fatal(e)
	}
	inv, e := s.Software(ctx, d.ID)
	if e != nil || inv.Data == nil || inv.Data.Skipped != 3 {
		t.Fatal("software skip count not stored", e)
	}
	b, _ = json.Marshal(protocol.Processes{Coverage: processes.Coverage, Items: []protocol.Process{{PID: 100, Name: "fixture.exe"}}, Skipped: 9})
	if e = s.RecordProcesses(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: processes.Capability, Status: "ok", Data: b}, now); e != nil {
		t.Fatal(e)
	}
	ps, e := s.Processes(ctx, d.ID)
	if e != nil || ps.Data == nil || ps.Data.Skipped != 9 {
		t.Fatal("process skip count not stored", e)
	}
}

// Per-user registrations change history only while their user's
// hive was read in both reports; signing out and in records nothing, and an
// upgrade from version 1 adds no per-user "added" noise.
func TestPerUserSoftwareHistory(t *testing.T) {
	s, d, now, _ := softwareFixture(t)
	ctx := context.Background()
	sid := "S-1-5-21-1-2-3-1001"
	alice := []protocol.SoftwareUser{{SID: sid, Name: `PC\alice`}}
	mine := func(id int, version string) protocol.SoftwareEntry {
		return protocol.SoftwareEntry{ID: fmt.Sprintf("%064x", 1000+id), View: "user", Name: "Per-user", Version: version, User: `PC\alice`, UserSID: sid}
	}
	step := 0
	send := func(users []protocol.SoftwareUser, entries ...protocol.SoftwareEntry) {
		t.Helper()
		step++
		b, _ := json.Marshal(protocol.Software{Coverage: software.CoverageUsers, Entries: append([]protocol.SoftwareEntry{}, entries...), Users: users})
		if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: software.Capability, Status: "ok", Data: b}, now.Add(time.Duration(step)*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, softwareReport(app(1, "1")), now); e != nil {
		t.Fatal(e)
	}
	send(alice, app(1, "1"), mine(1, "1")) // upgrade: alice's apps are not "added"
	send(nil, app(1, "1"))                 // alice signed out
	send(alice, app(1, "1"), mine(1, "1")) // signed in again
	send(alice, app(1, "1"), mine(1, "2")) // updated while signed in
	send(alice, app(1, "1"), mine(2, "1")) // replaced while signed in
	h, e := s.SoftwareHistory(ctx, d.ID, now.Add(time.Hour))
	if e != nil || len(h) != 3 {
		t.Fatalf("history %+v %v", h, e)
	}
	kinds := map[string]int{}
	for _, c := range h {
		kinds[c.Kind]++
	}
	if kinds["version_changed"] != 1 || kinds["added"] != 1 || kinds["removed"] != 1 {
		t.Fatalf("kinds %v", kinds)
	}
	v, e := s.Software(ctx, d.ID)
	if e != nil || v.Data == nil || len(v.Data.Entries) != 2 || len(v.Data.Users) != 1 {
		t.Fatalf("snapshot %+v %v", v.Data, e)
	}
	// A renamed account is no change; a per-user entry that became unreadable
	// (per-user skip count up) is no removal, and a machine-wide removal in
	// the same report is still recorded.
	renamed := mine(2, "1")
	renamed.User = `PC\alice2`
	send([]protocol.SoftwareUser{{SID: sid, Name: `PC\alice2`}}, app(1, "1"), renamed)
	step++
	b, _ := json.Marshal(protocol.Software{Coverage: software.CoverageUsers, Entries: []protocol.SoftwareEntry{}, Users: alice, UserSkipped: 1})
	if e := s.RecordSoftware(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: software.Capability, Status: "ok", Data: b}, now.Add(time.Duration(step)*time.Minute)); e != nil {
		t.Fatal(e)
	}
	h, e = s.SoftwareHistory(ctx, d.ID, now.Add(time.Hour))
	if e != nil || len(h) != 4 || h[0].Kind != "removed" || h[0].Before == nil || h[0].Before.View != "64" {
		t.Fatalf("after rename and skip %+v %v", h, e)
	}
}
