package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A log search sends an "events" action to every target that can
// run it (others are listed with the reason), waits a week for offline
// devices, does not use up the device's collection slots, and summarises
// stored results for the overview.
func TestLogSearch(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	old := Device{ID: "fedcba9876543210fedcba9876543210", Hostname: "old", OS: "windows", Architecture: "amd64", Certificate: "cert2", Fingerprint: "fp2"}
	if e := s.NewEnrollmentToken(ctx, "t2", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "t2", old, now); e != nil {
		t.Fatal(e)
	}
	support, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "readable"})
	if e := s.RecordEventLogs(ctx, device, "fp", protocol.FeatureReport{Capability: protocol.Capability{Name: "event_logs", Version: 3}, Status: "ok", Data: support}, now); e != nil {
		t.Fatal(e)
	}
	filter := protocol.EventFilter{Channel: "Security", From: now.Add(-time.Hour).Unix(), To: now.Unix(), Level: -1, EventID: 4625, XPath: "*[EventData[Data[@Name='LogonType']='10']]"}
	if _, e := s.StartLogSearch(ctx, LiveCase, []string{"0000000000000000000000000000000f"}, nil, filter, "owner", now); !errors.Is(e, ErrHunt) {
		t.Fatal("unknown device searched", e)
	}
	h, e := s.StartLogSearch(ctx, LiveCase, []string{device, old.ID}, nil, filter, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	if len(h.Targets) != 1 || h.Targets[0].DeviceID != device || len(h.Problems) != 1 || h.Problems[0].DeviceID != old.ID || h.Filter.Limit != protocol.MaxEventPage {
		t.Fatalf("targets %+v problems %+v", h.Targets, h.Problems)
	}
	// The search waits a week and does not take the device's collection
	// slots; other work is handed out before it.
	var queued []string
	for range 2 {
		id, e := s.QueueEvidence(ctx, caseID, device, `C:\x.txt`, "owner", now.Add(time.Second))
		if e != nil {
			t.Fatal("collection blocked by a search", e)
		}
		queued = append(queued, id)
	}
	if d, e := s.DispatchEvidence(ctx, device, "fp", now); e != nil || d.Job == nil || d.Job.Action != nil {
		t.Fatalf("search handed out before a collection %+v %v", d.Job, e)
	}
	for _, id := range queued {
		if e := s.CancelEvidence(ctx, caseID, id, "owner", now); e != nil {
			t.Fatal(e)
		}
	}
	var expires int64
	s.db.QueryRow(`SELECT expires_at FROM evidence_jobs WHERE hunt_id=?`, h.ID).Scan(&expires)
	if expires != now.Add(7*24*time.Hour).Unix() {
		t.Fatal("search wait", expires)
	}
	// The device takes the search first (oldest job) and reports.
	result := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: protocol.ResponseAction{Kind: "events", Events: &h.Filter}, EventLog: &protocol.EventResult{ID: h.Targets[0].JobID, Outcome: "ok", Events: []protocol.WindowsEvent{{RecordID: 9, EventID: 4625, Level: 0, Provider: "Microsoft-Windows-Security-Auditing", Channel: "Security", Time: now.Unix() - 60, MessageStatus: "unavailable"}}, More: true, NextBefore: 9}}
	data, _ := json.Marshal(result)
	job := collect(t, s, device, now, data, &protocol.EvidenceMeta{Method: "action"})
	if job.ID != h.Targets[0].JobID || job.Action == nil || job.Action.Kind != "events" || job.Action.Events.XPath != filter.XPath {
		t.Fatalf("dispatched %+v", job)
	}
	d, e := s.HuntDetail(ctx, h.ID)
	if e != nil || len(d.Targets) != 1 || !d.Targets[0].Result || d.Targets[0].Events != 1 || !d.Targets[0].More || d.Targets[0].Searched != "ok" {
		t.Fatalf("detail %+v %v", d.Targets, e)
	}
	var cached int
	s.db.QueryRow(`SELECT COUNT(*) FROM hunt_results`).Scan(&cached)
	list, _ := s.Hunts(ctx, "owner", false)
	if cached != 1 || len(list) != 1 || list[0].Targets != 1 || list[0].Waiting != 0 || list[0].Problems != 1 || list[0].Channel != "Security" {
		t.Fatalf("list %+v cached %d", list, cached)
	}
	if other, _ := s.Hunts(ctx, "technician:x", false); len(other) != 0 {
		t.Fatal("another account's search listed")
	}
	if c, dev, e := s.HuntJobCase(ctx, h.ID, job.ID); e != nil || c != LiveCase || dev != device {
		t.Fatal("job case", c, dev, e)
	}
	// Cancelling stops jobs still waiting for their device.
	second, e := s.StartLogSearch(ctx, caseID, []string{device}, nil, filter, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	third, e := s.StartLogSearch(ctx, caseID, []string{device}, nil, filter, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CancelHunt(ctx, second.ID, "owner", now); e != nil {
		t.Fatal(e)
	}
	if d, _ = s.HuntDetail(ctx, second.ID); d.CancelledAt == nil || d.Targets[0].Status != "cancelled" {
		t.Fatalf("cancelled %+v", d)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	found := false
	for _, entry := range detail.Entries {
		found = found || entry.Action == "action_requested" && entry.Details["hunt"] == second.ID
	}
	if !found {
		t.Fatal("search not in the case's custody log")
	}
	// Closing the case cancels searches still waiting for their device.
	if e = s.SetCaseStatus(ctx, caseID, "closed", "owner", "", now); e != nil {
		t.Fatal("close with a waiting search", e)
	}
	if d, _ = s.HuntDetail(ctx, third.ID); d.Targets[0].Status != "cancelled" {
		t.Fatalf("waiting search after close %+v", d.Targets)
	}
	// A result too large to count is cached as unreadable, not read again.
	s.db.Exec(`UPDATE evidence_jobs SET size=? WHERE id=?`, 1<<30, job.ID)
	s.db.Exec(`DELETE FROM hunt_results`)
	if d, _ = s.HuntDetail(ctx, h.ID); d.Targets[0].Searched != "unreadable" {
		t.Fatalf("oversized result %+v", d.Targets[0])
	}
}

// A technician's search leaves group members outside their scope
// out silently (nothing about them is returned), and a group with no member
// in scope is unknown.
func TestLogSearchTechnicianScope(t *testing.T) {
	ctx := context.Background()
	s, _, device, now := evidenceFixture(t)
	other := Device{ID: "fedcba9876543210fedcba9876543210", Hostname: "hidden-host", OS: "windows", Architecture: "amd64", Certificate: "cert2", Fingerprint: "fp2"}
	if e := s.NewEnrollmentToken(ctx, "t2", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "t2", other, now); e != nil {
		t.Fatal(e)
	}
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "secret", Name: "Secret"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: device, GroupID: "lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: other.ID, GroupID: "lab"}, now)
	support, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "readable"})
	if e := s.RecordEventLogs(ctx, device, "fp", protocol.FeatureReport{Capability: protocol.Capability{Name: "event_logs", Version: 3}, Status: "ok", Data: support}, now); e != nil {
		t.Fatal(e)
	}
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{device}, Response: true})
	filter := protocol.EventFilter{Channel: "Security", From: now.Add(-time.Hour).Unix(), To: now.Unix(), Level: -1, EventID: -1}
	h, e := s.StartLogSearch(ctx, LiveCase, nil, []string{"lab"}, filter, v.Actor(), now)
	if e != nil || len(h.Targets) != 1 || h.Targets[0].DeviceID != device || len(h.Problems) != 0 {
		t.Fatalf("group search %+v %v", h, e)
	}
	b, _ := json.Marshal(h)
	if strings.Contains(string(b), "hidden-host") || strings.Contains(string(b), other.ID) {
		t.Fatal("out-of-scope device disclosed")
	}
	if _, e = s.StartLogSearch(ctx, LiveCase, nil, []string{"secret"}, filter, v.Actor(), now); !errors.Is(e, ErrHunt) {
		t.Fatal("group without a member in scope", e)
	}
	if _, e = s.StartLogSearch(ctx, LiveCase, []string{other.ID}, nil, filter, v.Actor(), now); !errors.Is(e, ErrHunt) {
		t.Fatal("out-of-scope device searched", e)
	}
}
