package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAlertTriageCountsPaginationAndLiveScope(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	base, e := s.Alerts(ctx, d.ID)
	if e != nil || len(base) != 1 {
		t.Fatal(base, e)
	}
	id := base[0].ID
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab", Tags: []string{"servers"}}, now)
	v := technicianFixture(t, s, now, TechnicianAccess{Groups: []string{"lab"}})
	for i := 0; i < 61; i++ {
		_, e = s.db.Exec(`INSERT INTO alerts(id,device_id,hostname,kind,severity,threshold,hold_seconds,status,opened_at,last_seen,finished_at) VALUES(?,?,'literal %_ host','cpu','warning',90,60,'resolved',?,?,?)`, fmt.Sprintf("%032x", i+1), d.ID, now.Unix()-int64(i+100), now.Unix()-int64(i+100), now.Unix())
		if e != nil {
			t.Fatal(e)
		}
	}
	filter := AlertFilter{Page: 1, Group: "lab", Tag: "servers"}
	one, e := s.AlertTriage(ctx, v, filter)
	if e != nil || one.Counts.Matching != 62 || one.Counts.Active != 1 || one.Counts.Unacknowledged != 1 || len(one.Alerts) != 50 || one.Alerts[0].ID != id {
		t.Fatal(one, e)
	}
	filter.Page = 2
	two, e := s.AlertTriage(ctx, v, filter)
	if e != nil || len(two.Alerts) != 12 || two.Counts != one.Counts {
		t.Fatal(two, e)
	}
	seen := map[string]bool{}
	for _, a := range append(one.Alerts, two.Alerts...) {
		if seen[a.ID] {
			t.Fatal("duplicate page result")
		}
		seen[a.ID] = true
	}
	filter.Page = 1
	filter.Query = "%_"
	literal, e := s.AlertTriage(ctx, v, filter)
	if e != nil || literal.Counts.Matching != 61 {
		t.Fatal("wildcards interpreted", literal, e)
	}
	filter.Query = ""
	filter.Status = "active"
	filter.Acknowledgment = "acknowledged"
	empty, e := s.AlertTriage(ctx, v, filter)
	if e != nil || empty.Counts.Matching != 0 {
		t.Fatal(empty, e)
	}
	if e = s.AcknowledgeAlert(ctx, id, "admin", now); e != nil {
		t.Fatal(e)
	}
	ack, e := s.AlertTriage(ctx, v, filter)
	if e != nil || ack.Counts.Matching != 1 || ack.Counts.Unacknowledged != 0 {
		t.Fatal(ack, e)
	}
	a, e := s.AlertIncidentForSession(ctx, v, id)
	if e != nil || a.Status != "active" {
		t.Fatal(a, e)
	}
	mail, e := s.IncidentDeliveriesForSession(ctx, v, id)
	if e != nil || len(mail) != 1 || mail[0].Status != "cancelled" {
		t.Fatal(mail, e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, Tags: []string{}}, now)
	if _, e = s.AlertIncidentForSession(ctx, v, id); !errors.Is(e, ErrAlertNotFound) {
		t.Fatal("removed group retained detail access", e)
	}
	if mail, e = s.IncidentDeliveriesForSession(ctx, v, id); e != nil || len(mail) != 0 {
		t.Fatal("delivery scope leak", mail, e)
	}
	hidden, e := s.AlertTriage(ctx, v, AlertFilter{Page: 1})
	if e != nil || hidden.Counts.Matching != 0 || len(hidden.Alerts) != 0 {
		t.Fatal(hidden, e)
	}
	owner, e := s.AlertTriage(ctx, Session{}, AlertFilter{Page: 1, Group: "ungrouped"})
	if e != nil || owner.Counts.Matching != 62 {
		t.Fatal(owner, e)
	}
}

func TestAlertTriageFiltersValidateAndReadOnly(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	alerts, _ := s.Alerts(ctx, d.ID)
	id := alerts[0].ID
	_, e := s.db.Exec("UPDATE alerts SET kind=?,label='Required service' WHERE id=?", "check:"+strings.Repeat("a", 32), id)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.AlertTriage(ctx, Session{}, AlertFilter{Page: 1, Kind: "health", Severity: "warning"})
	if e != nil || got.Counts.Matching != 1 {
		t.Fatal(got, e)
	}
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	if _, e = s.db.Exec("UPDATE technicians SET revision=revision+1"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.AlertIncidentForSession(ctx, v, id); !errors.Is(e, ErrAlertNotFound) {
		t.Fatal("stale revision detail access", e)
	}
	if page, e := s.AlertTriage(ctx, v, AlertFilter{Page: 1}); e != nil || page.Counts.Matching != 0 {
		t.Fatal("stale revision counts", page, e)
	}
	for _, f := range []AlertFilter{{Page: 0}, {Page: 1001}, {Page: 1, Status: "healthy"}, {Page: 1, Kind: "cpu' OR 1=1"}, {Page: 1, Group: "../lab"}, {Page: 1, Tag: "one,two"}, {Page: 1, Query: "\n"}} {
		if _, e = s.AlertTriage(ctx, Session{}, f); !errors.Is(e, ErrAlert) {
			t.Fatal("invalid filter accepted", f, e)
		}
	}
	_, _ = s.AlertTriage(ctx, Session{}, AlertFilter{Page: 1})
	a, e := s.AlertIncidentForSession(ctx, Session{}, id)
	if e != nil || a.AcknowledgedAt != nil || a.Status != "active" || a.OpenedAt > now.Unix() {
		t.Fatal("read changed incident", a, e)
	}
}
