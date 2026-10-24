package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
)

func organizationApply(t *testing.T, s *Store, c OrganizationChange, now time.Time) OrganizationReview {
	t.Helper()
	ctx := context.Background()
	o, e := s.Organization(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c.Revision = o.Revision
	review, e := s.ChangeOrganization(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	after, e := s.Organization(ctx)
	if e != nil || !reflect.DeepEqual(o, after) {
		t.Fatal("preview changed persistent state", e)
	}
	if _, e = s.ChangeOrganization(ctx, c, "admin", review.Digest, now); e != nil {
		t.Fatal(e)
	}
	return review
}
func organizationRead(t *testing.T, s *Store) Organization {
	t.Helper()
	o, e := s.Organization(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func clonePolicy(o Organization, id string, threshold int) OrganizationChange {
	rs := append([]alerting.Rule(nil), o.Defaults...)
	for i := range rs {
		if rs[i].Kind == "cpu" {
			rs[i].Threshold = threshold
		}
	}
	return OrganizationChange{Action: "policy-create", ID: id, Name: id, Rules: rs}
}
func TestOrganizationInheritanceTaggingAndDeletion(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	organizationApply(t, s, clonePolicy(organizationRead(t, s), "servers", 80), now)
	organizationApply(t, s, clonePolicy(organizationRead(t, s), "override", 70), now)
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab", PolicyID: "servers"}, now)
	change := OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab", Tags: []string{"production", "windows"}}
	review := organizationApply(t, s, change, now)
	if len(review.Impacts) != 1 || !reflect.DeepEqual(review.Impacts[0].Kinds, []string{"cpu"}) {
		t.Fatal("incorrect affected rules", review)
	}
	o := organizationRead(t, s)
	rs, source := o.Effective(o.Devices[0])
	if ruleByKind(rs, "cpu").Threshold != 80 || source != "Group policy: servers" {
		t.Fatal("group inheritance", source)
	}
	change.PolicyID = "override"
	organizationApply(t, s, change, now)
	o = organizationRead(t, s)
	rs, source = o.Effective(o.Devices[0])
	if ruleByKind(rs, "cpu").Threshold != 70 || source != "Device policy: override" {
		t.Fatal("override precedence")
	}
	review = organizationApply(t, s, OrganizationChange{Action: "group-save", ID: "lab", Name: "Renamed", PolicyID: ""}, now)
	if len(review.Impacts) != 0 {
		t.Fatal("overridden device reset by group edit")
	}
	change.PolicyID = ""
	review = organizationApply(t, s, change, now)
	if len(review.Impacts) != 1 || review.Impacts[0].After != "Global defaults" {
		t.Fatal("fallback missing")
	}
	o = organizationRead(t, s)
	for _, c := range []OrganizationChange{{Action: "group-delete", ID: "lab"}, {Action: "device", ID: d.ID, GroupID: "missing"}, {Action: "device", ID: strings.Repeat("f", 32)}} {
		c.Revision = o.Revision
		if _, e := s.ChangeOrganization(ctx, c, "admin", "", now); !errors.Is(e, ErrOrganization) {
			t.Fatal("invalid mutation accepted", c, e)
		}
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID}, now)
	organizationApply(t, s, OrganizationChange{Action: "group-delete", ID: "lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "policy-delete", ID: "servers"}, now)
	organizationApply(t, s, OrganizationChange{Action: "policy-delete", ID: "override"}, now)
	o = organizationRead(t, s)
	if len(o.Groups) != 0 || len(o.Policies) != 0 {
		t.Fatal("deletion failed")
	}
}

func TestOrganizationReviewRejectsTamperStaleRevocationAndConcurrentApply(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	o := organizationRead(t, s)
	c := OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab", Revision: o.Revision}
	review, e := s.ChangeOrganization(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	tampered := c
	tampered.Name = "Other"
	if _, e = s.ChangeOrganization(ctx, tampered, "admin", review.Digest, now); !errors.Is(e, ErrOrganization) {
		t.Fatal("tampered form accepted")
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeOrganization(ctx, c, "admin", review.Digest, now); !errors.Is(e, ErrOrganization) {
		t.Fatal("changed fleet accepted")
	}
	review, e = s.ChangeOrganization(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	success := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.ChangeOrganization(ctx, c, "admin", review.Digest, now)
			success <- e == nil
		}()
	}
	wg.Wait()
	close(success)
	count := 0
	for v := range success {
		if v {
			count++
		}
	}
	if count != 1 {
		t.Fatal("review replay committed", count)
	}
	o = organizationRead(t, s)
	c = OrganizationChange{Action: "group-save", ID: "lab", Name: "Changed", Revision: o.Revision}
	review, e = s.ChangeOrganization(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	r := o.Defaults[0]
	r.Enabled = !r.Enabled
	if e = s.SaveAlertRule(ctx, r, "admin", now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeOrganization(ctx, c, "admin", review.Digest, now); !errors.Is(e, ErrOrganization) {
		t.Fatal("stale global defaults accepted")
	}
}

func TestOrganizationEffectiveRuleChangesPreserveOtherIncidentsAndMail(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	original := alertsFor(t, s, d.ID)[0]
	// Copying unchanged defaults into a group must not lose an existing incident.
	o := organizationRead(t, s)
	organizationApply(t, s, clonePolicy(o, "servers", 90), now)
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab", PolicyID: "servers"}, now)
	review := organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab"}, now)
	if len(review.Impacts) != 0 {
		t.Fatal("equal rule settings reset incident")
	}
	// Disabling global CPU mail and monitoring must not affect a policy device.
	o = organizationRead(t, s)
	r := ruleByKind(o.Defaults, "cpu")
	r.Revision = 2
	r.Enabled = false
	r.Email = false
	if e := s.SaveAlertRule(ctx, r, "admin", now); e != nil {
		t.Fatal(e)
	}
	if a := alertsFor(t, s, d.ID); len(a) != 1 || a[0].ID != original.ID || a[0].Status != "active" {
		t.Fatal("global edit closed overridden incident")
	}
	id, _, e := s.ClaimAlertMail(ctx, "test-mail", now)
	if e != nil || id == 0 {
		t.Fatal("mail used global rules instead of effective policy", e)
	}
	o = organizationRead(t, s)
	p := o.Policies[0]
	p.Rules = append([]alerting.Rule(nil), p.Rules...)
	for i := range p.Rules {
		if p.Rules[i].Kind == "memory" {
			p.Rules[i].Threshold = 80
		}
	}
	review = organizationApply(t, s, OrganizationChange{Action: "policy-save", ID: p.ID, Name: p.Name, Rules: p.Rules}, now)
	if len(review.Impacts) != 1 || !reflect.DeepEqual(review.Impacts[0].Kinds, []string{"memory"}) {
		t.Fatal("unrelated rules restarted")
	}
	if a := alertsFor(t, s, d.ID); a[0].Status != "active" {
		t.Fatal("memory edit closed CPU incident")
	}
	// Tags and display-name edits preserve qualification.
	review = organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab", Tags: []string{"windows"}}, now)
	if len(review.Impacts) != 0 {
		t.Fatal("tags changed monitoring")
	}
	for i := range p.Rules {
		if p.Rules[i].Kind == "cpu" {
			p.Rules[i].Enabled = false
		}
	}
	review = organizationApply(t, s, OrganizationChange{Action: "policy-save", ID: p.ID, Name: p.Name, Rules: p.Rules}, now)
	if len(review.Impacts) != 1 || !reflect.DeepEqual(review.Impacts[0].Kinds, []string{"cpu"}) {
		t.Fatal("wrong reset")
	}
	a := alertsFor(t, s, d.ID)[0]
	if a.Status != "closed" || a.CloseReason != "policy_changed" {
		t.Fatal("incident not closed as policy change", a)
	}
	var n int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM alert_states WHERE device_id=? AND kind='cpu'", d.ID).Scan(&n); e != nil || n != 0 {
		t.Fatal("old qualification retained")
	}
}

func TestOrganizationPolicyEvaluationAndQueuedSampleReset(t *testing.T) {
	s, d, now := alertFixture(t)
	ctx := context.Background()
	o := organizationRead(t, s)
	organizationApply(t, s, clonePolicy(o, "sensitive", 50), now)
	cpuReading(t, s, d, now, 70, "ok") // Must not qualify using a pre-assignment sample.
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, PolicyID: "sensitive"}, now)
	sweep(t, s, now)
	if len(alertsFor(t, s, d.ID)) != 0 {
		t.Fatal("assignment replayed old observations")
	}
	cpuReading(t, s, d, now.Add(time.Second), 70, "ok")
	sweep(t, s, now.Add(time.Second))
	for sec := 16; sec < 61; sec += 15 {
		sweep(t, s, now.Add(time.Duration(sec)*time.Second))
	}
	cpuReading(t, s, d, now.Add(61*time.Second), 70, "ok")
	sweep(t, s, now.Add(61*time.Second))
	a := alertsFor(t, s, d.ID)
	if len(a) != 1 || a[0].Threshold != 50 {
		t.Fatal("evaluator did not select policy threshold", a)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID}, now.Add(62*time.Second))
	mail, e := s.AlertDeliveries(ctx, d.ID)
	if e != nil || len(mail) != 1 || mail[0].Status != "cancelled" || mail[0].Reason != "policy_changed" {
		t.Fatal("queued old-policy notice survived", mail, e)
	}
}

func TestOrganizationBoundsAndCanonicalTags(t *testing.T) {
	tags, e := ParseDeviceTags(" Windows,production, WINDOWS, ssd.nvme ")
	if e != nil || strings.Join(tags, ",") != "production,ssd.nvme,windows" {
		t.Fatal(tags, e)
	}
	for _, raw := range []string{"a,,b", ".tag", "bad tag", "<script>", strings.Repeat("x", 33), "æ—¥æœ¬èªž"} {
		if _, e := ParseDeviceTags(raw); e == nil {
			t.Fatal("invalid tags", raw)
		}
	}
	raw := []string{}
	for i := 0; i < 17; i++ {
		raw = append(raw, fmt.Sprintf("tag%d", i))
	}
	if _, e := ParseDeviceTags(strings.Join(raw, ",")); e == nil {
		t.Fatal("tag count unbounded")
	}
	for _, id := range []string{"new", "ungrouped", "_bad", "1bad", "UPPER", "x/y", strings.Repeat("x", 33)} {
		if ValidOrganizationID(id) {
			t.Fatal("invalid ID accepted")
		}
	}
	s, _, now := actionFixture(t)
	o := organizationRead(t, s)
	ctx := context.Background()
	for _, c := range []OrganizationChange{{Action: "group-create", ID: "lab", Name: "bad\nname"}, {Action: "policy-create", ID: "broken", Name: "Broken", Rules: o.Defaults[:3]}, {Action: "policy-create", ID: "duplicate", Name: "Duplicate", Rules: []alerting.Rule{o.Defaults[0], o.Defaults[0], o.Defaults[2], o.Defaults[3]}}} {
		c.Revision = o.Revision
		if _, e := s.ChangeOrganization(ctx, c, "admin", "", now); !errors.Is(e, ErrOrganization) {
			t.Fatal("invalid configuration accepted", e)
		}
	}
}

func TestOrganizationMigrationPreservesExistingStateAndReopens(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "server.db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, e := s.Info(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Reconstruct schema 18 with its real migration hashes.
	rollbackHealthSchema(t, s)
	for _, query := range []string{"DROP INDEX sessions_technician", "ALTER TABLE sessions DROP COLUMN technician_id", "DROP TABLE technician_recovery_codes", "DROP TABLE technicians", "DELETE FROM schema_migrations WHERE version=19"} {
		if _, e = s.db.Exec(query); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal("upgrade failed", e)
	}
	after, e := s.Info(ctx)
	if e != nil || before != after {
		t.Fatal("installation identity changed", e)
	}
	organizationApply(t, s, clonePolicy(organizationRead(t, s), "servers", 70), time.Now())
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab", PolicyID: "servers"}, time.Now())
	expected := organizationRead(t, s)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if got := organizationRead(t, s); !reflect.DeepEqual(expected, got) {
		t.Fatal("organization lost on restart")
	}
}

func TestOrganizationAuditFailureRollsBackAndBoundsCapacity(t *testing.T) {
	s, _, now := actionFixture(t)
	ctx := context.Background()
	before := organizationRead(t, s)
	c := OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab", Revision: before.Revision}
	review, e := s.ChangeOrganization(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER fail_organization_audit BEFORE INSERT ON audit_events WHEN NEW.action LIKE 'organization_%' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeOrganization(ctx, c, "admin", review.Digest, now); e == nil {
		t.Fatal("unaudited mutation committed")
	}
	if got := organizationRead(t, s); !reflect.DeepEqual(before, got) {
		t.Fatal("audit failure left partial state")
	}
	if _, e = s.db.Exec("DROP TRIGGER fail_organization_audit"); e != nil {
		t.Fatal(e)
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(before.Defaults)
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("item%d", i)
		if _, e = tx.Exec("INSERT INTO device_groups VALUES(?,?,NULL)", id, id); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec("INSERT INTO monitoring_policies(id,name,rules_json) VALUES(?,?,?)", id, id, string(raw)); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []OrganizationChange{c, clonePolicy(before, "extra", 70)} {
		change.Revision = before.Revision
		if _, e = s.ChangeOrganization(ctx, change, "admin", "", now); !errors.Is(e, ErrOrganization) {
			t.Fatal("capacity limit ignored", e)
		}
	}
}

func TestOrganizationBulkDevices(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	other := Device{ID: strings.Repeat("b", 32), Hostname: "second", OS: "windows", Architecture: "amd64", Certificate: "public", Fingerprint: "fp-b"}
	if e := s.NewEnrollmentToken(ctx, "bulk-token", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "bulk-token", other, now); e != nil {
		t.Fatal(e)
	}
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, Tags: []string{"keep", "old"}}, now)
	organizationApply(t, s, OrganizationChange{Action: "devices", Devices: []string{d.ID, other.ID}, SetGroup: true, GroupID: "lab", AddTags: []string{"new"}, RemoveTags: []string{"old"}}, now)
	o := organizationRead(t, s)
	for _, v := range o.Devices {
		want := []string{"new"}
		if v.ID == d.ID {
			want = []string{"keep", "new"}
		}
		if v.GroupID != "lab" || v.PolicyID != "" || !reflect.DeepEqual(v.Tags, want) {
			t.Fatal("bulk result", v)
		}
	}
	// Policy left untouched unless requested; ungrouping is explicit.
	organizationApply(t, s, OrganizationChange{Action: "devices", Devices: []string{other.ID}, SetGroup: true}, now)
	if o = organizationRead(t, s); o.Groups[0].Members != 1 {
		t.Fatal("ungroup", o.Groups)
	}
	for _, c := range []OrganizationChange{
		{Action: "devices", Devices: []string{d.ID}},
		{Action: "devices", Devices: []string{d.ID, d.ID}, AddTags: []string{"x"}},
		{Action: "devices", Devices: []string{strings.Repeat("f", 32)}, AddTags: []string{"x"}},
		{Action: "devices", Devices: []string{d.ID}, SetGroup: true, GroupID: "missing"},
		{Action: "devices", Devices: []string{d.ID}, SetPolicy: true, PolicyID: "missing"},
		{Action: "devices", Devices: []string{d.ID}, AddTags: []string{"x"}, RemoveTags: []string{"x"}},
		{Action: "devices", Devices: []string{d.ID}, AddTags: []string{"Bad Tag"}},
		{Action: "devices", Devices: []string{}, AddTags: []string{"x"}},
	} {
		c.Revision = o.Revision
		if _, e := s.ChangeOrganization(ctx, c, "admin", "", now); !errors.Is(e, ErrOrganization) {
			t.Fatal("invalid bulk change accepted", c, e)
		}
	}
	tags := []string{}
	for i := range 17 {
		tags = append(tags, fmt.Sprintf("t%d", i))
	}
	c := OrganizationChange{Action: "devices", Devices: []string{d.ID}, AddTags: tags, Revision: o.Revision}
	if _, e := s.ChangeOrganization(ctx, c, "admin", "", now); !errors.Is(e, ErrOrganization) {
		t.Fatal("tag limit exceeded", e)
	}
}
