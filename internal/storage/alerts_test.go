package storage

import (
	"context"
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"testing"
	"time"
)

func alertFixture(t *testing.T) (*Store, Device, time.Time) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	if e := s.InitializeAlerts(ctx, 120*time.Second, "test-mail", now); e != nil {
		t.Fatal(e)
	}
	rs, e := s.AlertRules(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range rs {
		r.HoldSeconds = 60
		r.RecoverySeconds = 60
		r.Email = true
		if e = s.SaveAlertRule(ctx, r, "admin", now); e != nil {
			t.Fatal(e)
		}
	}
	return s, d, now
}

func TestMetricAlertThresholdBoundariesAndUnavailableData(t *testing.T) {
	at := int64(1800000000)
	contact := at
	for _, c := range []struct {
		kind string
		data any
		want string
	}{
		{"disk_space", protocol.DiskSpace{Drive: "C:\\", TotalBytes: 1000, AvailableBytes: 100}, "good"},
		{"disk_space", protocol.DiskSpace{Drive: "C:\\", TotalBytes: 1000, AvailableBytes: 99}, "bad"},
		{"memory", protocol.Memory{TotalBytes: 1000, AvailableBytes: 100}, "bad"},
		{"memory", protocol.Memory{TotalBytes: 1000, AvailableBytes: 101}, "good"},
	} {
		raw, _ := json.Marshal(c.data)
		threshold := 90
		if c.kind == "disk_space" {
			threshold = 10
		}
		r := alerting.Rule{Kind: c.kind, Threshold: threshold}
		v := alertSample{kind: c.kind, status: "ok", data: string(raw), at: at, contact: &contact}
		if got := sampleObservation(v, r, 120); got.Condition != c.want {
			t.Fatal("threshold boundary", c.kind, got.Condition)
		}
		v.status = "disabled"
		if got := sampleObservation(v, r, 120); got.Condition != "unknown" {
			t.Fatal("retained snapshot cleared alert")
		}
	}
}

func TestObservationOverflowDoesNotResolveAnActiveIncident(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	before := alertsFor(t, s, d.ID)[0]
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10001; i++ {
		if _, e = tx.Exec("INSERT INTO alert_samples(device_id,kind,status,data,received_at,contact_at) VALUES(?,'memory','failed','',?,?)", d.ID, now.Unix(), now.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	r, e := s.AlertRuntime(ctx)
	if e != nil || r.PendingSamples != 10000 || r.LastGap != now.Unix() {
		t.Fatal("queue bound or gap reporting failed", r, e)
	}
	sweep(t, s, now)
	after := alertsFor(t, s, d.ID)
	if len(after) != 1 || after[0].ID != before.ID || after[0].Status != "active" {
		t.Fatal("dropped readings fabricated recovery")
	}
}
func cpuReading(t *testing.T, s *Store, d Device, at time.Time, usage float64, status string) {
	t.Helper()
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test"}, at); e != nil {
		t.Fatal(e)
	}
	p := protocol.FeatureReport{Capability: cpu.Capability, Status: status}
	if status == "ok" {
		p.Data, _ = json.Marshal(protocol.CPU{UsagePercent: usage, SampleMilliseconds: 1000})
	}
	if e := s.RecordCPU(ctx, d.ID, d.Fingerprint, p, at); e != nil {
		t.Fatal(e)
	}
}
func sweep(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	if e := s.EvaluateAlerts(context.Background(), at); e != nil {
		t.Fatal(e)
	}
}
func alertsFor(t *testing.T, s *Store, id string) []Alert {
	t.Helper()
	a, e := s.Alerts(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestAlertLifecycleAcknowledgmentEmailAndUnknown(t *testing.T) {
	s, d, now := alertFixture(t)
	ctx := context.Background()
	cpuReading(t, s, d, now, 95, "ok")
	sweep(t, s, now)
	// Keep the evaluator alive while only one cached sample exists.
	for sec := 15; sec < 60; sec += 15 {
		sweep(t, s, now.Add(time.Duration(sec)*time.Second))
	}
	if len(alertsFor(t, s, d.ID)) != 0 {
		t.Fatal("cached metric caused alert")
	}
	cpuReading(t, s, d, now.Add(time.Minute), 90, "ok")
	sweep(t, s, now.Add(time.Minute))
	a := alertsFor(t, s, d.ID)
	if len(a) != 1 || a[0].Kind != "cpu" || a[0].Status != "active" {
		t.Fatal("CPU alert did not fire", a)
	}
	id, n, e := s.ClaimAlertMail(ctx, "test-mail", now.Add(time.Minute))
	if e != nil || id == 0 || n.Event != "opened" {
		t.Fatal("opening email missing", e)
	}
	if e = s.FinishAlertMail(ctx, id, alerting.MailResult{Status: "sent", Reason: "accepted"}, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = s.AcknowledgeAlert(ctx, a[0].ID, "admin", now.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	cpuReading(t, s, d, now.Add(75*time.Second), 0, "disabled")
	sweep(t, s, now.Add(75*time.Second))
	a = alertsFor(t, s, d.ID)
	if a[0].Status != "active" || a[0].AcknowledgedAt == nil {
		t.Fatal("disabled reading cleared alert")
	}
	states, e := s.AlertStates(ctx, d.ID)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range states {
		if v.Kind == "cpu" && v.Condition != "unknown" {
			t.Fatal("disabled not unknown")
		}
	}
	cpuReading(t, s, d, now.Add(90*time.Second), 10, "ok")
	sweep(t, s, now.Add(90*time.Second))
	sweep(t, s, now.Add(105*time.Second))
	sweep(t, s, now.Add(120*time.Second))
	sweep(t, s, now.Add(135*time.Second))
	cpuReading(t, s, d, now.Add(150*time.Second), 10, "ok")
	sweep(t, s, now.Add(150*time.Second))
	a = alertsFor(t, s, d.ID)
	if a[0].Status != "resolved" || a[0].CloseReason != "recovered" {
		t.Fatal("fresh recovery did not resolve", a)
	}
	id, n, e = s.ClaimAlertMail(ctx, "test-mail", now.Add(150*time.Second))
	if e != nil || id == 0 || n.Event != "resolved" {
		t.Fatal("recovery notification missing", e)
	}
}
func TestInterveningGoodSampleAndServerGapPreventFalseAlert(t *testing.T) {
	s, d, now := alertFixture(t)
	cpuReading(t, s, d, now, 99, "ok")
	sweep(t, s, now)
	// All three arrivals can occur between evaluations; the healthy one must
	// reset qualification even though the latest retained metric is high.
	sweep(t, s, now.Add(15*time.Second))
	cpuReading(t, s, d, now.Add(20*time.Second), 1, "ok")
	cpuReading(t, s, d, now.Add(30*time.Second), 99, "ok")
	sweep(t, s, now.Add(30*time.Second))
	sweep(t, s, now.Add(45*time.Second))
	cpuReading(t, s, d, now.Add(60*time.Second), 99, "ok")
	sweep(t, s, now.Add(60*time.Second))
	if len(alertsFor(t, s, d.ID)) != 0 {
		t.Fatal("missed healthy sample or server gap")
	}
	if e := s.InitializeAlerts(context.Background(), 120*time.Second, "test-mail", now.Add(60*time.Second)); e != nil {
		t.Fatal(e)
	}
	cpuReading(t, s, d, now.Add(61*time.Second), 99, "ok")
	sweep(t, s, now.Add(61*time.Second))
	if len(alertsFor(t, s, d.ID)) != 0 {
		t.Fatal("restart counted old duration")
	}
}
func TestOfflineQualificationAndNoRecoveryOnMissingMetrics(t *testing.T) {
	s, d, now := alertFixture(t)
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	for sec := 0; sec <= 180; sec += 15 {
		sweep(t, s, now.Add(time.Duration(sec)*time.Second))
	}
	a := alertsFor(t, s, d.ID)
	if len(a) != 1 || a[0].Kind != "offline" {
		t.Fatal("offline threshold did not qualify", a)
	}
	if e := s.RevokeDevice(ctx, d.ID, now.Add(181*time.Second)); e != nil {
		t.Fatal(e)
	}
	sweep(t, s, now.Add(181*time.Second))
	a = alertsFor(t, s, d.ID)
	if a[0].Status != "closed" || a[0].CloseReason == "recovered" {
		t.Fatal("revocation inferred recovery")
	}
	if id, _, e := s.ClaimAlertMail(ctx, "test-mail", now.Add(181*time.Second)); e != nil || id != 0 {
		t.Fatal("revoked device email claimed")
	}
}
