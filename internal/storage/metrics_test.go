package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func metricCPU(t *testing.T, s *Store, d Device, at time.Time, value float64, status string) {
	t.Helper()
	r := protocol.FeatureReport{Capability: protocol.Capability{Name: "cpu", Version: 1}, Status: status}
	if status == "ok" {
		r.Data, _ = json.Marshal(protocol.CPU{UsagePercent: value, SampleMilliseconds: 1000})
	}
	if e := s.RecordCPU(context.Background(), d.ID, d.Fingerprint, r, at); e != nil {
		t.Fatal(e)
	}
}
func TestMetricsAggregatesDeduplicatesAndPreservesUnknown(t *testing.T) {
	s, d, at := actionFixture(t)
	at = at.Truncate(time.Hour)
	ctx := context.Background()
	metricCPU(t, s, d, at, 0, "ok")
	metricCPU(t, s, d, at.Add(time.Second), 100, "ok") // same minute is not another sample
	metricCPU(t, s, d, at.Add(time.Minute), 100, "ok")
	metricCPU(t, s, d, at.Add(2*time.Minute), 0, "failed")
	metricCPU(t, s, d, at.Add(-time.Minute), 75, "ok") // old receipt is ignored
	w, _ := MetricsWindow("24h", at.Add(4*time.Minute))
	h, e := s.MetricHistory(ctx, d.ID, w)
	if e != nil || len(h.Buckets) != 1 {
		t.Fatal(h, e)
	}
	b := h.Buckets[0]
	if b.Count != 2 || b.Unknown != 1 || b.Gaps != 0 || b.Mean == nil || *b.Mean != 50 || *b.Min != 0 || *b.Max != 100 {
		t.Fatal(b)
	}
	metricCPU(t, s, d, at.Add(12*time.Minute), 25, "ok")
	w, _ = MetricsWindow("7d", at.Add(13*time.Minute))
	rows, e := s.MetricSummaries(ctx, []string{d.ID}, w)
	if e != nil || len(rows) != 3 || rows[0].Count != 3 || rows[0].Unknown != 1 || rows[0].Gaps != 1 || math.Abs(*rows[0].Mean-125.0/3) > 0.001 || rows[1].Mean != nil {
		t.Fatal(rows, e)
	}
	metricCPU(t, s, d, at.Add(13*time.Minute), 0, "unsupported")
	metricCPU(t, s, d, at.Add(14*time.Minute), 0, "disabled")
	w, _ = MetricsWindow("24h", at.Add(15*time.Minute))
	rows, e = s.MetricSummaries(ctx, []string{d.ID}, w)
	if e != nil || rows[0].Count != 3 || rows[0].Unknown != 3 {
		t.Fatal(rows, e)
	}
}
func TestMetricsAtomicAuthorizationAndResourceAdapters(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	r := protocol.FeatureReport{Capability: protocol.Capability{Name: "memory", Version: 1}, Status: "ok", Data: json.RawMessage(`{"total_bytes":1000,"available_bytes":250}`)}
	if e := s.RecordMemory(ctx, d.ID, d.Fingerprint, r, now); e != nil {
		t.Fatal(e)
	}
	r.Capability.Name = "disk_space"
	r.Data = json.RawMessage(`{"drive":"C:\\","total_bytes":1000,"available_bytes":100}`)
	if e := s.RecordDiskSpace(ctx, d.ID, d.Fingerprint, r, now); e != nil {
		t.Fatal(e)
	}
	w, _ := MetricsWindow("24h", now.Add(time.Minute))
	rows, e := s.MetricSummaries(ctx, []string{d.ID}, w)
	if e != nil || *rows[1].Mean != 75 || *rows[2].Mean != 90 {
		t.Fatal(rows, e)
	}
	if e = s.RecordDiskSpace(ctx, d.ID, "wrong", r, now.Add(time.Minute)); !errors.Is(e, ErrAuthentication) {
		t.Fatal(e)
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordMemory(ctx, d.ID, d.Fingerprint, r, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal(e)
	}
	after, _ := s.MetricSummaries(ctx, []string{d.ID}, w)
	if after[2].Count != 1 {
		t.Fatal("unauthorized history write")
	}
}
func TestMetricsRetentionBoundsAndReopenMigration(t *testing.T) {
	s, d, at := actionFixture(t)
	ctx := context.Background()
	metricCPU(t, s, d, at, 42, "ok")
	if e := s.PruneMetrics(ctx, at.Add(3*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	w, _ := MetricsWindow("24h", at.Add(3*24*time.Hour))
	h, e := s.MetricHistory(ctx, d.ID, w)
	if e != nil || len(h.Buckets) != 0 {
		t.Fatal(h, e)
	}
	w, _ = MetricsWindow("7d", at.Add(3*24*time.Hour))
	h, e = s.MetricHistory(ctx, d.ID, w)
	if e != nil || len(h.Buckets) != 1 {
		t.Fatal(h, e)
	}
	if e = s.PruneMetrics(ctx, at.Add(31*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM metric_buckets").Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
	// Fill the real global bound without thousands of fake enrolled devices.
	if _, e = s.db.Exec(`WITH RECURSIVE n(v) AS(VALUES(0) UNION ALL SELECT v+1 FROM n WHERE v<100004)
	INSERT INTO metric_buckets(device_id,kind,step,bucket,first_at,last_at) SELECT ?,'cpu',300,?,v,v FROM n`, d.ID, at.Unix()); e == nil {
		t.Fatal("duplicate buckets must not bypass primary key")
	}
	if _, e = s.db.Exec(`WITH RECURSIVE n(v) AS(VALUES(0) UNION ALL SELECT v+1 FROM n WHERE v<100004)
	INSERT INTO metric_buckets(device_id,kind,step,bucket,first_at,last_at) SELECT ?,'cpu',300,?+v,v,v FROM n`, d.ID, at.Unix()); e != nil {
		t.Fatal(e)
	}
	if e = s.PruneMetrics(ctx, at); e != nil {
		t.Fatal(e)
	}
	if e = s.db.QueryRow("SELECT COUNT(*) FROM metric_buckets WHERE step=300").Scan(&count); e != nil || count != MetricBucketLimit {
		t.Fatal(count, e)
	}
	path := filepath.Join(t.TempDir(), "private", "db")
	fresh, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := fresh.Info(ctx)
	rollbackFeatureSettings(t, fresh.db)
	for _, q := range []string{"DROP TABLE IF EXISTS agent_ring_policy", "DELETE FROM schema_migrations WHERE version=27", "DROP TABLE script_batches", "DELETE FROM schema_migrations WHERE version=26", "DROP TABLE metric_buckets", "DROP TABLE metric_receipts", "DELETE FROM schema_migrations WHERE version=25"} {
		if _, e = fresh.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	fresh.Close()
	fresh, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	after, _ := fresh.Info(ctx)
	if before != after {
		t.Fatal("schema24 identity changed")
	}
}
func TestMetricsRestartAndAtomicFailure(t *testing.T) {
	s, d, at := actionFixture(t)
	ctx := context.Background()
	metricCPU(t, s, d, at, 50, "ok")
	if _, e := s.db.Exec(`CREATE TRIGGER fail_metric BEFORE UPDATE ON metric_buckets BEGIN SELECT RAISE(ABORT,'fixture');END`); e != nil {
		t.Fatal(e)
	}
	r := protocol.FeatureReport{Capability: protocol.Capability{Name: "cpu", Version: 1}, Status: "ok", Data: json.RawMessage(`{"usage_percent":100,"sample_ms":1000}`)}
	if e := s.RecordCPU(ctx, d.ID, d.Fingerprint, r, at.Add(time.Minute)); e == nil {
		t.Fatal("history failure did not roll back")
	}
	latest, _ := s.CPU(ctx, d.ID)
	if latest.Data.UsagePercent != 50 {
		t.Fatal("collector and history write not atomic")
	}
	s.db.Exec("DROP TRIGGER fail_metric")
	if e := s.InitializeAlerts(ctx, 120*time.Second, "", at.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	w, _ := MetricsWindow("24h", at.Add(time.Hour))
	h, e := s.MetricHistory(ctx, d.ID, w)
	if e != nil || len(h.Buckets) != 1 {
		t.Fatal("startup cleared history", e)
	}
}

func TestMetricsStoredScopeRechecksMembershipAndAccount(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab"}, now)
	v := technicianFixture(t, s, now, TechnicianAccess{Groups: []string{"lab"}})
	metricCPU(t, s, d, now, 75, "ok")
	w, _ := MetricsWindow("24h", now.Add(time.Minute))
	h, e := s.MetricHistoryForSession(ctx, v, d.ID, w)
	if e != nil || len(h.Buckets) != 1 {
		t.Fatal(h, e)
	}
	rows, e := s.MetricSummariesForSession(ctx, v, []string{d.ID}, w)
	if e != nil || len(rows) != 3 {
		t.Fatal(rows, e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID}, now)
	h, e = s.MetricHistoryForSession(ctx, v, d.ID, w)
	if e != nil || len(h.Buckets) != 0 {
		t.Fatal("stale group scope exposed history", h, e)
	}
	rows, e = s.MetricSummariesForSession(ctx, v, []string{d.ID}, w)
	if e != nil || len(rows) != 0 {
		t.Fatal("stale group scope exposed summary", rows, e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab"}, now)
	if _, e = s.db.Exec("UPDATE technicians SET revision=revision+1"); e != nil {
		t.Fatal(e)
	}
	rows, e = s.MetricSummariesForSession(ctx, v, []string{d.ID}, w)
	if e != nil || len(rows) != 0 {
		t.Fatal("stale account revision exposed summary", rows, e)
	}
}
