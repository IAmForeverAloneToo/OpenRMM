package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The three pools: readers cannot write; the telemetry writer and the
// writer work at the same time without lock errors (SQLite lets one write at
// a time; the other waits); readers see telemetry at once.
func TestConnectionPools(t *testing.T) {
	s, d, now := alertFixture(t)
	ctx := context.Background()
	if _, e := s.rdb.ExecContext(ctx, "UPDATE alert_runtime SET last_sweep=0"); e == nil {
		t.Fatal("a reader wrote")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 1000)
	for i := range 200 {
		at := now.Add(time.Duration(i) * time.Second)
		wg.Add(2)
		go func() {
			defer wg.Done()
			hb := protocol.Heartbeat{Hostname: d.Hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test"}
			report := protocol.FeatureReport{Capability: cpu.Capability, Status: "ok"}
			report.Data, _ = json.Marshal(protocol.CPU{UsagePercent: 50, SampleMilliseconds: 1000})
			if e := s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, hb, at); e != nil {
				errs <- e
			}
			if e := s.RecordCPU(ctx, d.ID, d.Fingerprint, report, at); e != nil {
				errs <- e
			}
		}()
		go func() {
			defer wg.Done()
			if e := s.EvaluateAlerts(ctx, at); e != nil {
				errs <- e
			}
			if _, e := s.ActiveDevice(ctx, d.ID, d.Fingerprint, at); e != nil {
				errs <- e
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal("concurrent writers:", e)
	}
	c, e := s.CPU(ctx, d.ID)
	if e != nil || c.ReportedAt == 0 {
		t.Fatalf("telemetry not visible to readers: %+v %v", c, e)
	}
	// The health checks' monitored-device query ends at the fleet limit too.
	if !strings.HasSuffix(monitoredDevices, fleetLimit) {
		t.Fatal("monitoredDevices does not use MaxFleet")
	}
}

// Active alert counts cover every alert, past the bounded alert list.
func TestActiveAlertCounts(t *testing.T) {
	s, d, now := alertFixture(t)
	ctx := context.Background()
	for i := range 251 {
		severity, status := "warning", "active"
		if i%2 == 0 {
			severity = "critical"
		}
		if i == 250 {
			status = "resolved"
		}
		if _, e := s.db.ExecContext(ctx, `INSERT INTO alerts(id,device_id,hostname,kind,severity,threshold,hold_seconds,status,opened_at,last_seen) VALUES(?,?,'host',?,?,0,60,?,?,?)`, fmt.Sprintf("%032x", i+1), d.ID, fmt.Sprintf("check:%032x", i+1), severity, status, now.Unix(), now.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	counts, e := s.ActiveAlertCounts(ctx, Session{})
	if e != nil {
		t.Fatal(e)
	}
	if len(counts) != 1 || counts[d.ID] != (AlertCount{Active: 250, Critical: 125}) {
		t.Fatalf("counts: %+v", counts)
	}
}
