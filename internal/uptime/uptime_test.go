package uptime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"testing"
	"time"
)

type fakeCollector struct {
	value protocol.Uptime
	err   error
}

func (c fakeCollector) Collect(context.Context) (protocol.Uptime, error) { return c.value, c.err }

func TestUptimeDurationAndDeviceClockEstimate(t *testing.T) {
	now := time.Unix(1800000000, 500000000)
	for _, elapsed := range []time.Duration{0, 1500 * time.Millisecond, 90061 * time.Second} {
		value, err := fromDuration(elapsed, now)
		if err != nil || value.UptimeSeconds != uint64(elapsed/time.Second) || value.EstimatedBootAt != now.Add(-elapsed).Unix() {
			t.Fatal("incorrect uptime/boot estimate", value, err)
		}
		shifted, err := fromDuration(elapsed, now.Add(time.Hour))
		if err != nil || shifted.UptimeSeconds != value.UptimeSeconds || shifted.EstimatedBootAt != value.EstimatedBootAt+3600 {
			t.Fatal("uptime depends on wall clock or boot estimate hides clock shift")
		}
	}
	for _, test := range []struct {
		elapsed time.Duration
		now     time.Time
	}{{-1, now}, {time.Hour, time.Unix(10, 0)}, {0, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		if _, err := fromDuration(test.elapsed, test.now); err == nil {
			t.Fatal("invalid duration/clock accepted")
		}
	}
}

func TestUptimeAdapterAndStrictSchema(t *testing.T) {
	for _, seconds := range []uint64{0, 3600, MaxUptimeSeconds} {
		data, err := (Module{fakeCollector{value: protocol.Uptime{UptimeSeconds: seconds, EstimatedBootAt: 1800000000}}}).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`null`, `{}`, `{"uptime_seconds":0}`, `{"estimated_boot_at":1800000000}`, `{"uptime_seconds":null,"estimated_boot_at":1800000000}`,
		`{"uptime_seconds":-1,"estimated_boot_at":1800000000}`, `{"uptime_seconds":1.5,"estimated_boot_at":1800000000}`, `{"uptime_seconds":9223372037,"estimated_boot_at":1800000000}`,
		`{"uptime_seconds":1,"estimated_boot_at":0}`, `{"uptime_seconds":1,"estimated_boot_at":-1}`, `{"uptime_seconds":1,"estimated_boot_at":253402300799}`,
		`{"uptime_seconds":1,"estimated_boot_at":1800000000.5}`, `{"uptime_seconds":1,"estimated_boot_at":1800000000,"device_id":"forged"}`,
		`{"uptime_seconds":1,"estimated_boot_at":1800000000,"received_at":1}`, `{"uptime_seconds":1,"estimated_boot_at":1800000000} {}`,
	} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(body)}); !errors.Is(err, features.ErrReport) {
			t.Fatalf("bad uptime accepted: %s", body)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status}); err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status, Data: json.RawMessage(`{}`)}); err == nil {
			t.Fatal("non-success payload accepted")
		}
	}
	for _, cap := range []protocol.Capability{{Name: "uptime", Version: 0}, {Name: "uptime", Version: 1000}, {Name: "unknown", Version: 1}} {
		if _, err := Normalize(protocol.FeatureReport{Capability: cap, Status: "ok"}); err == nil {
			t.Fatal("unknown capability accepted")
		}
	}
	newer, err := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "uptime", Version: 2}, Status: "ok", Data: json.RawMessage(`{"future":true}`)})
	if err != nil || newer.Status != "unsupported" || len(newer.Data) != 0 {
		t.Fatal("newer payload not discarded")
	}
	if _, err := (Module{fakeCollector{err: features.ErrUnsupported}}).Collect(context.Background()); !errors.Is(err, features.ErrUnsupported) {
		t.Fatal("unsupported adapter lost")
	}
	if _, err := (Module{fakeCollector{err: errors.New("unavailable")}}).Collect(context.Background()); err == nil {
		t.Fatal("collector failure lost")
	}
	if _, err := (Module{fakeCollector{}}).Collect(context.Background()); err == nil {
		t.Fatal("invalid collector output accepted")
	}
}
