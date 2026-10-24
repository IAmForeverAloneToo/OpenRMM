package devices

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func TestCPUUsesAuthenticatedDeviceAndServerTime(t *testing.T) {
	s, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, _ := s.NewToken(ctx)
	first, err := s.Enroll(ctx, request(t, token), "peer")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ = s.NewToken(ctx)
	second, err := s.Enroll(ctx, request(t, token), "peer")
	if err != nil {
		t.Fatal(err)
	}
	report := protocol.FeatureReport{Capability: cpu.Capability, Status: "ok", Data: json.RawMessage(`{"usage_percent":75,"sample_ms":1000}`)}
	receipt, err := s.Feature(ctx, state(t, first), report)
	if err != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatal("cpu identity/time not server bound", err)
	}
	got, err := store.CPU(ctx, first.DeviceID)
	if err != nil || got.Data == nil || got.Data.UsagePercent != 75 || got.ReportedAt != now.Unix() {
		t.Fatal("cpu reading missing")
	}
	other, err := store.CPU(ctx, second.DeviceID)
	if err != nil || other.Status != "not_reported" || other.Data != nil {
		t.Fatal("another device updated")
	}
	disk, err := store.DiskSpace(ctx, first.DeviceID)
	if err != nil || disk.Status != "not_reported" {
		t.Fatal("cpu overwrote disk state")
	}
	if err := store.RevokeDevice(ctx, first.DeviceID, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Feature(ctx, state(t, first), report); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked device wrote cpu reading")
	}
}

func TestCPUReadingPresentationAndFreshness(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stamp := now.Unix()
	value := storage.CPU{Status: "ok", SnapshotAt: &stamp, Data: &protocol.CPU{UsagePercent: 75, SampleMilliseconds: 1250}}
	for _, test := range []struct {
		age    time.Duration
		device string
		stale  bool
	}{
		{0, "online", false}, {119 * time.Second, "online", false}, {120 * time.Second, "online", true}, {-time.Second, "online", true},
		{0, "offline", true}, {0, "revoked", true}, {0, "awaiting_contact", true},
	} {
		v := PresentCPU(value, View{Status: test.device}, now.Add(test.age))
		if v.Stale != test.stale || v.Usage != "75.0%" || v.SampleDuration != "1.250 seconds" {
			t.Fatal("incorrect CPU view", v)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		value.Status = status
		v := PresentCPU(value, View{Status: "online"}, now)
		if !v.Stale || v.Data == nil || v.StatusLabel == "Collected" {
			t.Fatal("failed CPU did not retain stale snapshot")
		}
	}
	for _, data := range []*protocol.CPU{nil, {}, {UsagePercent: 101, SampleMilliseconds: 1000}} {
		v := PresentCPU(storage.CPU{Status: "ok", SnapshotAt: &stamp, Data: data}, View{Status: "online"}, now)
		if !v.Stale || v.Usage != "" {
			t.Fatal("invalid CPU shown as collected")
		}
	}
}
