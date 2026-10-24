package devices

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/uptime"
)

func TestUptimeUsesAuthenticatedDeviceAndServerTime(t *testing.T) {
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
	report := protocol.FeatureReport{Capability: uptime.Capability, Status: "ok", Data: json.RawMessage(`{"uptime_seconds":3600,"estimated_boot_at":4102444800}`)}
	receipt, err := s.Feature(ctx, state(t, first), report)
	if err != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatal("uptime identity/time not server bound", err)
	}
	got, err := store.Uptime(ctx, first.DeviceID)
	if err != nil || got.Data == nil || got.Data.UptimeSeconds != 3600 || got.ReportedAt != now.Unix() {
		t.Fatal("uptime reading missing")
	}
	other, err := store.Uptime(ctx, second.DeviceID)
	if err != nil || other.Status != "not_reported" || other.Data != nil {
		t.Fatal("another device updated")
	}
	disk, err := store.DiskSpace(ctx, first.DeviceID)
	if err != nil || disk.Status != "not_reported" {
		t.Fatal("uptime overwrote disk state")
	}
	if err := store.RevokeDevice(ctx, first.DeviceID, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Feature(ctx, state(t, first), report); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked device wrote uptime reading")
	}
}

func TestUptimePresentationAndFreshness(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stamp := now.Unix()
	value := storage.Uptime{Status: "ok", SnapshotAt: &stamp, Data: &protocol.Uptime{UptimeSeconds: 90061, EstimatedBootAt: now.Unix() - 90061}}
	for _, test := range []struct {
		age    time.Duration
		device string
		stale  bool
	}{
		{0, "online", false}, {119 * time.Second, "online", false}, {120 * time.Second, "online", true}, {-time.Second, "online", true},
		{0, "offline", true}, {0, "revoked", true}, {0, "awaiting_contact", true},
	} {
		v := PresentUptime(value, View{Status: test.device}, now.Add(test.age))
		if v.Stale != test.stale || v.Duration != "1d 01h 01m 01s" || v.EstimatedBoot != time.Unix(value.Data.EstimatedBootAt, 0).UTC().Format(time.RFC3339) {
			t.Fatal("incorrect uptime view", v)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		value.Status = status
		v := PresentUptime(value, View{Status: "online"}, now)
		if !v.Stale || v.Data == nil || v.StatusLabel == "Collected" {
			t.Fatal("old uptime not retained as stale")
		}
	}
	for _, data := range []*protocol.Uptime{nil, {}, {UptimeSeconds: uptime.MaxUptimeSeconds + 1, EstimatedBootAt: 1800000000}} {
		v := PresentUptime(storage.Uptime{Status: "ok", SnapshotAt: &stamp, Data: data}, View{Status: "online"}, now)
		if !v.Stale || v.Duration != "" {
			t.Fatal("invalid uptime shown as collected")
		}
	}
	v := PresentUptime(storage.Uptime{Status: "ok", SnapshotAt: &stamp, Data: &protocol.Uptime{EstimatedBootAt: now.Unix()}}, View{Status: "online"}, now)
	if v.Stale || v.Duration != "0d 00h 00m 00s" {
		t.Fatal("zero uptime must be a valid reading")
	}
}
