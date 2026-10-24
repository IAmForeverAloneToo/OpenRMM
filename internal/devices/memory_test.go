package devices

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func TestMemoryUsesAuthenticatedDeviceAndServerTime(t *testing.T) {
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
	report := protocol.FeatureReport{Capability: memory.Capability, Status: "ok", Data: json.RawMessage(`{"total_bytes":100,"available_bytes":25}`)}
	receipt, err := s.Feature(ctx, state(t, first), report)
	if err != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatal("memory identity/time not server bound", err)
	}
	got, err := store.Memory(ctx, first.DeviceID)
	if err != nil || got.Data == nil || got.Data.AvailableBytes != 25 || got.ReportedAt != now.Unix() {
		t.Fatal("memory reading missing")
	}
	other, err := store.Memory(ctx, second.DeviceID)
	if err != nil || other.Status != "not_reported" || other.Data != nil {
		t.Fatal("another device updated")
	}
	disk, err := store.DiskSpace(ctx, first.DeviceID)
	if err != nil || disk.Status != "not_reported" {
		t.Fatal("memory overwrote disk state")
	}
	if err := store.RevokeDevice(ctx, first.DeviceID, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Feature(ctx, state(t, first), report); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked device wrote memory reading")
	}
}

func TestMemoryPresentationAndFreshness(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stamp := now.Unix()
	value := storage.Memory{Status: "ok", SnapshotAt: &stamp, Data: &protocol.Memory{TotalBytes: 4 << 30, AvailableBytes: 1 << 30}}
	for _, test := range []struct {
		age    time.Duration
		device string
		stale  bool
	}{
		{0, "online", false}, {119 * time.Second, "online", false}, {120 * time.Second, "online", true}, {-time.Second, "online", true},
		{0, "offline", true}, {0, "revoked", true}, {0, "awaiting_contact", true},
	} {
		v := PresentMemory(value, View{Status: test.device}, now.Add(test.age))
		if v.Stale != test.stale || v.UsedPercent == nil || *v.UsedPercent != 75 || v.TotalMemory != "4.0 GiB" || v.AvailableMemory != "1.0 GiB" || v.Usage != "75.0%" {
			t.Fatal("incorrect memory presentation", v)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		value.Status = status
		v := PresentMemory(value, View{Status: "online"}, now)
		if !v.Stale || v.Data == nil || v.StatusLabel == "Collected" {
			t.Fatal("unsuccessful report did not retain stale reading")
		}
	}
	for _, data := range []*protocol.Memory{nil, {}, {TotalBytes: 100, AvailableBytes: 101}} {
		v := PresentMemory(storage.Memory{Status: "ok", SnapshotAt: &stamp, Data: data}, View{Status: "online"}, now)
		if !v.Stale || v.UsedPercent != nil {
			t.Fatal("missing/invalid RAM shown as collected")
		}
	}
	for _, available := range []uint64{0, 100} {
		v := PresentMemory(storage.Memory{Status: "ok", SnapshotAt: &stamp, Data: &protocol.Memory{TotalBytes: 100, AvailableBytes: available}}, View{Status: "online"}, now)
		if v.UsedPercent == nil || *v.UsedPercent != float64(100-available) {
			t.Fatal("full/empty memory percentage wrong")
		}
	}
}
