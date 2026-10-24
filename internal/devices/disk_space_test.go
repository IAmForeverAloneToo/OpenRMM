package devices

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func TestDiskSpaceUsesAuthenticatedDeviceAndServerTime(t *testing.T) {
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
	report := protocol.FeatureReport{Capability: diskspace.Capability, Status: "ok", Data: json.RawMessage(`{"drive":"C:\\","total_bytes":100,"available_bytes":25}`)}
	receipt, err := s.Feature(ctx, state(t, first), report)
	if err != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatal("disk identity/time were not server bound", err)
	}
	got, err := store.DiskSpace(ctx, first.DeviceID)
	if err != nil || got.Data == nil || got.Data.AvailableBytes != 25 || got.ReportedAt != now.Unix() {
		t.Fatal("disk reading missing")
	}
	other, err := store.DiskSpace(ctx, second.DeviceID)
	if err != nil || other.Status != "not_reported" || other.Data != nil {
		t.Fatal("another device updated")
	}
	inv, err := store.Inventory(ctx, first.DeviceID)
	if err != nil || inv.Status != "not_reported" {
		t.Fatal("disk overwrote inventory")
	}
	if err := store.RevokeDevice(ctx, first.DeviceID, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Feature(ctx, state(t, first), report); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked device wrote disk reading")
	}
}

func TestDiskSpacePresentation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stamp := now.Unix()
	value := storage.DiskSpace{Status: "ok", SnapshotAt: &stamp, Data: &protocol.DiskSpace{Drive: `C:\`, TotalBytes: 4 << 30, AvailableBytes: 1 << 30}}
	for _, test := range []struct {
		age    time.Duration
		status string
		stale  bool
	}{
		{0, "online", false}, {10*time.Minute - time.Second, "online", false}, {10 * time.Minute, "online", true}, {-time.Second, "online", true},
		{0, "offline", true}, {0, "revoked", true}, {0, "awaiting_contact", true},
	} {
		v := PresentDiskSpace(value, View{Status: test.status}, now.Add(test.age))
		if v.Stale != test.stale || v.UsedPercent == nil || *v.UsedPercent != 75 || v.TotalSpace != "4.0 GiB" || v.AvailableSpace != "1.0 GiB" || v.Usage != "75.0%" {
			t.Fatal("incorrect disk presentation", v)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		value.Status = status
		v := PresentDiskSpace(value, View{Status: "online"}, now)
		if !v.Stale || v.Data == nil || v.StatusLabel == "Collected" {
			t.Fatal("failed reading not retained as stale")
		}
	}
	if v := PresentDiskSpace(storage.DiskSpace{}, View{Status: "online"}, now); !v.Stale || v.UsedPercent != nil || v.LastSuccess != "Never" {
		t.Fatal("missing reading shown as collected")
	}
}

func TestDiskWarningThresholdAndUnknownStates(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stamp := now.Unix()
	for _, test := range []struct {
		name             string
		total, available uint64
		warning          string
	}{
		{"full", 1000, 0, "low"}, {"just below", 1000, 99, "low"}, {"exactly ten percent", 1000, 100, "ok"},
		{"above", 1000, 101, "ok"}, {"empty", 1000, 1000, "ok"}, {"fractional threshold", 101, 10, "low"},
		{"large boundary low", 9007199254740990, 900719925474098, "low"},
		{"large boundary clear", 9007199254740990, 900719925474099, "ok"},
		{"invalid zero total", 0, 0, "unknown"}, {"invalid available", 100, 101, "unknown"},
		{"unrepresentable total", 1 << 53, 0, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := storage.DiskSpace{Status: "ok", SnapshotAt: &stamp, Data: &protocol.DiskSpace{Drive: `C:\`, TotalBytes: test.total, AvailableBytes: test.available}}
			v := PresentDiskSpace(value, View{Status: "online"}, now)
			if v.Warning != test.warning {
				t.Fatalf("got %s; want %s", v.Warning, test.warning)
			}
		})
	}
	for _, available := range []uint64{0, 900} {
		for _, test := range []struct {
			reportStatus, deviceStatus string
			age                        time.Duration
			missingTime, missingData   bool
		}{
			{"ok", "online", 10 * time.Minute, false, false}, {"ok", "online", -time.Second, false, false},
			{"ok", "offline", 0, false, false}, {"ok", "revoked", 0, false, false}, {"ok", "awaiting_contact", 0, false, false},
			{"failed", "online", 0, false, false}, {"disabled", "online", 0, false, false}, {"unsupported", "online", 0, false, false},
			{"not_reported", "online", 0, false, false}, {"ok", "online", 0, true, false}, {"ok", "online", 0, false, true},
		} {
			value := storage.DiskSpace{Status: test.reportStatus, SnapshotAt: &stamp, Data: &protocol.DiskSpace{Drive: `C:\`, TotalBytes: 1000, AvailableBytes: available}}
			if test.missingTime {
				value.SnapshotAt = nil
			}
			if test.missingData {
				value.Data = nil
			}
			v := PresentDiskSpace(value, View{Status: test.deviceStatus}, now.Add(test.age))
			if v.Warning != "unknown" || !v.Stale {
				t.Fatal("unavailable disk state reported a warning or recovery", v)
			}
		}
	}
}

func TestFleetDiskWarningUpdatesAndDeviceIsolation(t *testing.T) {
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
	if _, err := s.Heartbeat(ctx, state(t, first), protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	check := func(expected string) {
		t.Helper()
		list, err := List(ctx, store, *now, 120*time.Second)
		if err != nil || len(list) != 2 {
			t.Fatal("fleet warning query failed", err)
		}
		for _, item := range list {
			want := "unknown"
			if item.ID == first.DeviceID {
				want = expected
			} else if item.ID != second.DeviceID {
				t.Fatal("unexpected device")
			}
			if item.DiskSpaceWarning != want {
				t.Fatalf("got fleet disk warning %s; want %s", item.DiskSpaceWarning, want)
			}
		}
	}
	check("unknown")
	report := protocol.FeatureReport{Capability: diskspace.Capability, Status: "ok", Data: json.RawMessage(`{"drive":"C:\\","total_bytes":1000,"available_bytes":99}`)}
	if _, err := s.Feature(ctx, state(t, first), report); err != nil {
		t.Fatal(err)
	}
	check("low")
	*now = now.Add(120 * time.Second)
	check("unknown")
	if _, err := s.Heartbeat(ctx, state(t, first), protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	check("low")
	report.Data = json.RawMessage(`{"drive":"C:\\","total_bytes":1000,"available_bytes":100}`)
	if _, err := s.Feature(ctx, state(t, first), report); err != nil {
		t.Fatal(err)
	}
	check("ok")
	report.Status, report.Data = "failed", nil
	if _, err := s.Feature(ctx, state(t, first), report); err != nil {
		t.Fatal(err)
	}
	check("unknown")
}
