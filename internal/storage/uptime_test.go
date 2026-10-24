package storage

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func TestUptimePersistsRetainsSnapshotAndChecksAuthorization(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	d := Device{ID: "0123456789abcdef0123456789abcdef", Hostname: "test", OS: "windows", Architecture: "amd64", Certificate: "public", Fingerprint: "first"}
	if err := store.NewEnrollmentToken(ctx, "token", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.EnrollDevice(ctx, "token", d, now); err != nil {
		t.Fatal(err)
	}
	report := protocol.FeatureReport{Capability: protocol.Capability{Name: "uptime", Version: 1}, Status: "ok", Data: json.RawMessage(`{"uptime_seconds":3600,"estimated_boot_at":1799996400}`)}
	if err := store.RecordUptime(ctx, d.ID, d.Fingerprint, report, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		report.Status, report.Data = status, nil
		if err := store.RecordUptime(ctx, d.ID, d.Fingerprint, report, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		got, err := store.Uptime(ctx, d.ID)
		if err != nil || got.Data == nil || got.Data.UptimeSeconds != 3600 || got.Status != status || got.SnapshotAt == nil || *got.SnapshotAt != now.Unix() {
			t.Fatal("failed report erased snapshot or state did not persist")
		}
	}
	if err := store.RecordUptime(ctx, d.ID, "wrong", report, now); !errors.Is(err, ErrAuthentication) {
		t.Fatal("another fingerprint wrote uptime")
	}
	if err := store.RecordUptime(ctx, "ffffffffffffffffffffffffffffffff", d.Fingerprint, report, now); !errors.Is(err, ErrAuthentication) {
		t.Fatal("another device received uptime")
	}
	if err := store.RevokeDevice(ctx, d.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordUptime(ctx, d.ID, d.Fingerprint, report, now); !errors.Is(err, ErrAuthentication) {
		t.Fatal("stale authorization wrote after revocation")
	}
}
