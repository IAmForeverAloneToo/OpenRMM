package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func TestHeartbeatPersistsAndRejectsStaleAuthorization(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	if err := store.NewEnrollmentToken(ctx, "test-token", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	device := Device{ID: "0123456789abcdef0123456789abcdef", Hostname: "test", OS: "windows", Architecture: "amd64", Certificate: "test-public-cert", Fingerprint: "test-fingerprint"}
	if err := store.EnrollDevice(ctx, "test-token", device, now); err != nil {
		t.Fatal(err)
	}
	input := protocol.Heartbeat{Hostname: "updated", OS: "windows", Architecture: "amd64", AgentVersion: "0.1.0-test"}
	if err := store.RecordHeartbeat(ctx, device.ID, device.Fingerprint, input, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordHeartbeat(ctx, device.ID, device.Fingerprint, input, now.Add(-time.Minute)); err != nil {
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
	list, err := store.Devices(ctx)
	if err != nil || len(list) != 1 || list[0].LastContactAt == nil || *list[0].LastContactAt != now.Unix() || list[0].AgentVersion != input.AgentVersion {
		t.Fatal("last contact did not persist or moved backwards")
	}
	if err := store.RecordHeartbeat(ctx, device.ID, "another-device-fingerprint", input, now.Add(time.Second)); !errors.Is(err, ErrAuthentication) {
		t.Fatal("another credential updated device")
	}
	if err := store.RevokeDevice(ctx, device.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordHeartbeat(ctx, device.ID, device.Fingerprint, input, now.Add(time.Second)); !errors.Is(err, ErrAuthentication) {
		t.Fatal("stale authorization wrote after revocation")
	}
}
