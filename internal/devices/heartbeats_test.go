package devices

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func TestHeartbeatUsesCertificateIdentityAndServerReceiptTime(t *testing.T) {
	service, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, _ := service.NewToken(ctx)
	first, err := service.Enroll(ctx, request(t, token), "peer")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ = service.NewToken(ctx)
	second, err := service.Enroll(ctx, request(t, token), "peer")
	if err != nil {
		t.Fatal(err)
	}
	before, err := List(ctx, store, *now, 120*time.Second)
	if err != nil || len(before) != 2 {
		t.Fatal("missing devices")
	}
	for _, v := range before {
		if v.Status != "awaiting_contact" {
			t.Fatal("uncontacted device was not awaiting contact")
		}
	}
	input := protocol.Heartbeat{Hostname: "updated host", OS: "windows", Architecture: "amd64", AgentVersion: "0.1.0-test"}
	receipt, err := service.Heartbeat(ctx, state(t, first), input)
	if err != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatalf("heartbeat failed: %v", err)
	}
	list, err := List(ctx, store, *now, 120*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range list {
		if v.ID == first.DeviceID {
			if v.Status != "online" || v.LastContactAt == nil || *v.LastContactAt != now.Unix() || v.Hostname != input.Hostname || v.AgentVersion != input.AgentVersion {
				t.Fatal("heartbeat metadata/time not persisted")
			}
		} else if v.ID == second.DeviceID && v.LastContactAt != nil {
			t.Fatal("another device was updated")
		}
	}
	// A stale authorization result cannot write after administrator revocation.
	if err := store.RevokeDevice(ctx, first.DeviceID, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Heartbeat(ctx, state(t, first), input); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked heartbeat accepted")
	}
	if err := store.RecordHeartbeat(ctx, first.DeviceID, "wrong", input, *now); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("atomic heartbeat authorization missing")
	}
	if _, err := service.Heartbeat(ctx, state(t, second), protocol.Heartbeat{}); !errors.Is(err, ErrInvalidHeartbeat) {
		t.Fatal("invalid metadata accepted")
	}
}

func TestStatusBoundariesAndRevocationPrecedence(t *testing.T) {
	now := time.Unix(1800000000, 0)
	last := now.Unix()
	d := storage.Device{LastContactAt: &last}
	for _, test := range []struct {
		age    time.Duration
		status string
	}{{0, "online"}, {119 * time.Second, "online"}, {120 * time.Second, "offline"}, {121 * time.Second, "offline"}, {-time.Second, "offline"}} {
		if actual := Present(d, now.Add(test.age), 120*time.Second); actual.Status != test.status {
			t.Fatalf("unexpected status at %s: %s", test.age, actual.Status)
		}
	}
	d.RevokedAt = &last
	if actual := Present(d, now, 120*time.Second); actual.Status != "revoked" {
		t.Fatal("recent contact overrode revocation")
	}
	if actual := Present(storage.Device{}, now, 120*time.Second); actual.Status != "awaiting_contact" || actual.LastContact != "Never" {
		t.Fatal("never-contacted state incorrect")
	}
}
