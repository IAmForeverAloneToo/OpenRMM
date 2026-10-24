package storage

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/localaccounts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The newest snapshot is stored for an authorized device; failed and
// out-of-order reports keep it; revoked devices are rejected.
func TestLocalAccountsSnapshot(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	d := Device{ID: "0123456789abcdef0123456789abcdef", Hostname: "pc", OS: "windows", Architecture: "amd64", Certificate: "cert", Fingerprint: "fp"}
	if e = s.NewEnrollmentToken(ctx, "t", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = s.EnrollDevice(ctx, "t", d, now); e != nil {
		t.Fatal(e)
	}
	v := protocol.LocalAccounts{Accounts: []protocol.LocalAccount{{Name: "Admin", SID: "S-1-5-21-1-500", Enabled: true}}, Groups: []protocol.LocalGroup{{Key: "administrators", Name: "Administrators", Members: []protocol.GroupMember{{Name: `PC\Admin`, SID: "S-1-5-21-1-500", Kind: "user"}}}, {Key: "remote_desktop_users", Members: []protocol.GroupMember{}}}}
	b, _ := json.Marshal(v)
	ok := protocol.FeatureReport{Capability: localaccounts.Capability, Status: "ok", Data: b}
	if got, _ := s.LocalAccounts(ctx, d.ID); got.Status != "not_reported" {
		t.Fatal("initial", got.Status)
	}
	if e = s.RecordLocalAccounts(ctx, d.ID, "wrong", ok, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint", e)
	}
	if e = s.RecordLocalAccounts(ctx, d.ID, "fp", ok, now); e != nil {
		t.Fatal(e)
	}
	failed := protocol.FeatureReport{Capability: localaccounts.Capability, Status: "failed"}
	if e = s.RecordLocalAccounts(ctx, d.ID, "fp", failed, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	empty, _ := json.Marshal(protocol.LocalAccounts{Accounts: []protocol.LocalAccount{}, Groups: v.Groups})
	if e = s.RecordLocalAccounts(ctx, d.ID, "fp", protocol.FeatureReport{Capability: localaccounts.Capability, Status: "ok", Data: empty}, now.Add(-time.Minute)); e != nil {
		t.Fatal("out-of-order report must be ignored without error", e)
	}
	got, e := s.LocalAccounts(ctx, d.ID)
	if e != nil || got.Status != "failed" || got.Data == nil || len(got.Data.Accounts) != 1 || got.SnapshotAt == nil || *got.SnapshotAt != now.Unix() {
		t.Fatal("snapshot", got, e)
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordLocalAccounts(ctx, d.ID, "fp", ok, now.Add(2*time.Minute)); !errors.Is(e, ErrAuthentication) {
		t.Fatal("revoked device accepted", e)
	}
}
