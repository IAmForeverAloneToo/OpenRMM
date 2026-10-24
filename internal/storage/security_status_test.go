package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/securitystatus"
)

// The newest security status is stored per device, a failed report
// keeps it, and the fleet summaries come from it.
func TestSecurityStatusSnapshotAndSummaries(t *testing.T) {
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
	if got, e := s.SecurityStatus(ctx, d.ID); e != nil || got.Status != "not_reported" || got.Data != nil {
		t.Fatal("before any report", got, e)
	}
	v := protocol.SecurityStatus{
		BitLockerState: "available", DefenderState: "available",
		BitLocker: []protocol.BitLockerVolume{{Drive: "C:", Type: "os", Protection: "on", Conversion: "fully_encrypted", Percent: 100, Method: "XTS-AES 128"}},
		Defender:  &protocol.DefenderStatus{ServiceEnabled: true, AntivirusEnabled: true, RealTime: false, Mode: "normal"},
		Antivirus: []protocol.AntivirusProduct{{Name: "Windows Defender", Enabled: true, UpToDate: true}},
	}
	b, _ := json.Marshal(v)
	if e = s.RecordSecurityStatus(ctx, d.ID, "fp", protocol.FeatureReport{Capability: securitystatus.Capability, Status: "ok", Data: b}, now); e != nil {
		t.Fatal(e)
	}
	// A failed report and one from an unknown certificate keep the snapshot.
	if e = s.RecordSecurityStatus(ctx, d.ID, "fp", protocol.FeatureReport{Capability: securitystatus.Capability, Status: "failed"}, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordSecurityStatus(ctx, d.ID, "other", protocol.FeatureReport{Capability: securitystatus.Capability, Status: "ok", Data: b}, now.Add(2*time.Minute)); e == nil {
		t.Fatal("unknown certificate accepted")
	}
	got, e := s.SecurityStatus(ctx, d.ID)
	if e != nil || got.Status != "failed" || got.Data == nil || got.Data.BitLocker[0].Drive != "C:" || got.SnapshotAt == nil || *got.SnapshotAt != now.Unix() {
		t.Fatalf("snapshot %+v %v", got, e)
	}
	sums, e := s.SecuritySummaries(ctx)
	if sum := sums[d.ID]; e != nil || sum.BitLocker != "on" || sum.Defender != "real_time_off" || sum.SnapshotAt != now.Unix() {
		t.Fatalf("summaries %+v %v", sums, e)
	}
	// An invalid report is refused and changes nothing.
	v.BitLocker[0].Protection = "maybe"
	b, _ = json.Marshal(v)
	if e = s.RecordSecurityStatus(ctx, d.ID, "fp", protocol.FeatureReport{Capability: securitystatus.Capability, Status: "ok", Data: b}, now.Add(3*time.Minute)); e == nil {
		t.Fatal("invalid report accepted")
	}
}
