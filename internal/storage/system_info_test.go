package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sysinfo"
)

// The newest device information is stored per device, and the fleet
// identifiers (primary IPv4, addresses, MACs, serial) come from it.
func TestSystemInfoSnapshotAndIdentifiers(t *testing.T) {
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
	v := protocol.SystemInfo{
		Hardware: protocol.Hardware{Manufacturer: "Contoso", Model: "Box", Serial: "SN1"},
		Domain:   protocol.DomainInfo{Join: "workgroup", Entra: "none"},
		Adapters: []protocol.NetworkAdapter{
			{Name: "Hyper-V", Status: "up", Type: "ethernet", MAC: "00:15:5D:00:00:01", IPv4: []string{"172.16.0.1"}, IPv6: []string{}, Gateways: []string{}, DNS: []string{}},
			{Name: "Wi-Fi", Status: "up", Type: "wifi", MAC: "AA:BB:CC:DD:EE:FF", IPv4: []string{"169.254.1.1", "192.0.2.7"}, IPv6: []string{"fe80::1"}, Gateways: []string{"192.0.2.1"}, DNS: []string{}},
		},
	}
	b, _ := json.Marshal(v)
	if e = s.RecordSystemInfo(ctx, d.ID, "fp", protocol.FeatureReport{Capability: sysinfo.Capability, Status: "ok", Data: b}, now); e != nil {
		t.Fatal(e)
	}
	got, e := s.SystemInfo(ctx, d.ID)
	if e != nil || got.Status != "ok" || got.Data == nil || got.Data.Hardware.Serial != "SN1" {
		t.Fatal("snapshot", got, e)
	}
	ids, e := s.DeviceIdentifiers(ctx)
	id := ids[d.ID]
	if e != nil || id.PrimaryIPv4 != "192.0.2.7" || len(id.Addresses) != 4 || len(id.MACs) != 2 || id.Serial != "SN1" || id.Model != "Box" {
		t.Fatalf("identifiers %+v %v", id, e)
	}
	// Without a gateway anywhere, the first connected adapter's address is used.
	v.Adapters[1].Gateways = []string{}
	if PrimaryIPv4(v) != "172.16.0.1" {
		t.Fatal("fallback primary address", PrimaryIPv4(v))
	}
}
