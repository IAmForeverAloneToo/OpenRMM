package sysinfo

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The native collector is read-only; this machine must produce a valid
// report with hardware, CPU, OS and at least one network adapter.
func TestNativeSystemInfo(t *testing.T) {
	b, err := Module{Collector: NewCollector()}.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var v protocol.SystemInfo
	if json.Unmarshal(b, &v) != nil || !Valid(v) {
		t.Fatal("invalid report")
	}
	if v.CPU.LogicalProcessors == 0 || v.CPU.Cores == 0 || v.CPU.Sockets == 0 || v.OS.Build == "" || v.OS.Name == "" || len(v.Adapters) == 0 {
		t.Fatalf("missing values: %+v %+v", v.CPU, v.OS)
	}
	t.Logf("hardware: manufacturer %v, model %v, serial %v, uuid %v, bios %v", v.Hardware.Manufacturer != "", v.Hardware.Model != "", v.Hardware.Serial != "", v.Hardware.UUID != "", v.Hardware.BIOSVersion != "")
	t.Logf("cpu: %d sockets, %d cores, %d logical; os %q %q %q build %s tz %s %+d; join %s entra %s", v.CPU.Sockets, v.CPU.Cores, v.CPU.LogicalProcessors, v.OS.Name, v.OS.Edition, v.OS.DisplayVersion, v.OS.Build, v.OS.TimeZone, v.OS.UTCOffsetMinutes, v.Domain.Join, v.Domain.Entra)
	for _, a := range v.Adapters {
		t.Logf("adapter %s/%s: %d ipv4, %d ipv6, %d gateways, %d dns, dhcp %v, mac %v", a.Type, a.Status, len(a.IPv4), len(a.IPv6), len(a.Gateways), len(a.DNS), a.DHCP, a.MAC != "")
	}
}
