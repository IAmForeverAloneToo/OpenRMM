package sysinfo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func sample() protocol.SystemInfo {
	return protocol.SystemInfo{
		Hardware: protocol.Hardware{Manufacturer: "Contoso", Model: "Box 1", Serial: "SN123"},
		CPU:      protocol.CPUInfo{Model: "CPU", Sockets: 1, Cores: 8, LogicalProcessors: 16},
		OS:       protocol.OSInfo{Name: "Windows 11 Pro", Build: "22631.1", UTCOffsetMinutes: 540},
		Domain:   protocol.DomainInfo{Join: "workgroup", Name: "WORKGROUP", Entra: "none"},
		Adapters: []protocol.NetworkAdapter{{Name: "Ethernet", MAC: "00:11:22:33:44:55", Status: "up", Type: "ethernet", IPv4: []string{"192.0.2.5"}, IPv6: []string{"fe80::1"}, Gateways: []string{"192.0.2.1"}, DNS: []string{"192.0.2.53"}, DHCP: true, DHCPServer: "192.0.2.1"}},
	}
}

func TestSystemInfoStrictShape(t *testing.T) {
	good, _ := json.Marshal(sample())
	if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: good}); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"missing field":    strings.Replace(string(good), `"serial":"SN123",`, ``, 1),
		"unknown field":    strings.Replace(string(good), `"serial":"SN123"`, `"serial":"SN123","owner":"x"`, 1),
		"null list":        strings.Replace(string(good), `"dns":["192.0.2.53"]`, `"dns":null`, 1),
		"wrong type":       strings.Replace(string(good), `"cores":8`, `"cores":"8"`, 1),
		"fraction":         strings.Replace(string(good), `"cores":8`, `"cores":8.5`, 1),
		"bad join":         strings.Replace(string(good), `"join":"workgroup"`, `"join":"cloud"`, 1),
		"bad mac":          strings.Replace(string(good), `00:11:22:33:44:55`, `00-11-22-33-44-55`, 1),
		"v6 in ipv4":       strings.Replace(string(good), `"ipv4":["192.0.2.5"]`, `"ipv4":["fe80::2"]`, 1),
		"bad offset":       strings.Replace(string(good), `"utc_offset_minutes":540`, `"utc_offset_minutes":5000`, 1),
		"control in text":  strings.Replace(string(good), `"Box 1"`, `"Box\u00071"`, 1),
		"adapter nameless": strings.Replace(string(good), `"name":"Ethernet"`, `"name":""`, 1),
	} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(raw)}); !errors.Is(err, features.ErrReport) {
			t.Fatal(name, "accepted")
		}
	}
}

type fixed struct{ v protocol.SystemInfo }

func (f fixed) Collect(context.Context) (protocol.SystemInfo, error) { return f.v, nil }

func TestModuleBoundsAdapters(t *testing.T) {
	v := sample()
	for i := 0; i < MaxAdapters+3; i++ {
		v.Adapters = append(v.Adapters, sample().Adapters[0])
	}
	v.Adapters = append(v.Adapters, protocol.NetworkAdapter{Name: "bad", Status: "?"})
	b, err := Module{Collector: fixed{v}}.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out protocol.SystemInfo
	if json.Unmarshal(b, &out) != nil || len(out.Adapters) != MaxAdapters || out.Skipped != 5 || !Valid(out) {
		t.Fatal("bounds", len(out.Adapters), out.Skipped)
	}
}

func TestClean(t *testing.T) {
	if Clean("  To be\x00filled  ", 64) != "To be filled" || Clean(strings.Repeat("x", 300), 256) != "" || Clean("\xff", 64) != "�" {
		t.Fatal("clean")
	}
}
