// Package sysinfo reports expanded device information: hardware
// from SMBIOS, CPU model and counts, operating system details, domain and
// Microsoft Entra ID join, and network adapters. It belongs to the Inventory
// feature.
package sysinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "system_info", Version: 1}

const (
	Interval     = 15 * time.Minute
	MaxAdapters  = 32
	MaxAddresses = 16
	MaxServers   = 8
	MaxBytes     = 128 * 1024
	MaxSkipped   = 1 << 16
)

type Collector interface {
	Collect(context.Context) (protocol.SystemInfo, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Collector.Collect(ctx)
	if e != nil {
		return nil, e
	}
	v = Bound(v)
	if !Valid(v) {
		return nil, features.ErrReport
	}
	b, e := json.Marshal(v)
	if len(b) > MaxBytes {
		return nil, features.ErrReport
	}
	return b, e
}

func text(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Clean makes collected text reportable: control characters become spaces,
// space is trimmed, and over-long or invalid text becomes empty.
func Clean(s string, limit int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
	if len(s) > limit || !utf8.ValidString(s) {
		return ""
	}
	return s
}

var macPattern = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5,7}$`)

func addresses(list []string, limit int, v4, v6 bool) bool {
	if list == nil || len(list) > limit {
		return false
	}
	for _, s := range list {
		a, e := netip.ParseAddr(s)
		if e != nil || a.String() != s || a.Is4() && !v4 || !a.Is4() && !v6 {
			return false
		}
	}
	return true
}
func AdapterValid(a protocol.NetworkAdapter) bool {
	switch a.Status {
	case "up", "down", "other":
	default:
		return false
	}
	switch a.Type {
	case "ethernet", "wifi", "other":
	default:
		return false
	}
	server := a.DHCPServer == "" || addresses([]string{a.DHCPServer}, 1, true, true)
	return a.Name != "" && text(a.Name, 256) && text(a.Description, 256) && (a.MAC == "" || macPattern.MatchString(a.MAC)) &&
		addresses(a.IPv4, MaxAddresses, true, false) && addresses(a.IPv6, MaxAddresses, false, true) && addresses(a.Gateways, MaxServers, true, true) && addresses(a.DNS, MaxServers, true, true) && server
}
func Valid(v protocol.SystemInfo) bool {
	h, c, o, d := v.Hardware, v.CPU, v.OS, v.Domain
	for _, s := range []string{h.Manufacturer, h.Model, h.Serial, h.UUID, h.BIOSVendor, h.BIOSVersion, h.BIOSDate, c.Model, o.Name, o.Edition, o.DisplayVersion, o.Build, o.TimeZone, d.Name, d.EntraTenant, d.EntraTenantID} {
		if !text(s, 256) {
			return false
		}
	}
	switch d.Join {
	case "domain", "workgroup", "unjoined", "unknown":
	default:
		return false
	}
	switch d.Entra {
	case "joined", "registered", "none", "unknown":
	default:
		return false
	}
	if c.Sockets < 0 || c.Sockets > 64 || c.Cores < 0 || c.Cores > 4096 || c.LogicalProcessors < 0 || c.LogicalProcessors > 8192 || o.InstallDate < 0 || o.UTCOffsetMinutes < -840 || o.UTCOffsetMinutes > 840 {
		return false
	}
	if v.Adapters == nil || len(v.Adapters) > MaxAdapters || v.Skipped < 0 || v.Skipped > MaxSkipped {
		return false
	}
	for _, a := range v.Adapters {
		if !AdapterValid(a) {
			return false
		}
	}
	return true
}

// Bound keeps the first MaxAdapters valid adapters (in the order Windows lists
// them, which follows interface metrics) and counts the rest as skipped.
func Bound(v protocol.SystemInfo) protocol.SystemInfo {
	list := v.Adapters
	v.Adapters = []protocol.NetworkAdapter{}
	for _, a := range list {
		if !AdapterValid(a) || len(v.Adapters) >= MaxAdapters {
			v.Skipped++
			continue
		}
		v.Adapters = append(v.Adapters, a)
	}
	v.Skipped = min(v.Skipped, MaxSkipped)
	return v
}

// shape is a report with every field present (arrays with one element), used
// to require exactly these fields with these JSON types.
var shape = func() any {
	b, _ := json.Marshal(protocol.SystemInfo{Adapters: []protocol.NetworkAdapter{{IPv4: []string{""}, IPv6: []string{""}, Gateways: []string{""}, DNS: []string{""}}}, Skipped: 1})
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}()

// sameShape: objects carry exactly the shape's keys (optional: skipped), and
// every value has the shape's JSON type; null never matches.
func sameShape(v, s any) bool {
	switch s := s.(type) {
	case map[string]any:
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for k := range m {
			if _, ok := s[k]; !ok {
				return false
			}
		}
		for k, sub := range s {
			x, ok := m[k]
			if !ok {
				if k == "skipped" {
					continue
				}
				return false
			}
			if !sameShape(x, sub) {
				return false
			}
		}
		return true
	case []any:
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !sameShape(x, s[0]) {
				return false
			}
		}
		return true
	case string:
		_, ok := v.(string)
		return ok
	case float64:
		_, ok := v.(float64)
		return ok
	case bool:
		_, ok := v.(bool)
		return ok
	}
	return false
}

// Normalize is the server's strict decoder: every field is required with its
// type, unknown fields are rejected and the report is re-encoded.
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	bad := func() (protocol.FeatureReport, error) { return r, features.ErrReport }
	if r.Capability.Name != Capability.Name || r.Capability.Version < 1 || r.Capability.Version > 999 {
		return bad()
	}
	switch r.Status {
	case "ok", "failed", "disabled", "unsupported":
	default:
		return bad()
	}
	if r.Capability.Version != 1 {
		r.Status, r.Data = "unsupported", nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) != 0 {
			return bad()
		}
		return r, nil
	}
	if len(r.Data) > MaxBytes {
		return bad()
	}
	var generic any
	d := json.NewDecoder(bytes.NewReader(r.Data))
	if d.Decode(&generic) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || !sameShape(generic, shape) {
		return bad()
	}
	var v protocol.SystemInfo
	d = json.NewDecoder(bytes.NewReader(r.Data))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || !Valid(v) {
		return bad()
	}
	r.Data, _ = json.Marshal(v)
	return r, nil
}
