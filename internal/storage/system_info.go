package storage

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sysinfo"
)

type SystemInfo struct {
	Capability protocol.Capability  `json:"capability"`
	Status     string               `json:"status"`
	ReportedAt int64                `json:"reported_at"`
	SnapshotAt *int64               `json:"snapshot_at"`
	Data       *protocol.SystemInfo `json:"data"`
}

// RecordSystemInfo stores the newest report after repeating device
// authorization; failed and out-of-order reports keep the last snapshot.
func (s *Store) RecordSystemInfo(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	report, e := sysinfo.Normalize(report)
	if e != nil {
		return e
	}
	if e = s.recordSnapshot(ctx, "device_system_info", id, fingerprint, report, now); e != nil || report.Status != "ok" {
		return e
	}
	var v protocol.SystemInfo
	if json.Unmarshal(report.Data, &v) != nil {
		return errors.New("cannot persist device information")
	}
	d := identifiers(v)
	// Only when this report is the stored one (not out of order).
	if _, e = s.db.ExecContext(ctx, `UPDATE device_system_info SET primary_ipv4=?,addresses=?,macs=?,serial=?,manufacturer=?,model=? WHERE device_id=? AND reported_at=? AND last_status='ok'`, d.PrimaryIPv4, strings.Join(d.Addresses, ","), strings.Join(d.MACs, ","), d.Serial, d.Manufacturer, d.Model, id, now.Unix()); e != nil {
		return errors.New("cannot persist device information")
	}
	return nil
}

func (s *Store) SystemInfo(ctx context.Context, id string) (SystemInfo, error) {
	v := SystemInfo{Capability: sysinfo.Capability}
	data, e := s.readSnapshot(ctx, "device_system_info", id, &v.Capability, &v.Status, &v.ReportedAt, &v.SnapshotAt)
	if e != nil {
		return v, errors.New("cannot read device information")
	}
	if data != "" {
		v.Data = new(protocol.SystemInfo)
		if json.Unmarshal([]byte(data), v.Data) != nil || !sysinfo.Valid(*v.Data) {
			return v, errors.New("cannot decode device information")
		}
	}
	return v, nil
}

// DeviceIdentifiers are the fleet list's search and display values from the
// last good device information report.
type DeviceIdentifiers struct {
	PrimaryIPv4  string
	Addresses    []string
	MACs         []string
	Serial       string
	Manufacturer string
	Model        string
}

// PrimaryIPv4 is the first IPv4 address of a connected adapter with an IPv4
// gateway, else of any connected adapter; link-local is never chosen.
func PrimaryIPv4(v protocol.SystemInfo) string {
	hasGateway := func(a protocol.NetworkAdapter) bool {
		for _, g := range a.Gateways {
			if ip, e := netip.ParseAddr(g); e == nil && ip.Is4() {
				return true
			}
		}
		return false
	}
	for _, gateway := range []bool{true, false} {
		for _, a := range v.Adapters {
			if a.Status != "up" || gateway && !hasGateway(a) {
				continue
			}
			for _, s := range a.IPv4 {
				if ip, e := netip.ParseAddr(s); e == nil && !ip.IsLinkLocalUnicast() {
					return s
				}
			}
		}
	}
	return ""
}

func identifiers(v protocol.SystemInfo) DeviceIdentifiers {
	d := DeviceIdentifiers{PrimaryIPv4: PrimaryIPv4(v), Addresses: []string{}, MACs: []string{}, Serial: v.Hardware.Serial, Manufacturer: v.Hardware.Manufacturer, Model: v.Hardware.Model}
	for _, a := range v.Adapters {
		d.Addresses = append(append(d.Addresses, a.IPv4...), a.IPv6...)
		if a.MAC != "" {
			d.MACs = append(d.MACs, a.MAC)
		}
	}
	return d
}

func split(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

// DeviceIdentifiers reads the stored identifier columns of the last good
// reports; it never decodes the reports themselves.
func (s *Store) DeviceIdentifiers(ctx context.Context) (map[string]DeviceIdentifiers, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT device_id,primary_ipv4,addresses,macs,serial,manufacturer,model FROM device_system_info WHERE snapshot_json<>''`)
	if e != nil {
		return nil, errors.New("cannot read device identifiers")
	}
	defer rows.Close()
	out := map[string]DeviceIdentifiers{}
	for rows.Next() {
		var id, addresses, macs string
		var d DeviceIdentifiers
		if rows.Scan(&id, &d.PrimaryIPv4, &addresses, &macs, &d.Serial, &d.Manufacturer, &d.Model) != nil {
			return nil, errors.New("cannot read device identifiers")
		}
		d.Addresses, d.MACs = split(addresses), split(macs)
		out[id] = d
	}
	return out, rows.Err()
}
