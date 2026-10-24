package devices

import (
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sysinfo"
)

// SystemInfoView is the expanded device information with its
// freshness; the report is small, so the device page gets all of it.
type SystemInfoView struct {
	Capability  protocol.Capability  `json:"capability"`
	Status      string               `json:"status"`
	ReportedAt  int64                `json:"reported_at"`
	SnapshotAt  *int64               `json:"snapshot_at"`
	Data        *protocol.SystemInfo `json:"data"`
	PrimaryIPv4 string               `json:"primary_ipv4"`
	Stale       bool                 `json:"stale"`
}

func PresentSystemInfo(value storage.SystemInfo, device View, now time.Time) SystemInfoView {
	v := SystemInfoView{Capability: value.Capability, Status: value.Status, ReportedAt: value.ReportedAt, SnapshotAt: value.SnapshotAt, Stale: true}
	if value.Data != nil && sysinfo.Valid(*value.Data) {
		v.Data, v.PrimaryIPv4 = value.Data, storage.PrimaryIPv4(*value.Data)
		if value.SnapshotAt != nil {
			age := now.Sub(time.Unix(*value.SnapshotAt, 0))
			v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 2*sysinfo.Interval
		}
	}
	return v
}
