package devices

import (
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"time"
)

// The device summary does not duplicate the potentially large application list.
type SoftwareView struct {
	Capability    protocol.Capability `json:"capability"`
	Status        string              `json:"status"`
	ReportedAt    int64               `json:"reported_at"`
	SnapshotAt    *int64              `json:"snapshot_at"`
	Coverage      string              `json:"coverage"`
	Count         int                 `json:"count"`
	HasSnapshot   bool                `json:"has_snapshot"`
	BaselineReady bool                `json:"baseline_ready"`
	Stale         bool                `json:"stale"`
	StatusLabel   string              `json:"-"`
	LastReport    string              `json:"-"`
	LastSuccess   string              `json:"-"`
}

func PresentSoftware(value storage.Software, device View, now time.Time) SoftwareView {
	has, coverage, count := false, "", 0
	if value.Data != nil && software.Valid(*value.Data) {
		has, coverage, count = true, value.Data.Coverage, len(value.Data.Entries)
	}
	return presentSoftware(value, device, now, has, coverage, count)
}

func PresentFleetSoftware(value storage.FleetSoftwareDevice, device View, now time.Time) SoftwareView {
	return presentSoftware(storage.Software{Capability: value.Capability, Status: value.Status, ReportedAt: value.ReportedAt, SnapshotAt: value.SnapshotAt}, device, now, value.HasSnapshot, value.Coverage, value.Registrations)
}

func presentSoftware(value storage.Software, device View, now time.Time, has bool, coverage string, count int) SoftwareView {
	v := SoftwareView{Capability: value.Capability, Status: value.Status, ReportedAt: value.ReportedAt, SnapshotAt: value.SnapshotAt, BaselineReady: value.BaselineReady, Stale: true, StatusLabel: "Not reported", LastReport: "Never", LastSuccess: "Never"}
	switch value.Status {
	case "ok":
		v.StatusLabel = "Collected"
	case "failed":
		v.StatusLabel = "Collection failed"
	case "disabled":
		v.StatusLabel = "Disabled"
	case "unsupported":
		v.StatusLabel = "Unsupported"
	}
	if value.ReportedAt != 0 {
		v.LastReport = time.Unix(value.ReportedAt, 0).UTC().Format(time.RFC3339)
	}
	if value.SnapshotAt != nil {
		v.LastSuccess = time.Unix(*value.SnapshotAt, 0).UTC().Format(time.RFC3339)
	}
	if has {
		v.HasSnapshot = true
		v.Coverage = coverage
		v.Count = count
		if value.SnapshotAt != nil {
			age := now.Sub(time.Unix(*value.SnapshotAt, 0))
			v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 2*software.Interval
		}
	}
	return v
}
