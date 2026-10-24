package devices

import (
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"time"
)

type UpdateSupportView struct {
	storage.UpdateSupport
	Stale       bool   `json:"stale"`
	StatusLabel string `json:"-"`
	LastReport  string `json:"-"`
	LastSuccess string `json:"-"`
}

func PresentUpdateSupport(value storage.UpdateSupport, device View, now time.Time) UpdateSupportView {
	v := UpdateSupportView{UpdateSupport: value, Stale: true, LastReport: "Never", LastSuccess: "Never", StatusLabel: "Not reported"}
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
		stamp := time.Unix(*value.SnapshotAt, 0)
		v.LastSuccess = stamp.UTC().Format(time.RFC3339)
		age := now.Sub(stamp)
		v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 2*time.Minute
	}
	if value.Data == nil || !windowsupdate.SupportValid(*value.Data) {
		v.Stale = true
	}
	return v
}
