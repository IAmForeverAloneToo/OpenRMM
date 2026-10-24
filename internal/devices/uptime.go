package devices

import (
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/uptime"
	"time"
)

type UptimeView struct {
	storage.Uptime
	Stale         bool   `json:"stale"`
	StatusLabel   string `json:"-"`
	LastReport    string `json:"-"`
	LastSuccess   string `json:"-"`
	Duration      string `json:"-"`
	EstimatedBoot string `json:"-"`
}

func PresentUptime(value storage.Uptime, device View, now time.Time) UptimeView {
	v := UptimeView{Uptime: value, Stale: true, LastReport: "Never", LastSuccess: "Never", EstimatedBoot: "Unknown"}
	switch value.Status {
	case "ok":
		v.StatusLabel = "Collected"
	case "failed":
		v.StatusLabel = "Collection failed"
	case "disabled":
		v.StatusLabel = "Disabled"
	case "unsupported":
		v.StatusLabel = "Unsupported"
	default:
		v.StatusLabel = "Not reported"
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
	if value.Data != nil && uptime.Valid(*value.Data) {
		seconds := value.Data.UptimeSeconds
		v.Duration = fmt.Sprintf("%dd %02dh %02dm %02ds", seconds/86400, seconds/3600%24, seconds/60%60, seconds%60)
		v.EstimatedBoot = time.Unix(value.Data.EstimatedBootAt, 0).UTC().Format(time.RFC3339)
	} else {
		v.Stale = true
	}
	return v
}
