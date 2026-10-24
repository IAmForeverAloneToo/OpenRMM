package devices

import (
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sessions"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// SessionsView summarises the signed-in sessions; the full list and
// history come from the sessions endpoint.
type SessionsView struct {
	Capability  protocol.Capability `json:"capability"`
	Status      string              `json:"status"`
	ReportedAt  int64               `json:"reported_at"`
	SnapshotAt  *int64              `json:"snapshot_at"`
	HasSnapshot bool                `json:"has_snapshot"`
	Count       int                 `json:"count"`
	ActiveUsers []string            `json:"active_users"`
	Skipped     int                 `json:"skipped"`
	Stale       bool                `json:"stale"`
	StatusLabel string              `json:"-"`
}

func PresentSessions(value storage.Sessions, device View, now time.Time) SessionsView {
	v := SessionsView{Capability: value.Capability, Status: value.Status, ReportedAt: value.ReportedAt, SnapshotAt: value.SnapshotAt, ActiveUsers: []string{}, Stale: true, StatusLabel: "Not reported"}
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
	if value.Data != nil && sessions.Valid(*value.Data) {
		v.HasSnapshot, v.Count, v.Skipped = true, len(value.Data.Sessions), value.Data.Skipped
		for _, x := range value.Data.Sessions {
			if x.State == "active" {
				name := x.User
				if x.Domain != "" {
					name = x.Domain + `\` + x.User
				}
				v.ActiveUsers = append(v.ActiveUsers, name)
			}
		}
		if value.SnapshotAt != nil {
			age := now.Sub(time.Unix(*value.SnapshotAt, 0))
			// Reports arrive every minute; allow one missed report.
			v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 3*sessions.Interval
		}
	}
	return v
}
