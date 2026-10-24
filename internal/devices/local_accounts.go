package devices

import (
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/localaccounts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// LocalAccountsView summarises local accounts and privileged groups; the
// lists come from the local accounts endpoint.
type LocalAccountsView struct {
	Capability     protocol.Capability `json:"capability"`
	Status         string              `json:"status"`
	ReportedAt     int64               `json:"reported_at"`
	SnapshotAt     *int64              `json:"snapshot_at"`
	HasSnapshot    bool                `json:"has_snapshot"`
	Accounts       int                 `json:"accounts"`
	Enabled        int                 `json:"enabled"`
	Administrators int                 `json:"administrators"`
	RemoteDesktop  int                 `json:"remote_desktop_users"`
	Stale          bool                `json:"stale"`
}

func PresentLocalAccounts(value storage.LocalAccounts, device View, now time.Time) LocalAccountsView {
	v := LocalAccountsView{Capability: value.Capability, Status: value.Status, ReportedAt: value.ReportedAt, SnapshotAt: value.SnapshotAt, Stale: true}
	if value.Data != nil && localaccounts.Valid(*value.Data) {
		v.HasSnapshot, v.Accounts = true, len(value.Data.Accounts)
		for _, a := range value.Data.Accounts {
			if a.Enabled {
				v.Enabled++
			}
		}
		for _, g := range value.Data.Groups {
			switch g.Key {
			case "administrators":
				v.Administrators = len(g.Members)
			case "remote_desktop_users":
				v.RemoteDesktop = len(g.Members)
			}
		}
		if value.SnapshotAt != nil {
			age := now.Sub(time.Unix(*value.SnapshotAt, 0))
			v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 2*localaccounts.Interval
		}
	}
	return v
}
