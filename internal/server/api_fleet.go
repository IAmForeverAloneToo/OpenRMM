package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func (a *api) offlineAfter() time.Duration {
	if a.devices != nil && a.devices.OfflineAfter > 0 {
		return a.devices.OfflineAfter
	}
	return 120 * time.Second
}

type fleetDevice struct {
	devices.View
	ActiveAlerts   int `json:"active_alerts"`
	CriticalAlerts int `json:"critical_alerts"`
}

type fleetGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// visibleDevices returns the devices the session may see, with organization
// metadata and active alert counts attached.
func (a *api) visibleDevices(ctx context.Context, s storage.Session, now time.Time) ([]fleetDevice, []fleetGroup, error) {
	list, err := devices.List(ctx, a.store, now, a.offlineAfter())
	if err != nil {
		return nil, nil, err
	}
	o, err := a.store.Organization(ctx)
	if err != nil {
		return nil, nil, err
	}
	o = visibleOrganization(o, s)
	meta := map[string]storage.OrganizedDevice{}
	for _, d := range o.Devices {
		meta[d.ID] = d
	}
	groupNames := map[string]string{}
	groups := []fleetGroup{}
	for _, g := range o.Groups {
		groupNames[g.ID] = g.Name
		groups = append(groups, fleetGroup{g.ID, g.Name})
	}
	alerts, err := a.store.AlertsForSession(ctx, s, "")
	if err != nil {
		return nil, nil, err
	}
	active, critical := map[string]int{}, map[string]int{}
	for _, al := range alerts {
		if al.Status == "active" {
			active[al.DeviceID]++
			if al.Severity == "critical" {
				critical[al.DeviceID]++
			}
		}
	}
	out := []fleetDevice{}
	for _, v := range list {
		d, organized := meta[v.ID]
		// The organization projection only lists active devices visible to
		// this account; technicians never see devices outside their scope.
		if s.Technician != nil && !organized {
			continue
		}
		if organized {
			v.GroupID, v.GroupName, v.Tags = d.GroupID, groupNames[d.GroupID], d.Tags
			_, v.PolicySource = o.Effective(d)
		}
		out = append(out, fleetDevice{View: v, ActiveAlerts: active[v.ID], CriticalAlerts: critical[v.ID]})
	}
	return out, groups, nil
}

func visibleDevice(v storage.Session, d storage.OrganizedDevice) bool {
	return v.Technician == nil || v.Technician.Access.Includes(d)
}

func visibleOrganization(o storage.Organization, v storage.Session) storage.Organization {
	if v.Technician == nil {
		return o
	}
	list := []storage.OrganizedDevice{}
	groups := map[string]int{}
	for _, d := range o.Devices {
		if visibleDevice(v, d) {
			list = append(list, d)
			groups[d.GroupID]++
		}
	}
	o.Devices = list
	selected := []storage.DeviceGroup{}
	for _, g := range o.Groups {
		if n := groups[g.ID]; n > 0 {
			g.Members = n
			selected = append(selected, g)
		}
	}
	o.Groups = selected
	return o
}

type attentionItem struct {
	DeviceID string   `json:"device_id"`
	Hostname string   `json:"hostname"`
	Status   string   `json:"status"`
	Reasons  []string `json:"reasons"`
}

func registerFleetAPI(mux *http.ServeMux, a *api) {
	a.route(mux, "GET /api/v1/devices", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, groups, err := a.visibleDevices(r.Context(), s, time.Now())
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Devices are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Devices []fleetDevice `json:"devices"`
			Groups  []fleetGroup  `json:"groups"`
		}{list, groups})
	})

	a.route(mux, "GET /api/v1/dashboard", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		now := time.Now()
		list, _, err := a.visibleDevices(r.Context(), s, now)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The dashboard is temporarily unavailable.")
			return
		}
		type fleetCounts struct {
			Total           int `json:"total"`
			Online          int `json:"online"`
			Offline         int `json:"offline"`
			AwaitingContact int `json:"awaiting_contact"`
			Revoked         int `json:"revoked"`
			LowDisk         int `json:"low_disk"`
		}
		counts := fleetCounts{}
		attention := []attentionItem{}
		for _, d := range list {
			counts.Total++
			switch d.Status {
			case "online":
				counts.Online++
			case "offline":
				counts.Offline++
			case "revoked":
				counts.Revoked++
			default:
				counts.AwaitingContact++
			}
			if d.Status == "revoked" {
				continue
			}
			reasons := []string{}
			if d.Status == "offline" {
				reasons = append(reasons, "offline")
			}
			if d.DiskSpaceWarning == "low" {
				counts.LowDisk++
				reasons = append(reasons, "low_disk")
			}
			if d.CriticalAlerts > 0 {
				reasons = append(reasons, "critical_alert")
			} else if d.ActiveAlerts > 0 {
				reasons = append(reasons, "alert")
			}
			if len(reasons) > 0 {
				attention = append(attention, attentionItem{d.ID, d.Hostname, d.Status, reasons})
			}
		}
		if len(attention) > 50 {
			attention = attention[:50]
		}
		triage, err := a.store.AlertTriage(r.Context(), s, storage.AlertFilter{Status: "active", Page: 1})
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Alerts are temporarily unavailable.")
			return
		}
		recentAlerts := triage.Alerts
		if len(recentAlerts) > 10 {
			recentAlerts = recentAlerts[:10]
		}
		activity, err := a.store.FleetActivity(r.Context(), s, now, 15)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Activity is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			GeneratedAt int64                 `json:"generated_at"`
			Fleet       fleetCounts           `json:"fleet"`
			Attention   []attentionItem       `json:"attention"`
			Alerts      storage.AlertCounts   `json:"alert_counts"`
			AlertList   []storage.Alert       `json:"alerts"`
			Activity    storage.FleetActivity `json:"activity"`
		}{now.Unix(), counts, attention, triage.Counts, recentAlerts, activity})
	})

	a.route(mux, "GET /api/v1/devices/{id}", deviceAccess("read"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		id := r.PathValue("id")
		if !protocol.ValidID(id) {
			apiError(w, http.StatusNotFound, "not_found", "Device not found.")
			return
		}
		ctx, now := r.Context(), time.Now()
		d, err := a.store.Device(ctx, id)
		if errors.Is(err, storage.ErrAuthentication) {
			apiError(w, http.StatusNotFound, "not_found", "Device not found.")
			return
		}
		fail := func() {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Device details are temporarily unavailable.")
		}
		if err != nil {
			fail()
			return
		}
		inventory, e1 := a.store.Inventory(ctx, id)
		disk, e2 := a.store.DiskSpace(ctx, id)
		memory, e3 := a.store.Memory(ctx, id)
		cpu, e4 := a.store.CPU(ctx, id)
		uptime, e5 := a.store.Uptime(ctx, id)
		updates, e6 := a.store.UpdateSupport(ctx, id)
		events, e7 := a.store.EventLogs(ctx, id)
		services, e8 := a.store.Services(ctx, id)
		software, e9 := a.store.Software(ctx, id)
		signedIn, e15 := a.store.Sessions(ctx, id)
		accounts, e16 := a.store.LocalAccounts(ctx, id)
		system, e17 := a.store.SystemInfo(ctx, id)
		security, e18 := a.store.SecurityStatus(ctx, id)
		isolation, e19 := a.store.DeviceIsolation(ctx, id)
		reported, e20 := a.store.ReportedIsolation(ctx, id)
		alerts, e10 := a.store.AlertsForSession(ctx, s, id)
		activity, e11 := a.store.WorkspaceActivity(ctx, s, id, now)
		org, e12 := a.store.Organization(ctx)
		locks, e13 := a.store.FeatureLocks(ctx, id)
		disabled, e14 := a.store.DisabledFeatures(ctx, id)
		if err = errors.Join(e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17, e18, e19, e20); err != nil {
			fail()
			return
		}
		view := devices.Present(d, now, a.offlineAfter())
		// Read directly: the organization view covers only the newest devices.
		view.DisabledFeatures, view.LockedFeatures = disabled, locks
		for _, o := range org.Devices {
			if o.ID == id {
				view.GroupID, view.Tags = o.GroupID, o.Tags
				_, view.PolicySource = org.Effective(o)
			}
		}
		for _, g := range org.Groups {
			if g.ID == view.GroupID {
				view.GroupName = g.Name
			}
		}
		if system.Data != nil {
			id := devices.PresentSystemInfo(system, view, now)
			view.PrimaryIPv4, view.Serial, view.Manufacturer, view.Model = id.PrimaryIPv4, system.Data.Hardware.Serial, system.Data.Hardware.Manufacturer, system.Data.Hardware.Model
		}
		sessionsView := devices.PresentSessions(signedIn, view, now)
		if !sessionsView.Stale {
			view.SignedInUsers = sessionsView.ActiveUsers
		}
		diskView := devices.PresentDiskSpace(disk, view, now)
		view.DiskSpaceWarning = diskView.Warning
		softwareView := devices.PresentSoftware(software, view, now)
		securityView := devices.PresentSecurityStatus(security, view, now)
		if !s.Can("response") || a.store.AuthorizeDevice(ctx, s, id, "response") != nil {
			isolation.Code = ""
		}
		if isolation.ID != "" && isolation.Phase != "released" && isolation.Phase != "failed" {
			view.Isolation = isolation.Phase
		}
		if securityView.Data != nil {
			view.BitLocker, view.Defender, view.SecurityStale = securityView.BitLocker, securityView.Defender, securityView.Stale
		}
		writeJSON(w, http.StatusOK, struct {
			Device    devices.View               `json:"device"`
			Inventory devices.InventoryView      `json:"inventory"`
			DiskSpace devices.DiskSpaceView      `json:"disk_space"`
			Memory    devices.MemoryView         `json:"memory"`
			CPU       devices.CPUView            `json:"cpu"`
			Uptime    devices.UptimeView         `json:"uptime"`
			Services  devices.ServicesView       `json:"services"`
			EventLogs devices.EventLogsView      `json:"event_logs"`
			Updates   devices.UpdateSupportView  `json:"windows_updates"`
			Software  devices.SoftwareView       `json:"software"`
			Sessions  devices.SessionsView       `json:"sessions"`
			Accounts  devices.LocalAccountsView  `json:"local_accounts"`
			System    devices.SystemInfoView     `json:"system_info"`
			Security  devices.SecurityStatusView `json:"security_status"`
			Isolation struct {
				storage.Isolation
				Reported protocol.IsolationState `json:"reported"`
			} `json:"isolation"`
			Alerts   []storage.Alert           `json:"alerts"`
			Activity storage.WorkspaceActivity `json:"activity"`
		}{view, devices.PresentInventory(inventory, view, now), diskView, devices.PresentMemory(memory, view, now), devices.PresentCPU(cpu, view, now), devices.PresentUptime(uptime, view, now), devices.PresentServices(services, view, now), devices.PresentEventLogs(events, view, now), devices.PresentUpdateSupport(updates, view, now), softwareView, sessionsView, devices.PresentLocalAccounts(accounts, view, now), devices.PresentSystemInfo(system, view, now), securityView, struct {
			storage.Isolation
			Reported protocol.IsolationState `json:"reported"`
		}{isolation, reported}, alerts, activity})
	})

	a.route(mux, "POST /api/v1/enrollment-tokens", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if a.devices == nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Enrollment is unavailable.")
			return
		}
		token, t, err := a.devices.CreateToken(r.Context(), devices.TokenRequest{Actor: s.Actor()})
		if errors.Is(err, storage.ErrEnrollmentToken) {
			apiError(w, http.StatusConflict, "limit", "Too many unused tokens. Wait for one to expire and retry.")
			return
		}
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Cannot create a token. Wait for pending tokens to expire and retry.")
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expires_at"`
		}{token, t.ExpiresAt})
	})

	// Revocation needs typed confirmation: the request must repeat the exact
	// hostname, checked here as well as in the browser.
	a.route(mux, "POST /api/v1/devices/{id}/revoke", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		id := r.PathValue("id")
		var in struct {
			Confirm string `json:"confirm"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		d, err := a.store.Device(r.Context(), id)
		if errors.Is(err, storage.ErrAuthentication) || !protocol.ValidID(id) {
			apiError(w, http.StatusNotFound, "not_found", "Device not found.")
			return
		}
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Revocation is temporarily unavailable.")
			return
		}
		if in.Confirm != d.Hostname {
			apiError(w, http.StatusBadRequest, "confirmation", "Type the device name exactly to confirm.")
			return
		}
		if err := a.store.RevokeDevice(r.Context(), id, time.Now()); err != nil {
			if errors.Is(err, storage.ErrAuthentication) {
				apiError(w, http.StatusNotFound, "not_found", "Device not found.")
			} else {
				apiError(w, http.StatusServiceUnavailable, "unavailable", "Revocation is temporarily unavailable.")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
