package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

type observation struct {
	Condition  string   `json:"condition"` // bad, good or unknown
	Value      *float64 `json:"value"`
	ObservedAt int64    `json:"observed_at"`
}

func evaluatorStale(r storage.AlertRuntime, now time.Time) bool {
	return r.LastSweep > now.Unix() || now.Unix()-r.LastSweep >= 45
}

// incidentObservation is the current observation linked to an active
// incident. Anything stale, unlinked or ambiguous is "unknown"; unknown never
// counts as recovery.
func incidentObservation(a storage.Alert, states []storage.AlertDeviceState, runtime storage.AlertRuntime, now time.Time) observation {
	out := observation{Condition: "unknown"}
	if a.Status != "active" {
		return out
	}
	for _, s := range states {
		if s.DeviceID != a.DeviceID || s.Kind != a.Kind || s.Incident != a.ID {
			continue
		}
		out.ObservedAt = s.LastSample
		if evaluatorStale(runtime, now) || s.LastSample > now.Unix() || now.Unix()-s.LastSample >= alerting.Freshness(a.Kind) || (s.Condition != "bad" && s.Condition != "good") {
			return out
		}
		out.Condition, out.Value = s.Condition, s.Value
		return out
	}
	return out
}

func alertFilter(q url.Values) (storage.AlertFilter, bool) {
	f := storage.AlertFilter{Page: 1}
	for key, values := range q {
		if len(values) != 1 {
			return f, false
		}
		switch key {
		case "device", "group", "tag", "status", "ack", "severity", "kind", "q", "page":
		default:
			return f, false
		}
	}
	f.Device, f.Group, f.Tag, f.Status, f.Acknowledgment, f.Severity, f.Kind, f.Query = q.Get("device"), q.Get("group"), q.Get("tag"), q.Get("status"), q.Get("ack"), q.Get("severity"), q.Get("kind"), q.Get("q")
	if q.Has("page") {
		n, e := strconv.Atoi(q.Get("page"))
		if e != nil {
			return f, false
		}
		f.Page = n
	}
	return f, f.Valid()
}

func registerAlertsAPI(mux *http.ServeMux, a *api) {
	unavailable := func(w http.ResponseWriter) {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Alerts are temporarily unavailable.")
	}

	a.route(mux, "GET /api/v1/alerts", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		f, ok := alertFilter(r.URL.Query())
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid alert filters.")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		if f.Device != "" && s.Technician != nil {
			if e := a.store.AuthorizeDevice(ctx, s, f.Device, "read"); e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		now := time.Now()
		result, e1 := a.store.AlertTriage(ctx, s, f)
		runtime, e2 := a.store.AlertRuntime(ctx)
		states, e3 := a.store.AlertStatesForSession(ctx, s, f.Device)
		org, e4 := a.store.Organization(ctx)
		if errors.Join(e1, e2, e3, e4) != nil {
			unavailable(w)
			return
		}
		type row struct {
			storage.Alert
			Observation observation `json:"observation"`
		}
		rows := []row{}
		for _, al := range result.Alerts {
			o := incidentObservation(al, states, runtime, now)
			if al.Status == "active" {
				al.Condition = o.Condition
			}
			rows = append(rows, row{al, o})
		}
		groups := []fleetGroup{}
		for _, g := range visibleOrganization(org, s).Groups {
			groups = append(groups, fleetGroup{g.ID, g.Name})
		}
		writeJSON(w, http.StatusOK, struct {
			Counts   storage.AlertCounts `json:"counts"`
			Page     int                 `json:"page"`
			PageSize int                 `json:"page_size"`
			Alerts   []row               `json:"alerts"`
			Stale    bool                `json:"evaluator_stale"`
			Groups   []fleetGroup        `json:"groups"`
		}{result.Counts, result.Page, result.PageSize, rows, evaluatorStale(runtime, now), groups})
	})

	a.route(mux, "GET /api/v1/alerts/{incident}", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		al, e := a.store.AlertIncidentForSession(ctx, s, r.PathValue("incident"))
		if errors.Is(e, storage.ErrAlertNotFound) {
			apiError(w, http.StatusNotFound, "not_found", "Alert not found.")
			return
		}
		if e != nil {
			unavailable(w)
			return
		}
		now := time.Now()
		states, e1 := a.store.AlertStatesForSession(ctx, s, al.DeviceID)
		runtime, e2 := a.store.AlertRuntime(ctx)
		deliveries, e3 := a.store.IncidentDeliveriesForSession(ctx, s, al.ID)
		if errors.Join(e1, e2, e3) != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Alert       storage.Alert           `json:"alert"`
			Family      string                  `json:"family"`
			Observation observation             `json:"observation"`
			Deliveries  []storage.AlertDelivery `json:"deliveries"`
			Stale       bool                    `json:"evaluator_stale"`
		}{al, storage.AlertRuleFamily(al.Kind), incidentObservation(al, states, runtime, now), deliveries, evaluatorStale(runtime, now)})
	})

	// Acknowledging marks an incident as seen; it stays open until recovery.
	a.route(mux, "POST /api/v1/alerts/{incident}/acknowledge", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.AcknowledgeAlert(r.Context(), r.PathValue("incident"), s.Username, time.Now()); e != nil {
			apiError(w, http.StatusConflict, "refused", "This alert can no longer be acknowledged. Refresh to see its current state.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	a.route(mux, "GET /api/v1/alert-settings", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		rules, e1 := a.store.AlertRules(r.Context())
		runtime, e2 := a.store.AlertRuntime(r.Context())
		if errors.Join(e1, e2) != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Rules   []alerting.Rule      `json:"rules"`
			Runtime storage.AlertRuntime `json:"runtime"`
			Stale   bool                 `json:"evaluator_stale"`
		}{rules, runtime, evaluatorStale(runtime, time.Now())})
	})
	a.route(mux, "POST /api/v1/alert-settings/rules/{kind}", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var rule alerting.Rule
		if !decodeJSON(w, r, &rule, 2048) {
			return
		}
		rule.Kind = r.PathValue("kind")
		if !alerting.RuleValid(rule) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Use a threshold of 1–99%, trigger after 1–1,440 minutes, recover after 1–60 minutes, and a severity.")
			return
		}
		if e := a.store.SaveAlertRule(r.Context(), rule, s.Username, time.Now()); e != nil {
			apiError(w, http.StatusConflict, "refused", "The rule changed since you loaded it. Reload and try again.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "POST /api/v1/alert-settings/mail", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Paused bool `json:"paused"`
		}
		if !decodeJSON(w, r, &in, 256) {
			return
		}
		if e := a.store.PauseAlertMail(r.Context(), in.Paused, s.Username, time.Now()); e != nil {
			unavailable(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Health checks: technicians read their scope; changes are owner-only and
	// go through review (digest) then apply.
	a.route(mux, "GET /api/v1/health-checks", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		device := r.URL.Query().Get("device")
		if device != "" {
			if !protocol.ValidID(device) {
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid device.")
				return
			}
			if e := a.store.AuthorizeDevice(r.Context(), s, device, "read"); e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		checks, e1 := a.store.HealthChecksForSession(r.Context(), s, device, time.Now())
		attempts, e2 := a.store.HealthAttemptsForSession(r.Context(), s, device)
		if errors.Join(e1, e2) != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Health checks are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Checks   []storage.HealthStatus  `json:"checks"`
			Attempts []storage.HealthAttempt `json:"attempts"`
		}{checks, attempts})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/health-checks/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Change storage.HealthChange `json:"change"`
				Digest string               `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 8192) {
				return
			}
			c := &in.Change.Check
			c.Kind = "service_running"
			if c.HoldSeconds < 60 || c.HoldSeconds > 86400 || c.HoldSeconds%60 != 0 || c.RecoverySeconds < 60 || c.RecoverySeconds > 3600 || c.RecoverySeconds%60 != 0 || c.CooldownSeconds < 3600 || c.CooldownSeconds > 604800 || c.CooldownSeconds%60 != 0 {
				apiError(w, http.StatusBadRequest, "invalid_request", "Trigger after 1–1,440 minutes, recover after 1–60 minutes, and wait 1–168 hours between automatic starts.")
				return
			}
			digest := ""
			if op == "apply" {
				if len(in.Digest) != 64 {
					apiError(w, http.StatusBadRequest, "invalid_request", "Review the check before saving it.")
					return
				}
				digest = in.Digest
			}
			review, e := a.store.ChangeHealthCheck(r.Context(), in.Change, s.Actor(), digest, time.Now())
			if e != nil {
				apiError(w, http.StatusConflict, "refused", "The check could not be saved. It may have changed, or limits were reached (100 checks, 10 per device). Pending automatic starts must finish before re-arming.")
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Digest string `json:"digest"`
			}{review})
		})
	}
}
