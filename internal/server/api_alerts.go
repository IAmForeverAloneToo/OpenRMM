package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

	// E-mail settings: the SMTP password is write-only; responses only say
	// whether one is stored.
	emailView := func(ctx context.Context) (any, error) {
		type view struct {
			Source string `json:"source"` // dashboard or file
			storage.MailSettings
			HasPassword  bool   `json:"has_password"`
			Active       bool   `json:"active"`
			SuggestedURL string `json:"suggested_server_url"`
		}
		if a.mail.file != nil {
			return view{Source: "file", MailSettings: storage.MailSettings{To: []string{}}, Active: true}, nil
		}
		m, e1 := a.store.MailSettings(ctx)
		installer, e2 := a.store.InstallerSettings(ctx)
		if e := errors.Join(e1, e2); e != nil {
			return nil, e
		}
		return view{"dashboard", m, m.PasswordCipher != nil, a.mail.Current() != nil, installer.ServerURL}, nil
	}
	a.route(mux, "GET /api/v1/alert-settings/email", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		v, e := emailView(r.Context())
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	a.route(mux, "PUT /api/v1/alert-settings/email", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Enabled       bool     `json:"enabled"`
			Host          string   `json:"host"`
			Port          int      `json:"port"`
			TLS           string   `json:"tls"`
			Username      string   `json:"username"`
			Password      string   `json:"password"`
			ClearPassword bool     `json:"clear_password"`
			From          string   `json:"from"`
			To            []string `json:"to"`
			ServerURL     string   `json:"server_url"`
			Revision      int64    `json:"revision"`
		}
		if !decodeJSON(w, r, &in, 8192) {
			return
		}
		if a.mail.file != nil {
			apiError(w, http.StatusConflict, "file_managed", "E-mail is configured by the server's SMTP file. Remove -alert-smtp-config to manage it here.")
			return
		}
		ctx := r.Context()
		current, e := a.store.MailSettings(ctx)
		if e != nil {
			unavailable(w)
			return
		}
		next := storage.MailSettings{Enabled: in.Enabled, Host: strings.TrimSpace(in.Host), Port: in.Port, TLS: in.TLS, Username: in.Username, From: strings.TrimSpace(in.From), ServerURL: strings.TrimSuffix(strings.TrimSpace(in.ServerURL), "/"), Revision: in.Revision, To: []string{}}
		for _, to := range in.To {
			if to = strings.TrimSpace(to); to != "" {
				next.To = append(next.To, to)
			}
		}
		// A new password replaces the stored one; without a user name there is
		// no password.
		password := ""
		switch {
		case in.Username == "" || in.ClearPassword:
		case in.Password != "":
			password = in.Password
		case current.PasswordCipher != nil:
			plain, e := a.auth.OpenSetting(smtpPasswordPurpose, current.PasswordCipher)
			if e != nil {
				apiError(w, http.StatusConflict, "password_unreadable", "The stored SMTP password cannot be decrypted (the encryption key changed). Enter the password again.")
				return
			}
			password, next.PasswordCipher = string(plain), current.PasswordCipher
		}
		invalid := "Check the e-mail settings: a host name, port 1–65535, STARTTLS or TLS, a sender address, 1–10 different recipient addresses, an https:// dashboard address, and a password whenever a user name is set."
		c := mailConfig(next)
		c.Password = password
		blank := next.Host == "" && next.From == "" && len(next.To) == 0 && next.ServerURL == "" && next.Username == ""
		if next.Port < 1 || next.Port > 65535 || (next.TLS != "starttls" && next.TLS != "tls") {
			apiError(w, http.StatusBadRequest, "invalid_request", invalid)
			return
		}
		if _, e := alerting.NewMailer(c); e != nil && (next.Enabled || !blank) {
			apiError(w, http.StatusBadRequest, "invalid_request", invalid)
			return
		}
		if password != "" && next.PasswordCipher == nil {
			if next.PasswordCipher, e = a.auth.SealSetting(smtpPasswordPurpose, []byte(password)); e != nil {
				unavailable(w)
				return
			}
		}
		now := time.Now()
		if e = a.store.SetMailSettings(ctx, next, s.Username, now); errors.Is(e, storage.ErrMailSettingsChanged) {
			apiError(w, http.StatusConflict, "refused", "The e-mail settings changed since you loaded them. Reload and try again.")
			return
		} else if e != nil {
			unavailable(w)
			return
		}
		if e = a.mail.Reload(ctx, now); e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The settings were saved but could not be put into use. Reload and try again.")
			return
		}
		v, e := emailView(ctx)
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	a.route(mux, "POST /api/v1/alert-settings/email/test", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		mailer := a.mail.Current()
		if mailer == nil {
			apiError(w, http.StatusConflict, "disabled", "Turn e-mail on and save the settings before sending a test.")
			return
		}
		now := time.Now()
		if !a.mail.allowTest(now) {
			apiError(w, http.StatusTooManyRequests, "rate_limited", "Wait 30 seconds between test messages.")
			return
		}
		// Within the listener's 10-second write timeout.
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		result := mailer.SendTest(ctx, s.Username)
		_ = a.store.AuditMailTest(context.WithoutCancel(r.Context()), s.Username, result.Status, now)
		writeJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}{result.Status, result.Reason})
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
