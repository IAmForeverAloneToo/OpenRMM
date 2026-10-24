package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Network isolation: the response permission isolates and releases devices
// it can reach, optionally into a case; isolating needs the device name
// typed (typed confirmation is reserved for revoke and isolate). Agents run
// isolation as a dry run until it has been verified on a disposable machine.
func registerIsolationAPI(mux *http.ServeMux, a *api) {
	a.route(mux, "POST /api/v1/devices/{id}/isolate", deviceAccess("response"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Confirm      string `json:"confirm"`
			CaseID       string `json:"case_id"`
			CaseTitle    string `json:"case_title"`
			ReleaseAfter int64  `json:"release_after"`
		}
		if !decodeJSON(w, r, &in, 2048) {
			return
		}
		if in.CaseID != "" && (!protocol.ValidID(in.CaseID) || in.CaseID == storage.LiveCase) || in.CaseID != "" && in.CaseTitle != "" || in.ReleaseAfter < 0 || in.ReleaseAfter > protocol.MaxReleaseAfter {
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose at most one case and a timed release of up to 7 days.")
			return
		}
		_, view, ok := a.deviceView(w, r)
		if !ok {
			return
		}
		if view.RevokedAt != nil {
			apiError(w, http.StatusNotFound, "not_found", "Device not found.")
			return
		}
		if in.Confirm != view.Hostname {
			apiError(w, http.StatusBadRequest, "confirmation", "Type the device name exactly to confirm.")
			return
		}
		now := time.Now()
		caseID := storage.LiveCase
		if in.CaseID != "" {
			caseID = in.CaseID
		}
		if in.CaseTitle != "" {
			c, e := a.store.CreateCase(r.Context(), in.CaseTitle, s.Actor(), now)
			if e != nil {
				apiError(w, http.StatusBadRequest, "case", "The case title is invalid (1–200 characters, no line breaks).")
				return
			}
			caseID = c.ID
		}
		v, e := a.store.IsolateDevice(r.Context(), caseID, view.ID, s.Actor(), in.ReleaseAfter, now)
		if e != nil && in.CaseTitle != "" {
			_ = a.store.SetCaseStatus(r.Context(), caseID, "closed", s.Actor(), "Not used: the device could not be isolated.", now)
		}
		switch {
		case e == nil:
			writeJSON(w, http.StatusCreated, v)
		case errors.Is(e, storage.ErrIsolationBusy):
			apiError(w, http.StatusConflict, "isolated", "The device is already isolated or being isolated.")
		case errors.Is(e, storage.ErrActionUnsupported):
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot isolate yet; update it to the current release.")
		case errors.Is(e, storage.ErrCase):
			apiError(w, http.StatusConflict, "case", "The case is closed or unknown.")
		case errors.Is(e, storage.ErrIsolation), errors.Is(e, storage.ErrOrganization):
			apiError(w, http.StatusConflict, "unavailable", "The device cannot be isolated: check that incident response is on for it and that the evidence store is configured.")
		default:
			if a.store.AuthorizeDevice(r.Context(), s, view.ID, "response") != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Isolation is temporarily unavailable.")
		}
	})
	a.route(mux, "POST /api/v1/devices/{id}/release-isolation", deviceAccess("response"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		_, view, ok := a.deviceView(w, r)
		if !ok {
			return
		}
		v, e := a.store.ReleaseDevice(r.Context(), view.ID, s.Actor(), time.Now())
		switch {
		case e == nil:
			writeJSON(w, http.StatusOK, v)
		case errors.Is(e, storage.ErrNotIsolated):
			apiError(w, http.StatusConflict, "not_isolated", "The device is not isolated.")
		default:
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Releasing is temporarily unavailable.")
		}
	})
}
