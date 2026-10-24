package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Triage profiles: everyone with the response permission sees
// them and collects packages; only the owner adds or withdraws profiles.
func registerTriageAPI(mux *http.ServeMux, a *api) {
	a.route(mux, "GET /api/v1/triage-profiles", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.TriageProfiles(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Triage profiles are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Profiles []storage.TriageProfile `json:"profiles"`
			Items    []protocol.TriageItem   `json:"items"`
		}{list, protocol.TriageItems})
	})
	a.route(mux, "POST /api/v1/triage-profiles", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Name  string   `json:"name"`
			Items []string `json:"items"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		p, e := a.store.AddTriageProfile(r.Context(), in.Name, in.Items, s.Actor(), time.Now())
		if errors.Is(e, storage.ErrTriage) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Give a new name (1–100 characters) and choose at least one artifact type.")
			return
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The profile could not be saved.")
			return
		}
		writeJSON(w, http.StatusCreated, p)
	})
	a.route(mux, "POST /api/v1/triage-profiles/{id}/withdraw", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.WithdrawTriageProfile(r.Context(), r.PathValue("id"), s.Actor(), time.Now()); errors.Is(e, storage.ErrTriage) {
			apiError(w, http.StatusNotFound, "not_found", "No such profile (the built-in profile cannot be withdrawn).")
			return
		} else if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The profile could not be withdrawn.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
