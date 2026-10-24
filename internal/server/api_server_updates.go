package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Server updates from the dashboard (owner only).
func registerServerUpdateAPI(mux *http.ServeMux, a *api) {
	unavailable := func(w http.ResponseWriter) {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Server update information is temporarily unavailable.")
	}
	a.route(mux, "GET /api/v1/server/update", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		u := a.updates
		settings, e1 := a.store.ServerUpdateSettings(r.Context())
		history, e2 := a.store.ServerUpdates(r.Context())
		if errors.Join(e1, e2) != nil || u == nil {
			unavailable(w)
			return
		}
		type releaseView struct {
			Version  string `json:"version"`
			Sequence int64  `json:"sequence"`
			Notes    string `json:"notes"`
			Issued   int64  `json:"issued"`
			Image    string `json:"image"`
		}
		var available *releaseView
		if rel := u.available(settings, time.Now()); rel != nil {
			m := rel.Manifest
			available = &releaseView{m.Version, m.Sequence, m.Notes, m.Issued, m.Image}
		}
		type updaterView struct {
			Phase     string `json:"phase"`
			Version   string `json:"version"`
			Detail    string `json:"detail"`
			UpdatedAt int64  `json:"updated_at"`
		}
		var updater *updaterView
		if st, ok := u.status(); ok {
			updater = &updaterView{st.Phase, st.Version, st.Detail, st.UpdatedAt}
		}
		checkError := settings.CheckError
		if checkError == "not_configured" {
			checkError = ""
		}
		writeJSON(w, http.StatusOK, struct {
			Current      serverupdate.Current   `json:"current"`
			CheckEnabled bool                   `json:"check_enabled"`
			CheckedAt    *int64                 `json:"checked_at"`
			CheckError   string                 `json:"check_error"`
			Configured   bool                   `json:"repository_configured"`
			Available    *releaseView           `json:"available"`
			Updater      *updaterView           `json:"updater"`
			History      []storage.ServerUpdate `json:"history"`
		}{u.current, settings.CheckEnabled, settings.CheckedAt, checkError, serverupdate.Configured(), available, updater, history})
	})

	a.route(mux, "PUT /api/v1/server/update/settings", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			CheckEnabled bool `json:"check_enabled"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		if a.store.SetServerUpdateCheck(r.Context(), in.CheckEnabled, s.Actor(), time.Now()) != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, in)
	})

	a.route(mux, "POST /api/v1/server/update/check", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		u := a.updates
		if u == nil {
			unavailable(w)
			return
		}
		u.mu.Lock()
		recent := time.Since(u.manual) < time.Minute
		if !recent {
			u.manual = time.Now()
		}
		u.mu.Unlock()
		if recent {
			apiError(w, http.StatusTooManyRequests, "rate_limited", "A check ran less than a minute ago.")
			return
		}
		if u.check(r.Context(), a.store, time.Now()) != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct{}{})
	})

	a.route(mux, "POST /api/v1/server/update/install", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Sequence int64 `json:"sequence"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		u := a.updates
		if _, ok := u.status(); !ok {
			apiError(w, http.StatusConflict, "no_updater", "This installation has no updater. Run the install command again to add it, or update with the install command.")
			return
		}
		settings, e := a.store.ServerUpdateSettings(r.Context())
		if e != nil {
			unavailable(w)
			return
		}
		now := time.Now()
		rel := u.available(settings, now)
		if rel == nil || rel.Manifest.Sequence != in.Sequence {
			apiError(w, http.StatusConflict, "not_available", "This release is no longer available. Check for updates again.")
			return
		}
		record := storage.ServerUpdate{ID: newID(), Version: rel.Manifest.Version, Sequence: rel.Manifest.Sequence, FromVersion: u.current.Version, RequestedBy: s.Actor()}
		switch e := a.store.StartServerUpdate(r.Context(), record, now); {
		case errors.Is(e, storage.ErrServerUpdate):
			apiError(w, http.StatusConflict, "busy", "An update is already in progress.")
			return
		case e != nil:
			unavailable(w)
			return
		}
		e = serverupdate.SubmitRequest(u.dir, serverupdate.Request{ID: record.ID, Release: *rel, RequestedBy: s.Actor(), RequestedAt: now.Unix()}, now)
		if e != nil {
			_ = a.store.CancelServerUpdate(r.Context(), record.ID, now)
			if errors.Is(e, serverupdate.ErrBusy) {
				apiError(w, http.StatusConflict, "busy", "An update is already in progress.")
				return
			}
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id"`
		}{record.ID})
	})
}
