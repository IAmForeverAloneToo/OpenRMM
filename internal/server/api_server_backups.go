package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// writeBackupSchedule hands the stored schedule to the updater.
func (u *serverUpdates) writeBackupSchedule(ctx context.Context, s *storage.Store) error {
	if u == nil || u.dir == "" {
		return nil
	}
	b, e := s.BackupSettings(ctx)
	if e != nil {
		return e
	}
	return serverupdate.WriteSchedule(u.dir, serverupdate.BackupSchedule{Enabled: b.Enabled, Hour: b.Hour})
}

// Server backups from the dashboard (owner only): the nightly schedule, a
// backup on request and the updater's list. Restores need the server
// stopped and are done with the install command.
func registerServerBackupAPI(mux *http.ServeMux, a *api) {
	unavailable := func(w http.ResponseWriter) {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Backup information is temporarily unavailable.")
	}
	view := func(ctx context.Context) (any, error) {
		settings, e := a.store.BackupSettings(ctx)
		if e != nil {
			return nil, e
		}
		_, present := a.updates.status()
		var report *serverupdate.BackupReport
		if present {
			if r, e := serverupdate.ReadBackupReport(a.updates.dir); e == nil {
				report = &r
			}
		}
		return struct {
			Updater  bool                       `json:"updater"`
			Settings storage.BackupSettings     `json:"settings"`
			Report   *serverupdate.BackupReport `json:"report"`
		}{present, settings, report}, nil
	}
	a.route(mux, "GET /api/v1/server/backups", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		v, e := view(r.Context())
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	a.route(mux, "PUT /api/v1/server/backups/settings", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in storage.BackupSettings
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		if in.Hour < 0 || in.Hour > 23 {
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose an hour from 0 to 23 (UTC).")
			return
		}
		switch e := a.store.SetBackupSettings(r.Context(), in, s.Actor(), time.Now()); {
		case errors.Is(e, storage.ErrBackupSettingsChanged):
			apiError(w, http.StatusConflict, "refused", "The backup settings changed since you loaded them. Reload and try again.")
			return
		case e != nil:
			unavailable(w)
			return
		}
		if e := a.updates.writeBackupSchedule(r.Context(), a.store); e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The settings were saved but could not be handed to the updater. Reload and try again.")
			return
		}
		v, e := view(r.Context())
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	a.route(mux, "POST /api/v1/server/backups/run", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if _, ok := a.updates.status(); !ok {
			apiError(w, http.StatusConflict, "no_updater", "Backups are taken by the updater, which this installation does not have. Run the install command again to add it.")
			return
		}
		now := time.Now()
		id := newID()
		e := serverupdate.SubmitBackupRequest(a.updates.dir, serverupdate.BackupRequest{ID: id, RequestedBy: s.Actor(), RequestedAt: now.Unix()})
		if errors.Is(e, serverupdate.ErrBusy) {
			apiError(w, http.StatusConflict, "busy", "A backup has already been requested.")
			return
		} else if e != nil {
			unavailable(w)
			return
		}
		_ = a.store.AuditBackupRequest(context.WithoutCancel(r.Context()), s.Actor(), "requested", now)
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id"`
		}{id})
	})
}
