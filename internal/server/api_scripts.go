package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Scripts are owner-only. Versions are immutable; runs pin one exact version
// and argument set. SYSTEM scripts additionally need the device's local runner
// and a local approval of that exact version hash.

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// scriptArguments keeps only declared parameters; empty optional values are dropped.
func scriptArguments(d protocol.ScriptDefinition, in map[string]string) (map[string]string, bool) {
	out := map[string]string{}
	declared := map[string]protocol.ScriptParameter{}
	for _, p := range d.Parameters {
		declared[p.Name] = p
	}
	for k, v := range in {
		p, ok := declared[k]
		if !ok {
			return nil, false
		}
		if v != "" || p.Required {
			out[k] = v
		}
	}
	return out, scripting.ArgumentsValid(d, out)
}

type scriptRunSummary struct {
	ID              string `json:"id"`
	VersionID       string `json:"version_id"`
	Name            string `json:"name"`
	Number          int    `json:"version"`
	RunAs           string `json:"run_as"`
	Status          string `json:"status"`
	Actor           string `json:"actor"`
	CreatedAt       int64  `json:"created_at"`
	FinishedAt      *int64 `json:"finished_at"`
	CancelRequested bool   `json:"cancel_requested"`
	Outcome         string `json:"outcome"`
	ExitCode        *int32 `json:"exit_code"`
}

func summarizeRuns(rs []storage.ScriptRun) []scriptRunSummary {
	out := []scriptRunSummary{}
	for _, r := range rs {
		v := scriptRunSummary{ID: r.ID, VersionID: r.Version.ID, Name: r.Version.Definition.Name, Number: r.Version.Number, RunAs: r.Version.Definition.RunAs, Status: r.Status, Actor: r.Actor, CreatedAt: r.CreatedAt, FinishedAt: r.FinishedAt, CancelRequested: r.CancelRequested}
		if r.Result != nil {
			v.Outcome, v.ExitCode = r.Result.Outcome, r.Result.ExitCode
		}
		out = append(out, v)
	}
	return out
}

func registerScriptsAPI(mux *http.ServeMux, a *api) {
	unavailable := func(w http.ResponseWriter) {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Scripts are temporarily unavailable.")
	}

	// Library.
	a.route(mux, "GET /api/v1/scripts", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		vs, e := a.store.ScriptVersions(r.Context(), "")
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Scripts []storage.ScriptVersion `json:"scripts"`
		}{vs})
	})
	a.route(mux, "GET /api/v1/scripts/versions/{version}", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		v, e := a.store.ScriptVersion(r.Context(), r.PathValue("version"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "Script version not found.")
			return
		}
		history, e := a.store.ScriptVersions(r.Context(), v.ScriptID)
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Version storage.ScriptVersion   `json:"version"`
			History []storage.ScriptVersion `json:"history"`
		}{v, history})
	})
	a.route(mux, "POST /api/v1/scripts/versions", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			ScriptID   string                    `json:"script_id"`
			Definition protocol.ScriptDefinition `json:"definition"`
		}
		if !decodeJSON(w, r, &in, 256*1024) {
			return
		}
		if in.ScriptID == "" {
			in.ScriptID = newID()
		} else if vs, e := a.store.ScriptVersions(r.Context(), in.ScriptID); e != nil || len(vs) == 0 {
			apiError(w, http.StatusBadRequest, "invalid_request", "Unknown script.")
			return
		}
		d := in.Definition
		d.Name = strings.TrimSpace(d.Name)
		d.Body = strings.ReplaceAll(d.Body, "\r\n", "\n")
		if d.Parameters == nil {
			d.Parameters = []protocol.ScriptParameter{}
		}
		if !scripting.DefinitionValid(d) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Check the name (up to 100 characters), body (up to 64 KB), timeout (5–300 seconds) and parameter names.")
			return
		}
		v, e := a.store.CreateScriptVersion(r.Context(), storage.ScriptVersion{ScriptVersion: protocol.ScriptVersion{ID: newID(), ScriptID: in.ScriptID, Definition: d}, Actor: s.Username}, time.Now())
		if e != nil {
			apiError(w, http.StatusConflict, "refused", "The version could not be saved. The library may be full (500 versions, 100 scripts).")
			return
		}
		writeJSON(w, http.StatusCreated, v)
	})

	// Device runs.
	a.route(mux, "GET /api/v1/devices/{id}/scripts", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		_, view, ok := a.deviceView(w, r)
		if !ok {
			return
		}
		now := time.Now()
		support, e1 := a.store.ScriptSupport(r.Context(), view.ID)
		runs, e2 := a.store.ScriptRuns(r.Context(), view.ID, now)
		schedules, e3 := a.store.ScriptSchedules(r.Context(), view.ID)
		if errors.Join(e1, e2, e3) != nil {
			unavailable(w)
			return
		}
		age := now.Sub(time.Unix(support.ReportedAt, 0))
		available := support.Status == "ok" && support.Support.Restricted && age >= 0 && age < 2*time.Minute && view.Status == "online"
		writeJSON(w, http.StatusOK, struct {
			Support   storage.ScriptSupport    `json:"support"`
			Available bool                     `json:"available"`
			Runs      []scriptRunSummary       `json:"runs"`
			Schedules []storage.ScriptSchedule `json:"schedules"`
		}{support, available, summarizeRuns(runs), schedules})
	})
	a.route(mux, "POST /api/v1/devices/{id}/script-runs", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			ID        string            `json:"id"`
			Version   string            `json:"version"`
			Arguments map[string]string `json:"arguments"`
		}
		if !decodeJSON(w, r, &in, 64*1024) {
			return
		}
		id := r.PathValue("id")
		v, e := a.store.ScriptVersion(r.Context(), in.Version)
		if e != nil || !protocol.ValidID(id) || !protocol.ValidID(in.ID) {
			apiError(w, http.StatusNotFound, "not_found", "Script version or device not found.")
			return
		}
		args, ok := scriptArguments(v.Definition, in.Arguments)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid_request", "Check required parameters and value lengths.")
			return
		}
		e = a.store.QueueScriptRun(r.Context(), storage.ScriptRun{ScriptJob: protocol.ScriptJob{ID: in.ID, Version: protocol.ScriptVersion{ID: v.ID}, Arguments: args}, DeviceID: id, Actor: s.Username}, time.Now(), a.offlineAfter())
		if e != nil {
			queueError(w, e, storage.ErrScript, "Scripts are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id"`
		}{in.ID})
	})
	a.route(mux, "GET /api/v1/devices/{id}/script-runs/{run}", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		v, e := a.store.ScriptRun(r.Context(), r.PathValue("id"), r.PathValue("run"), time.Now())
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "Script run not found.")
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	a.route(mux, "POST /api/v1/devices/{id}/script-runs/{run}/cancel", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.CancelScriptRun(r.Context(), r.PathValue("id"), r.PathValue("run"), s.Username, time.Now()); e != nil {
			queueError(w, e, storage.ErrScript, "Cancellation is temporarily unavailable.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Schedules.
	a.route(mux, "GET /api/v1/script-schedules", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, e := a.store.FleetScriptSchedules(r.Context())
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Schedules []storage.FleetSchedule `json:"schedules"`
		}{items})
	})
	a.route(mux, "GET /api/v1/devices/{id}/script-schedules/{schedule}", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		id := r.PathValue("id")
		v, e := a.store.ScriptSchedule(r.Context(), id, r.PathValue("schedule"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "Schedule not found.")
			return
		}
		version, e1 := a.store.ScriptVersion(r.Context(), v.VersionID)
		occurrences, e2 := a.store.ScriptOccurrences(r.Context(), id, v.ID, time.Now())
		if errors.Join(e1, e2) != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Schedule    storage.ScriptSchedule     `json:"schedule"`
			Version     storage.ScriptVersion      `json:"version"`
			Occurrences []storage.ScriptOccurrence `json:"occurrences"`
		}{v, version, occurrences})
	})
	a.route(mux, "POST /api/v1/devices/{id}/script-schedules", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			ID        string            `json:"id"`
			Revision  int               `json:"revision"`
			Version   string            `json:"version"`
			Name      string            `json:"name"`
			StartAt   int64             `json:"start_at"`
			Interval  int64             `json:"interval_seconds"`
			Arguments map[string]string `json:"arguments"`
		}
		if !decodeJSON(w, r, &in, 64*1024) {
			return
		}
		now := time.Now()
		id := r.PathValue("id")
		name := strings.TrimSpace(in.Name)
		switch {
		case !protocol.ValidID(id) || !protocol.ValidID(in.ID) || !protocol.ValidID(in.Version) || in.Revision < 0:
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid schedule.")
			return
		case name == "" || !scripting.Text(name, 100, false):
			apiError(w, http.StatusBadRequest, "invalid_request", "Give the schedule a name of up to 100 characters.")
			return
		case in.StartAt < now.Unix()+5 || in.StartAt > now.Add(366*24*time.Hour).Unix():
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose a start time in the future, within one year.")
			return
		case in.Interval != 0 && (in.Interval < 300 || in.Interval > 43200*60 || in.Interval%60 != 0):
			apiError(w, http.StatusBadRequest, "invalid_request", "Repeat every 5 minutes to 30 days, or run once.")
			return
		}
		version, e := a.store.ScriptVersion(r.Context(), in.Version)
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "Script version not found.")
			return
		}
		args, ok := scriptArguments(version.Definition, in.Arguments)
		if !ok {
			apiError(w, http.StatusBadRequest, "invalid_request", "Check required parameters and value lengths.")
			return
		}
		v := storage.ScriptSchedule{ID: in.ID, DeviceID: id, VersionID: version.ID, Name: name, Arguments: args, StartAt: in.StartAt, Interval: in.Interval, Revision: in.Revision, Actor: s.Username}
		if e = a.store.SaveScriptSchedule(r.Context(), v, now); e != nil {
			queueError(w, e, storage.ErrSchedule, "Schedules are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			ID string `json:"id"`
		}{v.ID})
	})
	a.route(mux, "POST /api/v1/devices/{id}/script-schedules/{schedule}/state", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Action   string `json:"action"`
			Revision int    `json:"revision"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		if in.Action != "pause" && in.Action != "resume" && in.Action != "cancel" {
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose pause, resume or cancel.")
			return
		}
		if e := a.store.ChangeScriptSchedule(r.Context(), r.PathValue("id"), r.PathValue("schedule"), s.Username, in.Action, in.Revision, time.Now()); e != nil {
			queueError(w, e, storage.ErrSchedule, "Schedules are temporarily unavailable.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Fleet batches: review resolves the exact targets and returns a digest;
	// apply must quote that digest, so later group changes never expand a run.
	a.route(mux, "GET /api/v1/script-batches", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, e := a.store.ScriptBatches(r.Context(), s.Username)
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Batches []storage.ScriptBatchSummary `json:"batches"`
		}{items})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/script-batches/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Change storage.ScriptBatchChange `json:"change"`
				Digest string                    `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 64*1024) {
				return
			}
			version, e := a.store.ScriptVersion(r.Context(), in.Change.VersionID)
			if e != nil {
				apiError(w, http.StatusNotFound, "not_found", "Script version not found.")
				return
			}
			args, ok := scriptArguments(version.Definition, in.Change.Arguments)
			if !ok || len(in.Change.Devices)+len(in.Change.Groups) == 0 || len(in.Change.Devices) > 25 || len(in.Change.Groups) > 25 {
				apiError(w, http.StatusBadRequest, "invalid_request", "Choose 1–25 devices or groups and fill required parameters.")
				return
			}
			in.Change.Arguments = args
			if in.Change.Devices == nil {
				in.Change.Devices = []string{}
			}
			if in.Change.Groups == nil {
				in.Change.Groups = []string{}
			}
			digest := ""
			if op == "apply" {
				if len(in.Digest) != 64 {
					apiError(w, http.StatusConflict, "refused", "Review this run again before confirming.")
					return
				}
				digest = in.Digest
			}
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			b, e := a.store.SubmitScriptBatch(ctx, in.Change, s.Username, digest, time.Now(), a.offlineAfter())
			if e != nil {
				apiError(w, http.StatusConflict, "refused", "The run could not be confirmed: targets, readiness or the script changed. Check the batch history first — a lost response does not prove nothing ran — then review again.")
				return
			}
			writeJSON(w, http.StatusOK, b)
		})
	}
	a.route(mux, "GET /api/v1/script-batches/{batch}", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		b, e := a.store.ScriptBatch(r.Context(), r.PathValue("batch"), s.Username, time.Now())
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "Batch not found.")
			return
		}
		writeJSON(w, http.StatusOK, b)
	})
}
