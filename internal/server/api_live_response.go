package server

import (
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/liveresponse"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
)

// Live response console: built-in commands of a terminal session run the
// case actions and collections on its device. With a case they
// are recorded there; without one (storage.LiveCase) only the audit log
// records them and results are kept for 24 hours for viewing.
func registerLiveResponseAPI(mux *http.ServeMux, a *api, h *terminal.Hub) {
	const unavailable = "This live response session has ended or is not available."
	session := func(w http.ResponseWriter, r *http.Request, s storage.Session) (device, caseID string, ok bool) {
		device, caseID, _, e := h.Session(r.Context(), r.PathValue("session"), s.TokenHash)
		if e != nil {
			liveError(w, e, terminal.ErrInvalid, terminal.ErrUnavailable, unavailable)
			return "", "", false
		}
		if caseID == "" {
			caseID = storage.LiveCase
		}
		return device, caseID, true
	}
	a.route(mux, "POST /api/v1/terminal/{session}/case", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			CaseID    string `json:"case_id"`
			CaseTitle string `json:"case_title"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		device, current, ok := session(w, r, s)
		if !ok {
			return
		}
		if current != storage.LiveCase {
			apiError(w, http.StatusConflict, "case", "This session is already recorded to a case.")
			return
		}
		if (in.CaseID == "") == (in.CaseTitle == "") || in.CaseID != "" && (!protocol.ValidID(in.CaseID) || in.CaseID == storage.LiveCase) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose an open case or give a title for a new one.")
			return
		}
		created := false
		if in.CaseTitle != "" {
			c, e := a.store.CreateCase(r.Context(), in.CaseTitle, s.Actor(), time.Now())
			if e != nil {
				apiError(w, http.StatusBadRequest, "case", "The case title is invalid (1–200 characters, no line breaks).")
				return
			}
			in.CaseID, created = c.ID, true
		}
		e := h.Attach(r.Context(), r.PathValue("session"), s.TokenHash, in.CaseID, func(id string) (terminal.Recorder, error) {
			return a.store.StartTranscript(r.Context(), in.CaseID, device, s.Actor(), id, time.Now())
		})
		// A case created for an attach that failed is closed again, so no
		// empty open case is left behind.
		if e != nil && created {
			_ = a.store.SetCaseStatus(r.Context(), in.CaseID, "closed", s.Actor(), "Not attached: the live response session could not be attached.", time.Now())
		}
		switch {
		case e == nil:
			writeJSON(w, http.StatusOK, struct {
				CaseID string `json:"case_id"`
			}{in.CaseID})
		case errors.Is(e, storage.ErrCase):
			apiError(w, http.StatusConflict, "case", "The case is closed or unknown.")
		case errors.Is(e, storage.ErrEvidence):
			apiError(w, http.StatusConflict, "evidence", "The session cannot be recorded: check the evidence store and its quota.")
		case errors.Is(e, terminal.ErrInvalid):
			apiError(w, http.StatusConflict, "case", "This session is already recorded to a case.")
		default:
			liveError(w, e, terminal.ErrInvalid, terminal.ErrUnavailable, unavailable)
		}
	})
	a.route(mux, "POST /api/v1/terminal/{session}/command", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Line string `json:"line"`
		}
		if !decodeJSON(w, r, &in, 16*1024) {
			return
		}
		device, caseID, ok := session(w, r, s)
		if !ok {
			return
		}
		// A command is activity: it keeps the session from ending as idle.
		_ = h.Touch(r.Context(), r.PathValue("session"), s.TokenHash)
		c, e := liveresponse.Parse(strings.TrimSpace(in.Line))
		var usage liveresponse.ErrUsage
		if errors.As(e, &usage) {
			apiError(w, http.StatusBadRequest, "usage", usage.Message)
			return
		}
		if e != nil {
			apiError(w, http.StatusBadRequest, "usage", "Not a built-in command; help lists them.")
			return
		}
		if c.Verb == "help" {
			writeJSON(w, http.StatusOK, struct {
				Help string `json:"help"`
			}{liveresponse.Help})
			return
		}
		now := time.Now()
		action := c.Action
		switch c.Verb {
		case "kill":
			start, name, e := a.store.ListedProcess(r.Context(), device, c.PID, now)
			if e != nil {
				apiError(w, http.StatusBadRequest, "usage", "Run ps first and wait for its result: kill takes the process's start time from the latest process list (last 30 minutes), so a reused process ID is never hit.")
				return
			}
			if c.Start != "" && c.Start != start {
				apiError(w, http.StatusConflict, "usage", "In the latest process list this process ID belongs to another process. Open the latest ps result and kill from there.")
				return
			}
			action = &protocol.ResponseAction{Kind: "kill", PID: c.PID, Start: start, Name: name, Tree: c.Tree}
		case "put":
			tool, e := a.store.ToolNamed(r.Context(), c.Tool)
			if e != nil {
				apiError(w, http.StatusBadRequest, "usage", "No tool with that name in the tool library (Cases → Tool library).")
				return
			}
			spec, e := a.store.ResolveAction(r.Context(), caseID, protocol.ResponseAction{Kind: "drop", Source: "tool", Ref: tool, Path: c.Destination, Overwrite: c.Overwrite})
			if e != nil {
				apiError(w, http.StatusBadRequest, "usage", "The tool or destination is not valid.")
				return
			}
			action = &spec
		case "run":
			ref, e := a.store.ScriptNamed(r.Context(), c.Script)
			if errors.Is(e, storage.ErrScript) {
				apiError(w, http.StatusBadRequest, "usage", "No script with that name in the script library.")
				return
			}
			if e != nil {
				apiError(w, http.StatusServiceUnavailable, "unavailable", "The script library is temporarily unavailable.")
				return
			}
			spec, e := a.store.ResolveAction(r.Context(), caseID, protocol.ResponseAction{Kind: "script", Ref: ref, Arguments: c.Arguments})
			if e != nil {
				apiError(w, http.StatusBadRequest, "usage", "The script's arguments are not valid (required ones missing or unknown names).")
				return
			}
			action = &spec
		case "hunt":
			list := c.Indicators
			if c.List != "" {
				l, e := a.store.IOCListNamed(r.Context(), c.List)
				if errors.Is(e, storage.ErrIOCList) {
					apiError(w, http.StatusBadRequest, "usage", "No saved indicator list with that name (Hunting → Saved lists).")
					return
				}
				if e != nil {
					apiError(w, http.StatusServiceUnavailable, "unavailable", "Indicator lists are temporarily unavailable.")
					return
				}
				list = l.Indicators
			}
			action = &protocol.ResponseAction{Kind: "hunt", Hunt: &protocol.HuntSpec{Indicators: list, Files: c.Files}}
		}
		// A case attached while the command was resolved takes it instead.
		if _, current, ok := session(w, r, s); !ok {
			return
		} else if current != caseID {
			apiError(w, http.StatusConflict, "case", "The session was just attached to a case. Run the command again.")
			return
		}
		var id string
		triage := storage.TriageProfile{}
		if c.Source == "triage" {
			if triage, e = a.store.TriageProfileNamed(r.Context(), c.Path); e != nil {
				apiError(w, http.StatusBadRequest, "usage", "No triage profile with that name (Cases → Triage profiles).")
				return
			}
		}
		if c.Source == "triage" {
			id, e = a.store.QueueTriage(r.Context(), caseID, device, r.PathValue("session"), triage, s.Actor(), now)
		} else if c.Source == "ntfs" {
			volumes, all, _ := protocol.ParseNTFSQuery(c.Query)
			id, e = a.store.QueueNTFS(r.Context(), caseID, device, r.PathValue("session"), volumes, all, s.Actor(), now)
		} else if c.Source == "evtx" {
			id, e = a.store.QueueEventExport(r.Context(), caseID, device, r.PathValue("session"), c.Path, c.Query, s.Actor(), now)
		} else {
			id, e = a.store.QueueSessionJob(r.Context(), caseID, device, r.PathValue("session"), c.Source, c.Path, action, s.Actor(), now)
		}
		switch {
		case e == nil:
			label := c.Path
			if c.Source == "evtx" {
				label = "Event log " + c.Path
			}
			if c.Source == "triage" {
				label = "Triage package " + triage.Name
			}
			if c.Source == "ntfs" {
				label = "NTFS artifacts"
			}
			if action != nil {
				label = action.Label()
			}
			writeJSON(w, http.StatusCreated, struct {
				ID    string `json:"id"`
				Label string `json:"label"`
			}{id, label})
		case errors.Is(e, storage.ErrActionUnsupported):
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot run this action yet; update it to the current release.")
		case errors.Is(e, storage.ErrTriageUnsupported):
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot collect triage packages yet; update it to the current release.")
		case errors.Is(e, storage.ErrNTFSUnsupported):
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot collect NTFS artifacts yet; update it to the current release.")
		case errors.Is(e, storage.ErrEventExport):
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot export event logs yet; update it to the current release.")
		case errors.Is(e, storage.ErrEvidence):
			apiError(w, http.StatusConflict, "evidence", "The command could not start: check the path, that incident response is on for the device, and that fewer than two collections or actions are running on it.")
		case errors.Is(e, storage.ErrCase):
			apiError(w, http.StatusConflict, "case", "The session's case is closed.")
		default:
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Live response is temporarily unavailable.")
		}
	})
	// Results stay readable after the session ends (case-less ones for 24
	// hours), but only by the account that ran the commands while it may
	// still access the device.
	a.route(mux, "GET /api/v1/terminal/{session}/jobs", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.SessionJobs(r.Context(), r.PathValue("session"), s.Actor())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Live response is temporarily unavailable.")
			return
		}
		if len(list) > 0 && a.store.AuthorizeDevice(r.Context(), s, list[0].DeviceID, "response") != nil {
			apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Jobs []storage.EvidenceJob `json:"jobs"`
		}{list})
	})
	a.route(mux, "POST /api/v1/terminal/{session}/jobs/{job}/cancel", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		_, device, e := a.store.SessionJobCase(r.Context(), r.PathValue("session"), s.Actor(), r.PathValue("job"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "No such command.")
			return
		}
		if a.store.AuthorizeDevice(r.Context(), s, device, "response") != nil {
			apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
			return
		}
		if e := a.store.CancelSessionJob(r.Context(), r.PathValue("session"), s.Actor(), r.PathValue("job"), time.Now()); errors.Is(e, storage.ErrEvidence) {
			apiError(w, http.StatusConflict, "evidence", "This command has already finished or is running on the device.")
			return
		} else if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Live response is temporarily unavailable.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "GET /api/v1/terminal/{session}/jobs/{job}/file", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		caseID, device, e := a.store.SessionJobCase(r.Context(), r.PathValue("session"), s.Actor(), r.PathValue("job"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "No result for this command.")
			return
		}
		if a.store.AuthorizeDevice(r.Context(), s, device, "response") != nil {
			apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
			return
		}
		record := r.Method == http.MethodGet && rangeIncludesStart(r.Header.Get("Range"))
		f, j, e := a.store.OpenCaseEvidence(r.Context(), caseID, r.PathValue("job"), s.Actor(), record, time.Now())
		if errors.Is(e, storage.ErrEvidence) {
			apiError(w, http.StatusNotFound, "not_found", "No result for this command (results without a case are kept for 24 hours).")
			return
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The result cannot be read. Check the evidence volume.")
			return
		}
		defer f.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(12 * time.Hour))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": j.Name()}))
		w.Header().Set("X-Content-SHA256", j.ServerSHA256)
		http.ServeContent(w, r, "", time.Time{}, f)
	})
}
