package server

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Cases and the chain-of-custody log. The owner and technicians
// with the response permission see and work on all cases.
var responseAccess = featureAccess("response")

func registerCasesAPI(mux *http.ServeMux, a *api) {
	unavailable := func(w http.ResponseWriter) {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Cases are temporarily unavailable.")
	}
	caseError := func(w http.ResponseWriter, e error) {
		if errors.Is(e, storage.ErrCase) {
			apiError(w, http.StatusConflict, "case", "The case is closed or unknown, still has collections or a recorded terminal running, or the input is invalid. Reload and try again.")
			return
		}
		unavailable(w)
	}
	a.route(mux, "GET /api/v1/cases", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.Cases(r.Context())
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Cases []storage.Case `json:"cases"`
		}{list})
	})
	a.route(mux, "POST /api/v1/cases", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Title string `json:"title"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		c, e := a.store.CreateCase(r.Context(), in.Title, s.Actor(), time.Now())
		if e != nil {
			caseError(w, e)
			return
		}
		writeJSON(w, http.StatusCreated, c)
	})
	a.route(mux, "GET /api/v1/cases/{case}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		d, e := a.store.CaseDetail(r.Context(), r.PathValue("case"))
		if errors.Is(e, storage.ErrCase) {
			apiError(w, http.StatusNotFound, "not_found", "Case not found.")
			return
		}
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, d)
	})
	a.route(mux, "POST /api/v1/cases/{case}/notes", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Text string `json:"text"`
		}
		if !decodeJSON(w, r, &in, 16*1024) {
			return
		}
		if e := a.store.AddCaseNote(r.Context(), r.PathValue("case"), s.Actor(), in.Text, time.Now()); e != nil {
			caseError(w, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "POST /api/v1/cases/{case}/status", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if !decodeJSON(w, r, &in, 8192) {
			return
		}
		if e := a.store.SetCaseStatus(r.Context(), r.PathValue("case"), in.Status, s.Actor(), in.Reason, time.Now()); e != nil {
			caseError(w, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Evidence collection: technicians need the response
	// permission (route) and access to the device.
	a.route(mux, "POST /api/v1/cases/{case}/collect", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			DeviceID string `json:"device_id"`
			Path     string `json:"path"`
			// Source is "file" (default), "hive" or "evtx" (Path is the
			// channel; Filter, when set, limits the export).
			Source string                `json:"source"`
			Filter *protocol.EventFilter `json:"filter"`
			// Profile names a triage profile for source "triage".
			Profile string `json:"profile"`
		}
		if !decodeJSON(w, r, &in, 16*1024) {
			return
		}
		if s.Technician != nil {
			if e := a.store.AuthorizeDevice(r.Context(), s, in.DeviceID, "response"); e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		if in.Source == "" {
			in.Source = "file"
		}
		var id string
		var e error
		if in.Source == "evtx" {
			query, ok := exportQuery(in.Path, in.Filter)
			if !ok {
				apiError(w, http.StatusBadRequest, "invalid_request", "Use a channel name and, to export only some events, a time range up to 31 days and valid filters.")
				return
			}
			id, e = a.store.QueueEventExport(r.Context(), r.PathValue("case"), in.DeviceID, "", in.Path, query, s.Actor(), time.Now())
		} else if in.Source == "triage" {
			p, err := a.store.TriageProfileByID(r.Context(), in.Profile)
			if err != nil {
				apiError(w, http.StatusBadRequest, "invalid_request", "Choose a triage profile.")
				return
			}
			id, e = a.store.QueueTriage(r.Context(), r.PathValue("case"), in.DeviceID, "", p, s.Actor(), time.Now())
		} else {
			id, e = a.store.QueueEvidenceSource(r.Context(), r.PathValue("case"), in.DeviceID, in.Source, in.Path, s.Actor(), time.Now())
		}
		if errors.Is(e, storage.ErrTriageUnsupported) {
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot collect triage packages yet; update it to the current release.")
			return
		}
		if errors.Is(e, storage.ErrEventExport) {
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot export event logs yet; update it to the current release.")
			return
		}
		if errors.Is(e, storage.ErrEvidence) {
			apiError(w, http.StatusConflict, "evidence", "Cannot collect: check the path (a full local path such as C:\\Users\\name\\file.txt, optionally with :stream) or the hive, that the device exists and has incident response switched on, and that it has fewer than two collections running.")
			return
		}
		if e != nil {
			caseError(w, e)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			ID string `json:"id"`
		}{id})
	})
	// Response actions: the same permission and device access as
	// collecting; the result document becomes case evidence.
	a.route(mux, "POST /api/v1/cases/{case}/actions", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			DeviceID string                  `json:"device_id"`
			Action   protocol.ResponseAction `json:"action"`
		}
		// A typed script may be 64 KiB, which JSON escaping expands.
		if !decodeJSON(w, r, &in, 512*1024) {
			return
		}
		// Scripts and drops are completed from the library and the case:
		// the spec then says exactly what runs or is written.
		action, e := a.store.ResolveAction(r.Context(), r.PathValue("case"), in.Action)
		if e != nil || !action.Valid() {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid action: check the script, its arguments, the tool or evidence file and the destination path.")
			return
		}
		in.Action = action
		if s.Technician != nil {
			if e := a.store.AuthorizeDevice(r.Context(), s, in.DeviceID, "response"); e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		id, e := a.store.QueueAction(r.Context(), r.PathValue("case"), in.DeviceID, in.Action, s.Actor(), time.Now())
		if errors.Is(e, storage.ErrActionUnsupported) {
			apiError(w, http.StatusConflict, "agent", "The device's agent cannot run this action yet; update it to the current release.")
			return
		}
		if errors.Is(e, storage.ErrEvidence) {
			apiError(w, http.StatusConflict, "evidence", "Cannot run the action: check that the device exists and has incident response switched on, and that it has fewer than two collections or actions running.")
			return
		}
		if e != nil {
			caseError(w, e)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			ID string `json:"id"`
		}{id})
	})
	a.route(mux, "GET /api/v1/cases/{case}/collections", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if r.PathValue("case") == storage.LiveCase {
			apiError(w, http.StatusNotFound, "not_found", "No such case.")
			return
		}
		list, e := a.store.EvidenceJobs(r.Context(), r.PathValue("case"))
		if e != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Collections []storage.EvidenceJob `json:"collections"`
			MaxBytes    int64                 `json:"max_bytes"`
		}{list, storage.EvidenceMaxFile})
	})
	a.route(mux, "POST /api/v1/cases/{case}/collections/{job}/cancel", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		// Cancelling changes what a device does: technicians need access to it.
		if s.Technician != nil {
			device, e := a.store.EvidenceJobDevice(r.Context(), r.PathValue("case"), r.PathValue("job"))
			if e == nil {
				e = a.store.AuthorizeDevice(r.Context(), s, device, "response")
			}
			if e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		if e := a.store.CancelEvidence(r.Context(), r.PathValue("case"), r.PathValue("job"), s.Actor(), time.Now()); e != nil {
			if errors.Is(e, storage.ErrEvidence) {
				apiError(w, http.StatusConflict, "evidence", "This collection has already finished.")
				return
			}
			unavailable(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Downloads stream from the evidence store and are recorded in the custody
	// log before the first byte is sent.
	a.route(mux, "GET /api/v1/cases/{case}/collections/{job}/file", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		// One custody entry per download: HEAD and later range requests of the
		// same download are not recorded again.
		// Results of live response sessions without a case are only reachable
		// through their session.
		if r.PathValue("case") == storage.LiveCase {
			apiError(w, http.StatusNotFound, "not_found", "No collected file for this collection.")
			return
		}
		record := r.Method == http.MethodGet && rangeIncludesStart(r.Header.Get("Range"))
		f, j, e := a.store.OpenCaseEvidence(r.Context(), r.PathValue("case"), r.PathValue("job"), s.Actor(), record, time.Now())
		if errors.Is(e, storage.ErrEvidence) {
			apiError(w, http.StatusNotFound, "not_found", "No collected file for this collection.")
			return
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The evidence file cannot be read from the evidence store. Check the evidence volume.")
			return
		}
		defer f.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(12 * time.Hour))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": j.Name()}))
		w.Header().Set("X-Content-SHA256", j.ServerSHA256)
		http.ServeContent(w, r, "", time.Time{}, f)
	})
	// The export carries every entry's exact text and hash; verify it with
	// openrmm-custody verify. A broken chain is exported as stored.
	a.route(mux, "GET /api/v1/cases/{case}/custody.json", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		c, records, e := a.store.CaseRecords(r.Context(), r.PathValue("case"))
		if errors.Is(e, storage.ErrCase) {
			apiError(w, http.StatusNotFound, "not_found", "Case not found.")
			return
		}
		if e != nil {
			unavailable(w)
			return
		}
		head := custody.Genesis
		if len(records) > 0 {
			head = records[len(records)-1].Hash
		}
		x := custody.Export{Format: custody.Format, Version: custody.Version, ExportedAt: custody.Stamp(time.Now()), Case: custody.Case{ID: c.ID, Title: c.Title, Status: c.Status, CreatedBy: c.CreatedBy, CreatedAt: custody.Stamp(time.Unix(c.CreatedAt, 0))}, Entries: records, Head: head}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="openrmm-case-`+c.ID+`-custody.json"`)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(x)
	})
}

// rangeIncludesStart reports whether a download request can return the
// file's first byte: no Range header, a range starting at byte 0, a suffix
// range (bytes=-N), or anything not understood. Such requests are recorded in
// the custody log; later parts of a download are not.
func rangeIncludesStart(header string) bool {
	specs, ok := strings.CutPrefix(header, "bytes=")
	if header == "" || !ok {
		return true
	}
	for _, spec := range strings.Split(specs, ",") {
		spec = strings.TrimSpace(spec)
		if strings.HasPrefix(spec, "-") || strings.HasPrefix(spec, "0-") || !strings.Contains(spec, "-") {
			return true
		}
		if start, _, _ := strings.Cut(spec, "-"); strings.Trim(start, "0123456789") != "" || strings.TrimLeft(start, "0") == "" {
			return true
		}
	}
	return false
}

// exportQuery builds the event XPath of an .evtx export: ""
// (the whole channel) without a filter.
func exportQuery(channel string, f *protocol.EventFilter) (string, bool) {
	if f == nil {
		return "", eventlogs.ValidChannel(channel)
	}
	v := *f
	v.Channel = channel
	q, e := eventlogs.ExportQuery(v)
	return q, e == nil
}
