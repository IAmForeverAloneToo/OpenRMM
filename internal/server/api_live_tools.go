package server

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
)

// Live sessions belong to the browser session that created them (its token
// hash). They are kept only in bounded server memory and end on disconnect,
// idle, expiry, sign-out or authorization change. A terminal opened from a
// case is also recorded to the case as evidence.

func liveError(w http.ResponseWriter, e error, invalid, unavailable error, unavailableMessage string) {
	switch {
	case errors.Is(e, invalid), errors.Is(e, storage.ErrAuthentication):
		apiError(w, http.StatusNotFound, "ended", "This session has ended or is not available.")
	case errors.Is(e, unavailable):
		apiError(w, http.StatusConflict, "unavailable", unavailableMessage)
	case errors.Is(e, storage.ErrForbidden):
		apiError(w, http.StatusForbidden, "forbidden", "Your account no longer has access to this device.")
	default:
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Live sessions are temporarily unavailable.")
	}
}

func endedResponse(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusGone, struct {
		Error  string `json:"error"`
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}{"The session ended.", "ended", reason})
}

// Browser uploads/downloads use their own small pool so they can never starve
// agent file polls, which use fileSlots on the device listener.
var browserFileSlots = make(chan struct{}, 2)

func boundedBrowserFile(next apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		select {
		case browserFileSlots <- struct{}{}:
			defer func() { <-browserFileSlots }()
			next(w, r, s)
		default:
			w.Header().Set("Retry-After", "5")
			apiError(w, http.StatusTooManyRequests, "busy", "Another file transfer is in progress. Try again in a few seconds.")
		}
	}
}

func registerLiveToolsAPI(mux *http.ServeMux, a *api) {
	if a.devices != nil && a.devices.Terminal != nil {
		registerTerminalAPI(mux, a, a.devices.Terminal)
	}
	if a.devices != nil && a.devices.Desktop != nil {
		registerDesktopAPI(mux, a, a.devices.Desktop)
	}
	registerFilesAPI(mux, a)
}

// Terminal: the live response console. The owner and
// technicians with the response permission and access to the device; the
// shell runs as SYSTEM on the device. With a case (an open one, or a new one
// from case_title) the session is recorded to it; without one nothing is
// kept as evidence.
func registerTerminalAPI(mux *http.ServeMux, a *api, h *terminal.Hub) {
	const unavailable = "Live response is not available. The agent must be connected with the terminal turned on, and only one session can run per device."
	a.route(mux, "POST /api/v1/devices/{id}/terminal", deviceAccess("response"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			CaseID    string `json:"case_id"`
			CaseTitle string `json:"case_title"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		if in.CaseID != "" && (!protocol.ValidID(in.CaseID) || in.CaseID == storage.LiveCase) || in.CaseID != "" && in.CaseTitle != "" {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid case.")
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
		if in.CaseTitle != "" {
			c, e := a.store.CreateCase(r.Context(), in.CaseTitle, s.Actor(), time.Now())
			if e != nil {
				apiError(w, http.StatusBadRequest, "case", "The case title is invalid (1–200 characters, no line breaks).")
				return
			}
			in.CaseID = c.ID
		}
		var open func(string) (terminal.Recorder, error)
		if in.CaseID != "" {
			open = func(session string) (terminal.Recorder, error) {
				return a.store.StartTranscript(r.Context(), in.CaseID, view.ID, s.Actor(), session, time.Now())
			}
		}
		q, e := h.CreateRecorded(r.Context(), view.ID, s.TokenHash, s.Actor(), in.CaseID, open)
		switch {
		case e == nil:
			writeJSON(w, http.StatusCreated, q)
		case errors.Is(e, storage.ErrCase):
			apiError(w, http.StatusConflict, "case", "The case is closed or unknown. Reload the case and try again.")
		case errors.Is(e, storage.ErrEvidence):
			apiError(w, http.StatusConflict, "evidence", "The terminal cannot be recorded: the evidence store is not configured on the server.")
		default:
			liveError(w, e, terminal.ErrInvalid, terminal.ErrUnavailable, unavailable)
		}
	})
	a.route(mux, "GET /api/v1/terminal/{session}/output", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		after, e := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if e != nil {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid output cursor.")
			return
		}
		id := r.PathValue("session")
		v, e := h.View(r.Context(), id, s.TokenHash, after)
		if e != nil {
			if errors.Is(e, terminal.ErrInvalid) {
				if reason, ok := h.EndReason(r.Context(), id, s.TokenHash); ok {
					endedResponse(w, reason)
					return
				}
			}
			liveError(w, e, terminal.ErrInvalid, terminal.ErrUnavailable, unavailable)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	a.route(mux, "POST /api/v1/terminal/{session}/input", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var v terminal.Input
		if !decodeJSON(w, r, &v, terminal.MaxWire) {
			return
		}
		if e := h.Input(r.Context(), r.PathValue("session"), s.TokenHash, v); e != nil {
			liveError(w, e, terminal.ErrInvalid, terminal.ErrUnavailable, unavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "POST /api/v1/terminal/{session}/stop", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := h.Stop(r.Context(), r.PathValue("session"), s.TokenHash); e != nil && !errors.Is(e, terminal.ErrInvalid) {
			liveError(w, e, terminal.ErrInvalid, terminal.ErrUnavailable, unavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	registerLiveResponseAPI(mux, a, h)
}

// Remote desktop: the Desktop permission on the device to start; the account's
// Desktop permission for an existing session it owns. Sessions start without
// asking and the companion stays hidden; display and
// quality are chosen here, at start and during the session.
func registerDesktopAPI(mux *http.ServeMux, a *api, h *desktop.Hub) {
	const unavailable = "Remote desktop is not available. A user must be signed in on the device with the OpenRMM desktop companion running (the agent starts it within a minute of sign-in), remote desktop must be turned on for the device, and only one session can run per device."
	a.route(mux, "GET /api/v1/devices/{id}/desktop/displays", deviceAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		_, view, ok := a.deviceView(w, r)
		if !ok {
			return
		}
		displays, available, e := h.Displays(r.Context(), view.ID, s.TokenHash)
		if e != nil {
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Available bool              `json:"available"`
			Displays  []desktop.Display `json:"displays"`
			Qualities []string          `json:"qualities"`
		}{available, displays, desktop.Qualities})
	})
	a.route(mux, "POST /api/v1/devices/{id}/desktop", deviceAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Mode    string `json:"mode"`
			Display int    `json:"display"`
			Quality string `json:"quality"`
		}
		if !decodeJSON(w, r, &in, 256) {
			return
		}
		if in.Mode != "view" && in.Mode != "control" {
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose view or control.")
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
		q, e := h.Create(r.Context(), view.ID, s.TokenHash, s.Actor(), in.Mode == "control", in.Display, in.Quality)
		if e != nil {
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		writeJSON(w, http.StatusCreated, q)
	})
	a.route(mux, "GET /api/v1/desktop/{session}", featureAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		id := r.PathValue("session")
		v, _, e := h.View(r.Context(), id, s.TokenHash)
		if e != nil {
			if errors.Is(e, desktop.ErrInvalid) {
				if reason := h.EndReason(r.Context(), id, s.TokenHash); reason != "" {
					endedResponse(w, reason)
					return
				}
			}
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
	// Frames are binary; state travels in headers. 204 means no fresh frame.
	a.route(mux, "GET /api/v1/desktop/{session}/frame", featureAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		id := r.PathValue("session")
		v, b, e := h.View(r.Context(), id, s.TokenHash)
		if e != nil {
			if errors.Is(e, desktop.ErrInvalid) {
				if reason := h.EndReason(r.Context(), id, s.TokenHash); reason != "" {
					endedResponse(w, reason)
					return
				}
			}
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		w.Header().Set("X-Desktop-State", v.State)
		w.Header().Set("X-Desktop-Frame-Age", strconv.FormatInt(v.FrameAge, 10))
		if len(b) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(b)
	})
	a.route(mux, "POST /api/v1/desktop/{session}/input", featureAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var b desktop.Batch
		if !decodeJSON(w, r, &b, 16384) {
			return
		}
		if e := h.Input(r.Context(), r.PathValue("session"), s.TokenHash, b); e != nil {
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "POST /api/v1/desktop/{session}/configure", featureAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Display int    `json:"display"`
			Quality string `json:"quality"`
		}
		if !decodeJSON(w, r, &in, 256) {
			return
		}
		if e := h.Configure(r.Context(), r.PathValue("session"), s.TokenHash, in.Display, in.Quality); e != nil {
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "POST /api/v1/desktop/{session}/stop", featureAccess("desktop"), func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := h.Stop(r.Context(), r.PathValue("session"), s.TokenHash); e != nil && !errors.Is(e, desktop.ErrInvalid) {
			liveError(w, e, desktop.ErrInvalid, desktop.ErrUnavailable, unavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// Files: locally allowed folders only, 8 MiB per file, create-only uploads that
// are staged and then confirmed. Every route needs the Files permission.
func registerFilesAPI(mux *http.ServeMux, a *api) {
	files := deviceAccess("files")
	a.route(mux, "GET /api/v1/devices/{id}/files", files, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		d, view, ok := a.deviceView(w, r)
		if !ok {
			return
		}
		if d.RevokedAt != nil {
			apiError(w, http.StatusNotFound, "not_found", "Device not found.")
			return
		}
		now := time.Now()
		support, e1 := a.store.FileSupport(r.Context(), d.ID)
		jobs, e2 := a.store.FileJobs(r.Context(), s, d.ID, now)
		if errors.Join(e1, e2) != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "File access is temporarily unavailable.")
			return
		}
		age := now.Sub(time.Unix(support.ReportedAt, 0))
		available := support.Status == "ok" && age >= 0 && age < 2*time.Minute && len(support.Support.Roots) > 0 && view.Status == "online"
		writeJSON(w, http.StatusOK, struct {
			Support   storage.FileSupport `json:"support"`
			Available bool                `json:"available"`
			Jobs      []storage.FileJob   `json:"jobs"`
			MaxBytes  int                 `json:"max_bytes"`
		}{support, available, jobs, filetransfer.MaxFile})
	})
	a.route(mux, "POST /api/v1/devices/{id}/files", files, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			ID        string `json:"id"`
			Operation string `json:"operation"`
			Root      string `json:"root"`
			Path      string `json:"path"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		q := protocol.FileJob{ID: in.ID, Operation: in.Operation, Root: in.Root, Path: in.Path, ExpiresAt: time.Now().Add(time.Minute).Unix()}
		if q.Operation != "list" && q.Operation != "download" || !filetransfer.JobValid(q) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid folder or file.")
			return
		}
		if e := a.store.QueueFile(r.Context(), q, r.PathValue("id"), s.Actor(), time.Now(), a.offlineAfter()); e != nil {
			queueError(w, e, storage.ErrFile, "File access is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusAccepted, struct {
			ID string `json:"id"`
		}{q.ID})
	})
	// Upload stages content on the server; nothing reaches the device until
	// the stage is confirmed.
	a.route(mux, "POST /api/v1/devices/{id}/files/upload", files, boundedBrowserFile(func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		r.Body = http.MaxBytesReader(w, r.Body, filetransfer.MaxFile+32768)
		reader, e := r.MultipartReader()
		if e != nil {
			apiError(w, http.StatusBadRequest, "invalid_request", "Send the file as a multipart upload.")
			return
		}
		fields := map[string]string{}
		var data []byte
		filename, seenFile, parts := "", false, 0
		for {
			part, e := reader.NextPart()
			if e == io.EOF {
				break
			}
			if e != nil {
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid or oversized upload.")
				return
			}
			parts++
			key := part.FormName()
			switch {
			case parts > 5:
				part.Close()
				apiError(w, http.StatusBadRequest, "invalid_request", "Too many upload fields.")
				return
			case key == "file" && !seenFile:
				seenFile = true
				filename = part.FileName()
				data, e = io.ReadAll(io.LimitReader(part, filetransfer.MaxFile+1))
				part.Close()
				if e != nil || len(data) > filetransfer.MaxFile {
					apiError(w, http.StatusRequestEntityTooLarge, "too_large", "Files are limited to 8 MiB.")
					return
				}
			case (key == "id" || key == "root" || key == "path") && fields[key] == "":
				b, e := io.ReadAll(io.LimitReader(part, 2049))
				part.Close()
				if e != nil || len(b) > 2048 {
					apiError(w, http.StatusBadRequest, "invalid_request", "Invalid upload field.")
					return
				}
				fields[key] = string(b)
			default:
				part.Close()
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid upload field.")
				return
			}
		}
		if !seenFile || !filetransfer.Name(filename) || !filetransfer.Path(fields["path"]) {
			apiError(w, http.StatusBadRequest, "invalid_request", "This file name or folder is not allowed.")
			return
		}
		q := protocol.FileJob{ID: fields["id"], Operation: "upload", Root: fields["root"], Path: path.Join(fields["path"], filename), Data: data, Size: int64(len(data)), Hash: filetransfer.Digest(data), ExpiresAt: time.Now().Add(time.Minute).Unix()}
		if !filetransfer.JobValid(q) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Invalid upload.")
			return
		}
		if e := a.store.QueueFile(r.Context(), q, r.PathValue("id"), s.Actor(), time.Now(), a.offlineAfter()); e != nil {
			queueError(w, e, storage.ErrFile, "Uploads are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			ID     string `json:"id"`
			Path   string `json:"path"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		}{q.ID, q.Path, q.Size, q.Hash})
	}))
	for _, op := range []string{"confirm", "cancel"} {
		a.route(mux, "POST /api/v1/devices/{id}/files/{file}/"+op, files, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			id, file := r.PathValue("id"), r.PathValue("file")
			if !protocol.ValidID(file) {
				apiError(w, http.StatusNotFound, "not_found", "Transfer not found.")
				return
			}
			var e error
			if op == "confirm" {
				e = a.store.ConfirmFile(r.Context(), s, id, file, time.Now(), a.offlineAfter())
			} else {
				e = a.store.CancelFile(r.Context(), s, id, file, time.Now())
			}
			if e != nil {
				queueError(w, e, storage.ErrFile, "File transfers are temporarily unavailable.")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	a.route(mux, "GET /api/v1/devices/{id}/files/{file}/download", files, boundedBrowserFile(func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if !protocol.ValidID(r.PathValue("file")) {
			apiError(w, http.StatusNotFound, "not_found", "Transfer not found.")
			return
		}
		job, b, e := a.store.FileDownload(r.Context(), s, r.PathValue("id"), r.PathValue("file"), time.Now())
		if e != nil {
			apiError(w, http.StatusGone, "expired", "This download is no longer available. Downloads are kept for 15 minutes.")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(job.Path)}))
		w.Header().Set("X-Content-SHA256", job.Result.Hash)
		_, _ = w.Write(b)
	}))
}
