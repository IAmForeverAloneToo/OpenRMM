package server

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// The response tool library: the owner uploads and withdraws
// tools; everyone with the response permission sees them and can drop them
// from a case.
func registerToolsAPI(mux *http.ServeMux, a *api) {
	a.route(mux, "GET /api/v1/response-tools", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.Tools(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The tool library is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Tools    []storage.ResponseTool `json:"tools"`
			MaxBytes int64                  `json:"max_bytes"`
		}{list, protocol.MaxDrop})
	})
	a.route(mux, "POST /api/v1/response-tools", ownerOnly, boundedBrowserFile(func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(2 * time.Hour))
		_ = rc.SetWriteDeadline(time.Now().Add(2*time.Hour + time.Minute))
		r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxDrop+64*1024)
		reader, e := r.MultipartReader()
		if e != nil {
			apiError(w, http.StatusBadRequest, "invalid_request", "Send the tool as a multipart upload.")
			return
		}
		fields := map[string]string{}
		for {
			part, e := reader.NextPart()
			if e == io.EOF {
				apiError(w, http.StatusBadRequest, "invalid_request", "The upload has no file.")
				return
			}
			if e != nil {
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid or oversized upload.")
				return
			}
			switch key := part.FormName(); {
			case (key == "name" || key == "description") && fields[key] == "":
				b, e := io.ReadAll(io.LimitReader(part, 4097))
				part.Close()
				if e != nil || len(b) > 4096 {
					apiError(w, http.StatusBadRequest, "invalid_request", "Invalid upload field.")
					return
				}
				fields[key] = string(b)
			case key == "file":
				// Name and description come before the file.
				if fields["name"] == "" {
					fields["name"] = part.FileName()
				}
				t, e := a.store.AddTool(r.Context(), fields["name"], fields["description"], s.Actor(), part, r.ContentLength, time.Now())
				part.Close()
				if errors.Is(e, storage.ErrTool) {
					apiError(w, http.StatusConflict, "tool", "The tool was not stored: check its name (no folder characters), that it is at most 4 GiB and that the evidence quota has room.")
					return
				}
				if e != nil {
					apiError(w, http.StatusServiceUnavailable, "unavailable", "The tool could not be stored. Check the evidence volume.")
					return
				}
				writeJSON(w, http.StatusCreated, t)
				return
			default:
				part.Close()
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid upload field.")
				return
			}
		}
	}))
	// Library scripts that can run from a case (their latest versions); the
	// RMM script pages stay owner-only.
	a.route(mux, "GET /api/v1/response-scripts", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		vs, e := a.store.ScriptVersions(r.Context(), "")
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The script library is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Scripts []storage.ScriptVersion `json:"scripts"`
		}{vs})
	})
	a.route(mux, "POST /api/v1/response-tools/{id}/withdraw", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.WithdrawTool(r.Context(), r.PathValue("id"), s.Actor(), time.Now()); e != nil {
			if errors.Is(e, storage.ErrTool) {
				apiError(w, http.StatusNotFound, "not_found", "Tool not found or already withdrawn.")
				return
			}
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The tool library is temporarily unavailable.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
