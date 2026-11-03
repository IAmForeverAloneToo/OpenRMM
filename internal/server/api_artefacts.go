package server

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// Parsed artefacts of triage packages, hives and event logs are read on
// the server: the manifest, pages of a table with filters, a table as CSV
// and the whole results as a ZIP. Opening the manifest and each download
// are recorded in the custody log; paging is not recorded again. A
// collection can be parsed again on request.
func registerArtefactsAPI(mux *http.ServeMux, a *api) {
	// caseOf names the case of the request's collection; for console
	// results it also checks access to the device.
	caseJob := func(w http.ResponseWriter, r *http.Request, s storage.Session) (string, bool) {
		return r.PathValue("case"), true
	}
	sessionJob := func(w http.ResponseWriter, r *http.Request, s storage.Session) (string, bool) {
		caseID, device, e := a.store.SessionJobCase(r.Context(), r.PathValue("session"), s.Actor(), r.PathValue("job"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "No result for this command.")
			return "", false
		}
		if a.store.AuthorizeDevice(r.Context(), s, device, "response") != nil {
			apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
			return "", false
		}
		return caseID, true
	}
	for prefix, caseOf := range map[string]func(http.ResponseWriter, *http.Request, storage.Session) (string, bool){
		"/api/v1/cases/{case}/collections/{job}": caseJob,
		"/api/v1/terminal/{session}/jobs/{job}":  sessionJob,
	} {
		open := func(w http.ResponseWriter, r *http.Request, s storage.Session, record bool) (*os.File, storage.EvidenceJob, *zip.Reader, bool) {
			caseID, ok := caseOf(w, r, s)
			if !ok {
				return nil, storage.EvidenceJob{}, nil, false
			}
			f, j, e := a.store.OpenParsed(r.Context(), caseID, r.PathValue("job"), s.Actor(), record, time.Now())
			if errors.Is(e, storage.ErrEvidence) {
				apiError(w, http.StatusNotFound, "not_found", "No parsed artefacts for this collection yet.")
				return nil, j, nil, false
			}
			if e != nil {
				apiError(w, http.StatusServiceUnavailable, "unavailable", "The parsed artefacts cannot be read from the evidence store. Check the evidence volume.")
				return nil, j, nil, false
			}
			zr, e := zip.NewReader(f, j.Size)
			if e != nil {
				f.Close()
				apiError(w, http.StatusUnprocessableEntity, "package", "The parsed artefacts are not a readable ZIP file.")
				return nil, j, nil, false
			}
			return f, j, zr, true
		}
		manifest := func(w http.ResponseWriter, zr *zip.Reader) (artefacts.Manifest, bool) {
			var m artefacts.Manifest
			rc, e := zr.Open("manifest.json")
			if e == nil {
				e = json.NewDecoder(io.LimitReader(rc, 8<<20)).Decode(&m)
				rc.Close()
			}
			if e != nil || m.Format != artefacts.Format {
				apiError(w, http.StatusUnprocessableEntity, "package", "The parsed artefacts have no readable manifest.")
				return m, false
			}
			return m, true
		}
		a.route(mux, "GET "+prefix+"/parsed", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			f, j, zr, ok := open(w, r, s, true)
			if !ok {
				return
			}
			defer f.Close()
			if r.URL.Query().Get("format") == "zip" {
				_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Hour))
				w.Header().Set("Content-Type", "application/zip")
				w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "parsed-" + j.ID[:8] + ".zip"}))
				w.Header().Set("Content-Length", strconv.FormatInt(j.Size, 10))
				_, _ = io.Copy(w, f)
				return
			}
			if m, ok := manifest(w, zr); ok {
				writeJSON(w, http.StatusOK, m)
			}
		})
		a.route(mux, "GET "+prefix+"/parsed/{table}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			table := r.PathValue("table")
			if !tableName.MatchString(table) {
				apiError(w, http.StatusNotFound, "not_found", "No such table.")
				return
			}
			csvOut := r.URL.Query().Get("format") == "csv"
			f, j, zr, ok := open(w, r, s, csvOut)
			if !ok {
				return
			}
			defer f.Close()
			m, ok := manifest(w, zr)
			if !ok {
				return
			}
			i := slices.IndexFunc(m.Tables, func(t artefacts.TableInfo) bool { return t.Name == table })
			rc, e := zr.Open("tables/" + table + ".csv")
			if i < 0 || e != nil {
				apiError(w, http.StatusNotFound, "not_found", "The parsed artefacts have no such table.")
				return
			}
			defer rc.Close()
			if csvOut {
				_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Hour))
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "parsed-" + j.ID[:8] + "-" + table + ".csv"}))
				_, _ = io.Copy(w, rc)
				return
			}
			q := r.URL.Query()
			filter := artefacts.Filter{Contains: q.Get("q")}
			for _, b := range []struct {
				name string
				to   *string
			}{{"from", &filter.From}, {"to", &filter.To}} {
				if v := q.Get(b.name); v != "" {
					t, e := time.Parse(time.RFC3339, v)
					if e != nil {
						apiError(w, http.StatusBadRequest, "invalid_request", "Times must be RFC 3339, such as 2026-11-03T12:00:00Z.")
						return
					}
					*b.to = artefacts.Stamp(t)
				}
			}
			offset, _ := strconv.Atoi(q.Get("offset"))
			limit, e := strconv.Atoi(q.Get("limit"))
			if e != nil {
				limit = 100
			}
			if len(filter.Contains) > 400 || offset < 0 || offset > 10_000_000 || limit < 1 || limit > artefacts.MaxPage {
				apiError(w, http.StatusBadRequest, "invalid_request", "The filter is too long or the page is out of range (up to 500 rows).")
				return
			}
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
			p, e := artefacts.Query(rc, m.Tables[i].Times, filter, offset, limit)
			if e != nil {
				apiError(w, http.StatusUnprocessableEntity, "package", "The table cannot be read.")
				return
			}
			writeJSON(w, http.StatusOK, p)
		})
		a.route(mux, "POST "+prefix+"/parse", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			caseID, ok := caseOf(w, r, s)
			if !ok {
				return
			}
			switch e := a.store.QueueParse(r.Context(), caseID, r.PathValue("job"), s.Actor(), time.Now()); {
			case errors.Is(e, storage.ErrParseBusy):
				apiError(w, http.StatusConflict, "busy", "This collection is already being parsed.")
			case errors.Is(e, storage.ErrEvidence), errors.Is(e, storage.ErrCase):
				apiError(w, http.StatusConflict, "evidence", "Only finished triage packages, registry hives and event logs of an open case can be parsed.")
			case e != nil:
				apiError(w, http.StatusServiceUnavailable, "unavailable", "Parsing is temporarily unavailable.")
			default:
				w.WriteHeader(http.StatusAccepted)
			}
		})
	}
}
