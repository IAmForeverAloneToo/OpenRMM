package server

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/ntfs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// NTFS artifact packages are read on the server: the manifest, pages of a
// timeline with filters, and a timeline as CSV. Opening the manifest and
// downloading a CSV are recorded in the custody log like a download; paging
// through a timeline is not recorded again.
func registerNTFSAPI(mux *http.ServeMux, a *api) {
	caseJob := func(w http.ResponseWriter, r *http.Request, s storage.Session, record bool) (*os.File, storage.EvidenceJob, bool) {
		if r.PathValue("case") == storage.LiveCase {
			apiError(w, http.StatusNotFound, "not_found", "No NTFS package for this collection.")
			return nil, storage.EvidenceJob{}, false
		}
		return a.openNTFS(w, r, s, r.PathValue("case"), record)
	}
	sessionJob := func(w http.ResponseWriter, r *http.Request, s storage.Session, record bool) (*os.File, storage.EvidenceJob, bool) {
		caseID, device, e := a.store.SessionJobCase(r.Context(), r.PathValue("session"), s.Actor(), r.PathValue("job"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "No result for this command.")
			return nil, storage.EvidenceJob{}, false
		}
		if a.store.AuthorizeDevice(r.Context(), s, device, "response") != nil {
			apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
			return nil, storage.EvidenceJob{}, false
		}
		return a.openNTFS(w, r, s, caseID, record)
	}
	for prefix, open := range map[string]func(http.ResponseWriter, *http.Request, storage.Session, bool) (*os.File, storage.EvidenceJob, bool){
		"/api/v1/cases/{case}/collections/{job}/ntfs": caseJob,
		"/api/v1/terminal/{session}/jobs/{job}/ntfs":  sessionJob,
	} {
		a.route(mux, "GET "+prefix, responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			f, j, ok := open(w, r, s, true)
			if !ok {
				return
			}
			defer f.Close()
			zr, ok := ntfsPackage(w, f, j)
			if !ok {
				return
			}
			rc, e := zr.Open("manifest.json")
			var m protocol.NTFSManifest
			if e == nil {
				e = json.NewDecoder(io.LimitReader(rc, 1<<20)).Decode(&m)
				rc.Close()
			}
			if e != nil || m.Format != protocol.NTFSFormat {
				apiError(w, http.StatusUnprocessableEntity, "package", "The package has no readable manifest.")
				return
			}
			writeJSON(w, http.StatusOK, m)
		})
		a.route(mux, "GET "+prefix+"/{volume}/{table}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			volume, table := r.PathValue("volume"), r.PathValue("table")
			if len(volume) != 1 || volume[0] < 'A' || volume[0] > 'Z' || table != "mft" && table != "usn" {
				apiError(w, http.StatusNotFound, "not_found", "No such timeline.")
				return
			}
			csvOut := r.URL.Query().Get("format") == "csv"
			f, j, ok := open(w, r, s, csvOut)
			if !ok {
				return
			}
			defer f.Close()
			zr, ok := ntfsPackage(w, f, j)
			if !ok {
				return
			}
			rc, e := zr.Open(volume + "/" + table + ".csv")
			if e != nil {
				apiError(w, http.StatusNotFound, "not_found", "The package has no such timeline (the volume may not have been read).")
				return
			}
			defer rc.Close()
			if csvOut {
				_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Hour))
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "ntfs-" + j.ID[:8] + "-" + volume + "-" + table + ".csv"}))
				_, _ = io.Copy(w, rc)
				return
			}
			q := r.URL.Query()
			filter := ntfs.Filter{Contains: q.Get("q"), Deleted: q.Get("deleted") == "1", Reasons: q["reason"]}
			for _, b := range []struct {
				name string
				to   *string
			}{{"from", &filter.From}, {"to", &filter.To}} {
				if v := q.Get(b.name); v != "" {
					t, e := time.Parse(time.RFC3339, v)
					if e != nil {
						apiError(w, http.StatusBadRequest, "invalid_request", "Times must be RFC 3339, such as 2026-10-30T12:00:00Z.")
						return
					}
					*b.to = t.UTC().Format("2006-01-02 15:04:05.0000000")
				}
			}
			offset, _ := strconv.Atoi(q.Get("offset"))
			limit, e := strconv.Atoi(q.Get("limit"))
			if e != nil {
				limit = 100
			}
			if len(filter.Contains) > 400 || len(filter.Reasons) > 25 || offset < 0 || offset > 10_000_000 {
				apiError(w, http.StatusBadRequest, "invalid_request", "The filter is too long or the page is out of range.")
				return
			}
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
			p, e := ntfs.QueryCSV(rc, filter, offset, limit)
			if e != nil && !errors.Is(e, ntfs.ErrCorrupt) {
				apiError(w, http.StatusBadRequest, "invalid_request", "Use a known change reason and a page of up to 500 rows.")
				return
			}
			if e != nil {
				apiError(w, http.StatusUnprocessableEntity, "package", "The timeline cannot be read.")
				return
			}
			writeJSON(w, http.StatusOK, p)
		})
	}
}

// openNTFS opens a succeeded NTFS collection's stored package.
func (a *api) openNTFS(w http.ResponseWriter, r *http.Request, s storage.Session, caseID string, record bool) (*os.File, storage.EvidenceJob, bool) {
	f, j, e := a.store.OpenCaseEvidence(r.Context(), caseID, r.PathValue("job"), s.Actor(), record, time.Now())
	if errors.Is(e, storage.ErrEvidence) {
		apiError(w, http.StatusNotFound, "not_found", "No NTFS package for this collection (results without a case are kept for 24 hours).")
		return nil, j, false
	}
	if e != nil {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "The package cannot be read from the evidence store. Check the evidence volume.")
		return nil, j, false
	}
	if j.Source != "ntfs" {
		f.Close()
		apiError(w, http.StatusNotFound, "not_found", "This collection is not an NTFS package.")
		return nil, j, false
	}
	return f, j, true
}

func ntfsPackage(w http.ResponseWriter, f *os.File, j storage.EvidenceJob) (*zip.Reader, bool) {
	zr, e := zip.NewReader(f, j.Size)
	if e != nil {
		apiError(w, http.StatusUnprocessableEntity, "package", "The package is not a readable ZIP file.")
		return nil, false
	}
	return zr, true
}
