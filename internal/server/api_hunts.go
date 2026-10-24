package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Fleet searches and indicator hunts: the response
// permission starts them over the devices the account may reach; a search is visible to the account that
// started it and to the owner. Results are case evidence or, without a case,
// kept for 24 hours.
func registerHuntsAPI(mux *http.ServeMux, a *api) {
	// caseFor resolves a hunt's case: an open case, a new one with the title,
	// or none (LiveCase).
	caseFor := func(w http.ResponseWriter, r *http.Request, s storage.Session, id, title string) (string, bool) {
		if id != "" && title != "" || id != "" && (!protocol.ValidID(id) || id == storage.LiveCase) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose at most one case.")
			return "", false
		}
		if title != "" {
			c, e := a.store.CreateCase(r.Context(), title, s.Actor(), time.Now())
			if e != nil {
				apiError(w, http.StatusBadRequest, "case", "The case title is invalid (1–200 characters, no line breaks).")
				return "", false
			}
			return c.ID, true
		}
		if id != "" {
			return id, true
		}
		return storage.LiveCase, true
	}
	// started answers a hunt start; a case created for a hunt that could not
	// start is closed again.
	started := func(w http.ResponseWriter, r *http.Request, s storage.Session, h storage.Hunt, e error, caseID string, created bool, what string) {
		if e != nil && created {
			_ = a.store.SetCaseStatus(r.Context(), caseID, "closed", s.Actor(), "Not used: the "+what+" could not start.", time.Now())
		}
		switch {
		case e == nil:
			writeJSON(w, http.StatusCreated, h)
		case errors.Is(e, storage.ErrHunt) && len(h.Problems) > 0:
			writeJSON(w, http.StatusConflict, struct {
				Error    string                `json:"error"`
				Code     string                `json:"code"`
				Problems []storage.HuntProblem `json:"problems"`
			}{"None of the chosen devices can run this search.", "no_targets", h.Problems})
		case errors.Is(e, storage.ErrHuntSize):
			apiError(w, http.StatusBadRequest, "too_many", "The chosen devices and group members are more than 500; choose fewer.")
		case errors.Is(e, storage.ErrHunt):
			apiError(w, http.StatusBadRequest, "invalid_request", "Choose devices or groups you can access, and check that the evidence store is configured.")
		case errors.Is(e, storage.ErrCase):
			apiError(w, http.StatusConflict, "case", "The case is closed or unknown.")
		default:
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Searches are temporarily unavailable.")
		}
	}
	a.route(mux, "POST /api/v1/hunts/log-search", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Devices   []string             `json:"devices"`
			Groups    []string             `json:"groups"`
			Filter    protocol.EventFilter `json:"filter"`
			CaseID    string               `json:"case_id"`
			CaseTitle string               `json:"case_title"`
		}
		if !decodeJSON(w, r, &in, 64*1024) {
			return
		}
		in.Filter.Limit, in.Filter.Before = protocol.MaxEventPage, 0
		in.Filter.Channel, in.Filter.Provider, in.Filter.XPath = strings.TrimSpace(in.Filter.Channel), strings.TrimSpace(in.Filter.Provider), strings.TrimSpace(in.Filter.XPath)
		if !protocol.EventFilterValid(in.Filter) {
			apiError(w, http.StatusBadRequest, "invalid_request", "Use a channel name, a time range up to 31 days, valid filters and an XPath of the form *[...], and at most one case.")
			return
		}
		caseID, ok := caseFor(w, r, s, in.CaseID, in.CaseTitle)
		if !ok {
			return
		}
		h, e := a.store.StartLogSearch(r.Context(), caseID, in.Devices, in.Groups, in.Filter, s.Actor(), time.Now())
		started(w, r, s, h, e, caseID, in.CaseTitle != "", "log search")
	})
	// Indicator hunts: indicators as parsed by
	// /api/v1/hunts/indicators/parse (or from a saved list).
	a.route(mux, "POST /api/v1/hunts/indicators", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Devices    []string             `json:"devices"`
			Groups     []string             `json:"groups"`
			Indicators []protocol.Indicator `json:"indicators"`
			Files      bool                 `json:"files"`
			CaseID     string               `json:"case_id"`
			CaseTitle  string               `json:"case_title"`
		}
		if !decodeJSON(w, r, &in, 512*1024) {
			return
		}
		spec := protocol.HuntSpec{Indicators: in.Indicators, Files: in.Files}
		if !spec.Valid() {
			apiError(w, http.StatusBadRequest, "invalid_request", "Use 1 to 1,000 distinct valid indicators.")
			return
		}
		caseID, ok := caseFor(w, r, s, in.CaseID, in.CaseTitle)
		if !ok {
			return
		}
		h, e := a.store.StartIndicatorHunt(r.Context(), caseID, in.Devices, in.Groups, spec, s.Actor(), time.Now())
		started(w, r, s, h, e, caseID, in.CaseTitle != "", "indicator hunt")
	})
	a.route(mux, "POST /api/v1/hunts/indicators/parse", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Text string `json:"text"`
		}
		if !decodeJSON(w, r, &in, 512*1024) {
			return
		}
		list, problems := protocol.ParseIndicators(in.Text)
		writeJSON(w, http.StatusOK, struct {
			Indicators []protocol.Indicator `json:"indicators"`
			Problems   []string             `json:"problems"`
		}{list, problems})
	})
	// Saved indicator lists: anyone with the response permission manages
	// them.
	a.route(mux, "GET /api/v1/ioc-lists", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.IOCLists(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Indicator lists are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Lists []storage.IOCList `json:"lists"`
		}{list})
	})
	saveList := func(w http.ResponseWriter, r *http.Request, s storage.Session, id string) {
		var in struct {
			Name       string               `json:"name"`
			Indicators []protocol.Indicator `json:"indicators"`
		}
		if !decodeJSON(w, r, &in, 512*1024) {
			return
		}
		l, e := a.store.SaveIOCList(r.Context(), id, in.Name, in.Indicators, s.Actor(), time.Now())
		switch {
		case errors.Is(e, storage.ErrIOCList):
			apiError(w, http.StatusBadRequest, "invalid_request", "Use a unique name (1–100 characters) and 1 to 1,000 distinct valid indicators; at most 200 lists.")
		case e != nil:
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The list could not be saved.")
		case id == "":
			writeJSON(w, http.StatusCreated, l)
		default:
			writeJSON(w, http.StatusOK, l)
		}
	}
	a.route(mux, "POST /api/v1/ioc-lists", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		saveList(w, r, s, "")
	})
	a.route(mux, "PUT /api/v1/ioc-lists/{list}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if !protocol.ValidID(r.PathValue("list")) {
			apiError(w, http.StatusNotFound, "not_found", "No such list.")
			return
		}
		saveList(w, r, s, r.PathValue("list"))
	})
	a.route(mux, "DELETE /api/v1/ioc-lists/{list}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.DeleteIOCList(r.Context(), r.PathValue("list"), s.Actor(), time.Now()); errors.Is(e, storage.ErrIOCList) {
			apiError(w, http.StatusNotFound, "not_found", "No such list.")
			return
		} else if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The list could not be deleted.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a.route(mux, "GET /api/v1/hunts", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.Hunts(r.Context(), s.Actor(), s.Technician == nil)
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Searches are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Hunts []storage.HuntSummary `json:"hunts"`
		}{list})
	})
	// hunt loads a search the session may see.
	hunt := func(w http.ResponseWriter, r *http.Request, s storage.Session) (storage.Hunt, bool) {
		h, e := a.store.HuntDetail(r.Context(), r.PathValue("hunt"))
		if errors.Is(e, storage.ErrHunt) || e == nil && s.Technician != nil && h.Actor != s.Actor() {
			apiError(w, http.StatusNotFound, "not_found", "No such search.")
			return h, false
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Searches are temporarily unavailable.")
			return h, false
		}
		// A technician sees only devices still in their scope.
		if s.Technician != nil {
			targets, problems := []storage.HuntTarget{}, []storage.HuntProblem{}
			for _, t := range h.Targets {
				if a.store.AuthorizeDevice(r.Context(), s, t.DeviceID, "response") == nil {
					targets = append(targets, t)
				}
			}
			for _, p := range h.Problems {
				if a.store.AuthorizeDevice(r.Context(), s, p.DeviceID, "response") == nil {
					problems = append(problems, p)
				}
			}
			h.Targets, h.Problems = targets, problems
		}
		return h, true
	}
	a.route(mux, "GET /api/v1/hunts/{hunt}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if h, ok := hunt(w, r, s); ok {
			writeJSON(w, http.StatusOK, h)
		}
	})
	a.route(mux, "POST /api/v1/hunts/{hunt}/cancel", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if _, ok := hunt(w, r, s); !ok {
			return
		}
		if e := a.store.CancelHunt(r.Context(), r.PathValue("hunt"), s.Actor(), time.Now()); e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The search could not be cancelled.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// A device's result document; reading a case result is recorded in its
	// custody log like any download.
	a.route(mux, "GET /api/v1/hunts/{hunt}/jobs/{job}/result", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if _, ok := hunt(w, r, s); !ok {
			return
		}
		caseID, device, e := a.store.HuntJobCase(r.Context(), r.PathValue("hunt"), r.PathValue("job"))
		if e != nil {
			apiError(w, http.StatusNotFound, "not_found", "No result for this device.")
			return
		}
		if a.store.AuthorizeDevice(r.Context(), s, device, "response") != nil {
			apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
			return
		}
		f, _, e := a.store.OpenCaseEvidence(r.Context(), caseID, r.PathValue("job"), s.Actor(), true, time.Now())
		if errors.Is(e, storage.ErrEvidence) {
			apiError(w, http.StatusNotFound, "not_found", "No result for this device (results without a case are kept for 24 hours).")
			return
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The result cannot be read. Check the evidence volume.")
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/json")
		http.ServeContent(w, r, "", time.Time{}, f)
	})
}
