package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// YARA rule sets: responders list, read and check rules; the owner adds,
// changes and withdraws sets.
func registerYaraAPI(mux *http.ServeMux, a *api) {
	a.route(mux, "GET /api/v1/yara-rule-sets", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		list, e := a.store.YaraRuleSets(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Rule sets are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Sets []storage.YaraRuleSet `json:"sets"`
		}{list})
	})
	a.route(mux, "GET /api/v1/yara-rule-sets/{set}", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		set, e := a.store.YaraRuleSet(r.Context(), r.PathValue("set"))
		if errors.Is(e, storage.ErrYaraSet) {
			apiError(w, http.StatusNotFound, "not_found", "No such rule set.")
			return
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Rule sets are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, set)
	})
	a.route(mux, "POST /api/v1/yara/check", responseAccess, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Source string `json:"source"`
		}
		if !decodeJSON(w, r, &in, storage.MaxYaraSource+4096) {
			return
		}
		n, e := storage.CheckYara(in.Source)
		if e != nil {
			apiError(w, http.StatusBadRequest, "rules", yaraReason(e))
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Rules int `json:"rules"`
		}{n})
	})
	save := func(w http.ResponseWriter, r *http.Request, s storage.Session, id string) {
		var in struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		}
		if !decodeJSON(w, r, &in, storage.MaxYaraSource+4096) {
			return
		}
		set, e := a.store.SaveYaraRuleSet(r.Context(), id, in.Name, in.Source, s.Actor(), time.Now())
		switch {
		case errors.Is(e, storage.ErrYaraRules):
			apiError(w, http.StatusBadRequest, "rules", yaraReason(e))
		case errors.Is(e, storage.ErrYaraSet):
			apiError(w, http.StatusBadRequest, "invalid_request", "Use a unique name of 1–100 characters; at most 200 rule sets. A withdrawn set cannot be changed.")
		case e != nil:
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The rule set could not be saved.")
		case id == "":
			writeJSON(w, http.StatusCreated, set)
		default:
			writeJSON(w, http.StatusOK, set)
		}
	}
	a.route(mux, "POST /api/v1/yara-rule-sets", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		save(w, r, s, "")
	})
	a.route(mux, "PUT /api/v1/yara-rule-sets/{set}", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if !protocol.ValidID(r.PathValue("set")) {
			apiError(w, http.StatusNotFound, "not_found", "No such rule set.")
			return
		}
		save(w, r, s, r.PathValue("set"))
	})
	a.route(mux, "POST /api/v1/yara-rule-sets/{set}/withdraw", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.WithdrawYaraRuleSet(r.Context(), r.PathValue("set"), s.Actor(), time.Now()); errors.Is(e, storage.ErrYaraSet) {
			apiError(w, http.StatusNotFound, "not_found", "No such rule set.")
			return
		} else if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The rule set could not be withdrawn.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// yaraInput chooses the rules of a YARA scan: a saved set, or rules pasted
// for this run; Memory, Path and PID say what to scan besides files.
type yaraInput struct {
	Set    string `json:"set"`
	Rules  string `json:"rules"`
	Memory bool   `json:"memory"`
	Path   string `json:"path"`
	PID    uint32 `json:"pid"`
}

// yaraSpec resolves the rules, checks them and keeps them by hash for the
// jobs that run them.
func (a *api) yaraSpec(w http.ResponseWriter, r *http.Request, in yaraInput) (*protocol.YaraSpec, bool) {
	source, name := in.Rules, "pasted rules"
	if in.Set != "" {
		set, e := a.store.YaraRuleSet(r.Context(), in.Set)
		if errors.Is(e, storage.ErrYaraSet) {
			apiError(w, http.StatusBadRequest, "invalid_request", "No such rule set (it may have been withdrawn).")
			return nil, false
		}
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Rule sets are temporarily unavailable.")
			return nil, false
		}
		source, name = set.Source, set.Name+" v"+strconv.Itoa(set.Version)
	}
	hash, _, e := a.store.KeepYaraSource(r.Context(), source, time.Now())
	if errors.Is(e, storage.ErrYaraRules) {
		apiError(w, http.StatusBadRequest, "rules", yaraReason(e))
		return nil, false
	}
	if e != nil {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "The rules could not be stored.")
		return nil, false
	}
	return &protocol.YaraSpec{Name: name, SHA256: hash, Memory: in.Memory, Path: in.Path, PID: in.PID}, true
}

// yaraReason is a compile error as shown to the user ("line 3: ...").
func yaraReason(e error) string {
	return strings.TrimPrefix(e.Error(), storage.ErrYaraRules.Error()+": ")
}
