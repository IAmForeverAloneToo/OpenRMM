package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

const sessionCookie = "__Host-openrmm-session"

// api serves the administrator JSON API used by the browser application.
type api struct {
	auth    *auth.Service
	store   *storage.Store
	devices *devices.Service
	updates *serverUpdates
	mail    *mailSource
}

// access declares who may call a route. The zero value is owner-only, so a
// route is never opened to technicians by omission.
type access struct {
	technicians bool   // technicians may call it; handlers/storage scope the data
	device      string // technicians need this permission on the {id} device
	feature     string // technicians need this account permission (no device in the path)
}

var (
	ownerOnly  = access{}
	anyAccount = access{technicians: true}
)

func deviceAccess(kind string) access  { return access{technicians: true, device: kind} }
func featureAccess(kind string) access { return access{technicians: true, feature: kind} }

type apiHandler func(http.ResponseWriter, *http.Request, storage.Session)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{message, code})
}

// decodeJSON accepts exactly one JSON object of known fields within limit.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	typeName, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typeName != "application/json" {
		apiError(w, http.StatusUnsupportedMediaType, "invalid_request", "Send a JSON request body.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			apiError(w, http.StatusRequestEntityTooLarge, "too_large", "The request is too large.")
		} else {
			apiError(w, http.StatusBadRequest, "invalid_request", "The request could not be read.")
		}
		return false
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		apiError(w, http.StatusBadRequest, "invalid_request", "The request could not be read.")
		return false
	}
	return true
}

func (a *api) currentSession(r *http.Request) (storage.Session, string, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return storage.Session{}, "", storage.ErrAuthentication
	}
	s, err := a.auth.Session(r.Context(), c.Value)
	return s, c.Value, err
}

// route registers an authenticated handler. Every state-changing method must
// carry the session's CSRF token in X-CSRF-Token, in addition to the
// cross-origin protection applied to the whole listener.
// workWake decides, per route, which waiting agents a change may have given
// work: the device in the path, or every device for fleet-wide operations.
// Reads and session input (typing, mouse) wake nobody.
func workWake(pattern string) func(*api, *http.Request) {
	method, path, _ := strings.Cut(pattern, " ")
	switch {
	case method == http.MethodGet || method == http.MethodHead || strings.HasSuffix(path, "/input"):
		return nil
	case strings.HasPrefix(path, "/api/v1/devices/{id}/"):
		return func(a *api, r *http.Request) {
			if a.devices != nil {
				a.devices.Notify(r.PathValue("id"))
			}
		}
	}
	return func(a *api, _ *http.Request) {
		if a.devices != nil {
			a.devices.Notify("")
		}
	}
}

func (a *api) route(mux *http.ServeMux, pattern string, p access, h apiHandler) {
	wake := workWake(pattern)
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if wake != nil {
			defer wake(a, r)
		}
		s, _, err := a.currentSession(r)
		if err != nil {
			if errors.Is(err, storage.ErrAuthentication) {
				http.SetCookie(w, cookie(sessionCookie, "", -1))
				apiError(w, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
			} else {
				apiError(w, http.StatusServiceUnavailable, "unavailable", "Sign-in is temporarily unavailable.")
			}
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(s.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
				apiError(w, http.StatusForbidden, "csrf", "The request could not be verified. Reload the page.")
				return
			}
		}
		if s.Technician != nil {
			if !p.technicians {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this.")
				return
			}
			if p.feature != "" && !s.Can(p.feature) {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this.")
				return
			}
			if p.device != "" {
				if e := a.store.AuthorizeDevice(r.Context(), s, r.PathValue("id"), p.device); e != nil {
					if errors.Is(e, storage.ErrForbidden) {
						apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device or operation.")
					} else {
						apiError(w, http.StatusServiceUnavailable, "unavailable", "Authorization is temporarily unavailable.")
					}
					return
				}
			}
		}
		h(w, r, s)
	})
}

type sessionPermissions struct {
	Owner     bool `json:"owner"`
	Events    bool `json:"events"`
	Services  bool `json:"services"`
	Processes bool `json:"processes"`
	Desktop   bool `json:"desktop"`
	Files     bool `json:"files"`
	Response  bool `json:"response"`
}

type sessionInfo struct {
	Username    string             `json:"username"`
	Role        string             `json:"role"`
	CSRF        string             `json:"csrf"`
	ExpiresAt   int64              `json:"expires_at"`
	Permissions sessionPermissions `json:"permissions"`
}

func describeSession(s storage.Session) sessionInfo {
	out := sessionInfo{Username: s.Username, Role: "owner", CSRF: s.CSRF, ExpiresAt: s.ExpiresAt}
	out.Permissions = sessionPermissions{Owner: s.Technician == nil, Events: s.Can("events"), Services: s.Can("services"), Processes: s.Can("processes"), Desktop: s.Can("desktop"), Files: s.Can("files"), Response: s.Can("response")}
	if s.Technician != nil {
		out.Role = "technician"
	}
	return out
}

func registerAPI(mux *http.ServeMux, a *api) {
	mux.HandleFunc("GET /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		s, _, err := a.currentSession(r)
		if err != nil {
			if errors.Is(err, storage.ErrAuthentication) {
				apiError(w, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
			} else {
				apiError(w, http.StatusServiceUnavailable, "unavailable", "Sign-in is temporarily unavailable.")
			}
			return
		}
		writeJSON(w, http.StatusOK, describeSession(s))
	})
	mux.HandleFunc("POST /api/v1/session", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		signedIn, err := a.auth.Login(r.Context(), in.Username, in.Password, in.Code, peerKey(r))
		switch {
		case errors.Is(err, auth.ErrCredentials):
			apiError(w, http.StatusUnauthorized, "invalid_credentials", "Sign-in failed. Check your username, password and a fresh authenticator code.")
			return
		case errors.Is(err, auth.ErrLimited):
			w.Header().Set("Retry-After", "60")
			apiError(w, http.StatusTooManyRequests, "rate_limited", "Too many sign-in attempts. Try again in a minute.")
			return
		case err != nil:
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Sign-in is temporarily unavailable.")
			return
		}
		s, err := a.auth.Session(r.Context(), signedIn.Token)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Sign-in is temporarily unavailable.")
			return
		}
		http.SetCookie(w, cookie(sessionCookie, signedIn.Token, int((8*time.Hour).Seconds())))
		writeJSON(w, http.StatusOK, describeSession(s))
	})
	a.route(mux, "DELETE /api/v1/session", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		_, token, _ := a.currentSession(r)
		if err := a.auth.Logout(r.Context(), token); err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Sign-out is temporarily unavailable.")
			return
		}
		http.SetCookie(w, cookie(sessionCookie, "", -1))
		w.WriteHeader(http.StatusNoContent)
	})
	registerFleetAPI(mux, a)
	registerDeviceToolsAPI(mux, a)
	registerLiveToolsAPI(mux, a)
	registerScriptsAPI(mux, a)
	registerAlertsAPI(mux, a)
	registerOperationsAPI(mux, a)
	registerReportsAPI(mux, a)
	registerAdminAPI(mux, a)
	registerInstallerAPI(mux, a)
	registerServerUpdateAPI(mux, a)
	registerServerBackupAPI(mux, a)
	registerCasesAPI(mux, a)
	registerHuntsAPI(mux, a)
	registerIsolationAPI(mux, a)
	registerTriageAPI(mux, a)
	registerToolsAPI(mux, a)
}
