package server

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Administration: groups, monitoring policies and device organization, and
// technician accounts (owner-only), plus the unauthenticated technician
// activation that an invitation link opens.

type organizedDevice struct {
	storage.OrganizedDevice
	Source string `json:"policy_source"`
}

type policyImpact struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	Before   string   `json:"before"`
	After    string   `json:"after"`
	Kinds    []string `json:"kinds"`
	Features []string `json:"features"`
}

func registerAdminAPI(mux *http.ServeMux, a *api) {
	a.route(mux, "GET /api/v1/organization", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		o, e := a.store.Organization(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Groups and policies are temporarily unavailable.")
			return
		}
		list := []organizedDevice{}
		for _, d := range o.Devices {
			if d.Tags == nil {
				d.Tags = []string{}
			}
			_, source := o.Effective(d)
			list = append(list, organizedDevice{d, source})
		}
		writeJSON(w, http.StatusOK, struct {
			Revision int64                      `json:"revision"`
			Groups   []storage.DeviceGroup      `json:"groups"`
			Policies []storage.MonitoringPolicy `json:"policies"`
			Defaults []alerting.Rule            `json:"defaults"`
			Devices  []organizedDevice          `json:"devices"`
			MaxBulk  int                        `json:"max_bulk"`
		}{o.Revision, o.Groups, o.Policies, o.Defaults, list, storage.MaxBulkDevices})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/organization/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Change storage.OrganizationChange `json:"change"`
				Digest string                     `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 65536) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			if in.Change.Tags == nil {
				in.Change.Tags = []string{}
			}
			review, e := a.store.ChangeOrganization(r.Context(), in.Change, s.Actor(), digest, time.Now())
			if e != nil {
				apiError(w, http.StatusConflict, "refused", "This change can't be saved. Check names and IDs (lowercase letters, digits, - or _), tags (up to 16 per device) and rule values. Groups and policies must be unused before deletion, including technician group grants. Someone may also have changed the organization — review again.")
				return
			}
			impacts := []policyImpact{}
			for _, v := range review.Impacts {
				impacts = append(impacts, policyImpact{v.ID, v.Hostname, v.Before, v.After, v.Kinds, v.Features})
			}
			writeJSON(w, http.StatusOK, struct {
				Digest  string         `json:"digest"`
				Impacts []policyImpact `json:"impacts"`
			}{review.Digest, impacts})
		})
	}

	a.route(mux, "GET /api/v1/technicians", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		rows, e := a.store.Technicians(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Technician accounts are temporarily unavailable.")
			return
		}
		type technician struct {
			storage.Technician
			Pending bool `json:"pending_activation"`
		}
		list := []technician{}
		now := time.Now().Unix()
		for _, t := range rows {
			list = append(list, technician{t, !t.Confirmed && t.InvitationUntil != nil && *t.InvitationUntil > now})
		}
		writeJSON(w, http.StatusOK, struct {
			Technicians []technician `json:"technicians"`
		}{list})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/technicians/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Change struct {
					Action   string                   `json:"action"`
					ID       string                   `json:"id"`
					Username string                   `json:"username"`
					Revision int64                    `json:"revision"`
					Enabled  bool                     `json:"enabled"`
					Access   storage.TechnicianAccess `json:"access"`
				} `json:"change"`
				Digest string `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 16384) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			c := storage.TechnicianChange{Action: in.Change.Action, ID: in.Change.ID, Username: in.Change.Username, Revision: in.Change.Revision, Enabled: in.Change.Enabled, Access: in.Change.Access}
			if c.Access.Devices == nil {
				c.Access.Devices = []string{}
			}
			if c.Access.Groups == nil {
				c.Access.Groups = []string{}
			}
			var invitation string
			var e error
			if op == "review" {
				digest, e = a.auth.ReviewTechnician(r.Context(), c, s.Actor())
			} else {
				invitation, e = a.auth.ApplyTechnician(r.Context(), c, s.Actor(), digest)
			}
			if e != nil {
				apiError(w, http.StatusConflict, "refused", "This account change can't be saved. Usernames must be unique (and not the owner's), and the access scope must reference existing devices and groups. The account may also have changed — review again.")
				return
			}
			if op == "apply" {
				digest = ""
			}
			// The invitation is shown once; only its hash is stored.
			writeJSON(w, http.StatusOK, struct {
				Digest     string `json:"digest,omitempty"`
				Invitation string `json:"invitation,omitempty"`
			}{digest, invitation})
		})
	}

	// Activation runs without a session: the invitation (then the one-time
	// confirmation) is the credential. Requests are throttled per peer.
	activationError := func(w http.ResponseWriter, e error) {
		if errors.Is(e, auth.ErrLimited) {
			w.Header().Set("Retry-After", "60")
			apiError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again in a minute.")
			return
		}
		apiError(w, http.StatusBadRequest, "activation_failed", "Activation failed. Check the invitation link, use a password of at least 15 characters, and enter a fresh authenticator code. Invitations expire after 30 minutes; ask your administrator for a new one.")
	}
	peer := func(r *http.Request) string {
		p, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			return "unknown"
		}
		return p
	}
	// First-administrator setup link: the link (in the URL
	// fragment, never in logs) creates the administrator in two steps.
	setupError := func(w http.ResponseWriter, e error) {
		switch {
		case errors.Is(e, auth.ErrLimited):
			w.Header().Set("Retry-After", "60")
			apiError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again in a minute.")
		case errors.Is(e, storage.ErrSetupLink):
			apiError(w, http.StatusBadRequest, "setup_link", "This setup link is not valid (it works for one hour, once, until an administrator exists). Run the install command again for a new link.")
		case errors.Is(e, auth.ErrCredentials):
			apiError(w, http.StatusBadRequest, "code", "The authenticator code is not valid. Check the time on your phone and use a fresh code.")
		default:
			apiError(w, http.StatusBadRequest, "invalid_request", "Use a username of 3 to 64 lowercase letters, numbers, dots, underscores or hyphens and a password of at least 15 characters.")
		}
	}
	setupPeer := func(r *http.Request) string {
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return "unknown"
		}
		return peer
	}
	mux.HandleFunc("GET /api/v1/setup", func(w http.ResponseWriter, r *http.Request) {
		done, e := a.store.AdministratorConfirmed(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Setup is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Needed bool `json:"needed"`
		}{!done})
	})
	mux.HandleFunc("POST /api/v1/setup/begin", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Link     string `json:"link"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		p, e := a.auth.SetupWithLink(r.Context(), in.Link, in.Username, in.Password, setupPeer(r))
		if e != nil {
			setupError(w, e)
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("POST /api/v1/setup/confirm", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Link string `json:"link"`
			Code string `json:"code"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		if e := a.auth.ConfirmWithLink(r.Context(), in.Link, in.Code, setupPeer(r)); e != nil {
			setupError(w, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/activation/begin", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Invitation string `json:"invitation"`
			Password   string `json:"password"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		p, e := a.auth.BeginTechnician(r.Context(), in.Invitation, in.Password, peer(r))
		if e != nil {
			activationError(w, e)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			auth.Provisioning
			Confirmation string `json:"confirmation"`
		}{p.Provisioning, p.Confirmation})
	})
	mux.HandleFunc("POST /api/v1/activation/confirm", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Confirmation string `json:"confirmation"`
			Code         string `json:"code"`
		}
		if !decodeJSON(w, r, &in, 1024) {
			return
		}
		if e := a.auth.ConfirmTechnician(r.Context(), in.Confirmation, in.Code, peer(r)); e != nil {
			activationError(w, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
