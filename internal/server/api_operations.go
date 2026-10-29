package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/applications"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/patching"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Fleet change operations (patch policies, application deployments, agent
// rollouts) follow the same rule: review resolves exact targets and returns a
// digest; apply must quote that digest, so nothing changes between what was
// confirmed and what runs.

// One release upload at a time: each spools up to 32 MiB to private storage.
var agentReleaseSlots = make(chan struct{}, 1)

type target struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

func needDigest(w http.ResponseWriter, op, digest string) (string, bool) {
	if op != "apply" {
		return "", true
	}
	if len(digest) != 64 {
		apiError(w, http.StatusConflict, "refused", "Review this change again before confirming it.")
		return "", false
	}
	return digest, true
}

func registerOperationsAPI(mux *http.ServeMux, a *api) {
	refused := func(w http.ResponseWriter, msg string) { apiError(w, http.StatusConflict, "refused", msg) }

	// Patch policies (owner-only).
	a.route(mux, "GET /api/v1/patch-policies", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		policies, e1 := a.store.PatchPolicies(r.Context())
		runs, e2 := a.store.PatchRuns(r.Context())
		guards, e3 := a.store.PatchGuards(r.Context())
		if errors.Join(e1, e2, e3) != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Patching is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Policies []storage.PatchPolicy `json:"policies"`
			Runs     []storage.PatchRun    `json:"runs"`
			Guards   []storage.PatchGuard  `json:"guards"`
		}{policies, runs, guards})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/patch-policies/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Action     string              `json:"action"`
				ID         string              `json:"id"`
				Revision   int64               `json:"revision"`
				Enabled    bool                `json:"enabled"`
				Definition patching.Definition `json:"definition"`
				Groups     []string            `json:"groups"`
				Digest     string              `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 16384) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			in.Definition.Name, in.Definition.Ring = strings.TrimSpace(in.Definition.Name), strings.TrimSpace(in.Definition.Ring)
			c := storage.PatchChange{Action: in.Action, ID: in.ID, Revision: in.Revision, Enabled: in.Enabled, Definition: in.Definition, Groups: in.Groups}
			now := time.Now()
			review, e := a.store.ChangePatchPolicy(r.Context(), c, s.Actor(), "", now)
			if e != nil {
				refused(w, "This policy can't be saved: check the name, 1–25 Windows devices not already in another active policy, a 30–240 minute window, and KB numbers when installing. It may also have changed since you loaded it.")
				return
			}
			if op == "apply" {
				if review.Digest != digest {
					refused(w, "The policy or its devices changed since your review. Review it again.")
					return
				}
				if _, e = a.store.ChangePatchPolicy(r.Context(), c, s.Actor(), digest, now); e != nil {
					refused(w, "The policy changed while saving. Review it again.")
					return
				}
			}
			targets := []target{}
			for _, t := range review.Targets {
				targets = append(targets, target{t.ID, t.Hostname})
			}
			writeJSON(w, http.StatusOK, struct {
				Policy  storage.PatchPolicy `json:"policy"`
				Targets []target            `json:"targets"`
				Digest  string              `json:"digest"`
			}{review.Policy, targets, review.Digest})
		})
		// Device holds after an uncertain or failed patch run: acknowledge
		// (allow automation again) or defer a pending restart.
		a.route(mux, "POST /api/v1/patch-guards/{device}/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Action   string `json:"action"`
				Revision int64  `json:"revision"`
				Until    int64  `json:"until"`
				Digest   string `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 1024) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			now := time.Now()
			g, review, e := a.store.ChangePatchGuard(r.Context(), r.PathValue("device"), in.Action, in.Revision, in.Until, s.Actor(), "", now)
			if e != nil {
				refused(w, "This hold changed or the request is invalid (deferrals are limited to 7 days and not available once a restart was requested).")
				return
			}
			if op == "apply" {
				if review != digest {
					refused(w, "The hold changed since your review. Review it again.")
					return
				}
				if g, _, e = a.store.ChangePatchGuard(r.Context(), r.PathValue("device"), in.Action, in.Revision, in.Until, s.Actor(), digest, now); e != nil {
					refused(w, "The hold changed while saving. Review it again.")
					return
				}
			}
			writeJSON(w, http.StatusOK, struct {
				Guard  storage.PatchGuard `json:"guard"`
				Digest string             `json:"digest"`
			}{g, review})
		})
	}

	// Application catalog (owner-only) and deployments.
	a.route(mux, "GET /api/v1/applications", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		c, e := a.store.ApplicationCatalog(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The application catalog is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Revision int64                        `json:"revision"`
			Versions []storage.ApplicationVersion `json:"versions"`
		}{c.Revision, c.Versions})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/applications/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				ID            string                  `json:"id"`
				ApplicationID string                  `json:"application_id"`
				Revision      int64                   `json:"revision"`
				Definition    applications.Definition `json:"definition"`
				Digest        string                  `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 8192) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			d := in.Definition
			d.ProductCode, d.SHA256 = strings.ToUpper(strings.TrimSpace(d.ProductCode)), strings.ToLower(strings.TrimSpace(d.SHA256))
			v, review, e := a.store.ChangeApplication(r.Context(), storage.ApplicationChange{ID: in.ID, ApplicationID: in.ApplicationID, Revision: in.Revision, Definition: d}, s.Actor(), digest, time.Now())
			if e != nil {
				refused(w, "This package version can't be saved. Use an HTTPS .msi URL without credentials or query, its SHA-256, the MSI product code ({GUID}) and a three-part version (x.y.z); the version and product code must not already be in the catalog. The catalog may also have changed — reload and review again.")
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Version storage.ApplicationVersion `json:"version"`
				Digest  string                     `json:"digest"`
			}{v, review})
		})
		a.route(mux, "POST /api/v1/deployments/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Change storage.DeploymentChange `json:"change"`
				Digest string                   `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 16384) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			if in.Change.Devices == nil {
				in.Change.Devices = []string{}
			}
			if in.Change.Groups == nil {
				in.Change.Groups = []string{}
			}
			review, e := a.store.DeployApplication(r.Context(), in.Change, s.Actor(), digest, time.Now(), a.offlineAfter())
			if e != nil {
				refused(w, "This deployment can't go ahead. Every target must be online with scripts turned on, and no other deployment may be pending. The review may also be out of date.")
				return
			}
			targets := []target{}
			for _, t := range review.Targets {
				targets = append(targets, target{t.ID, t.Hostname})
			}
			writeJSON(w, http.StatusOK, struct {
				Version  storage.ApplicationVersion  `json:"version"`
				Previous *storage.ApplicationVersion `json:"previous"`
				Targets  []target                    `json:"targets"`
				Digest   string                      `json:"digest"`
			}{review.Version, review.Previous, targets, review.Digest})
		})
	}
	a.route(mux, "GET /api/v1/deployments", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		device := r.URL.Query().Get("device")
		if device != "" {
			if !protocol.ValidID(device) {
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid device.")
				return
			}
			if e := a.store.AuthorizeDevice(r.Context(), s, device, "read"); e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		rows, e := a.store.ApplicationDeployments(r.Context(), s, device, time.Now())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Deployments are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Deployments []storage.ApplicationDeployment `json:"deployments"`
		}{rows})
	})
	a.route(mux, "POST /api/v1/deployments/{deployment}/cancel", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.CancelApplicationDeployment(r.Context(), r.PathValue("deployment"), s.Actor(), time.Now()); e != nil {
			refused(w, "This deployment can no longer be cancelled. Refresh its status.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Agent releases (owner-only) and rollouts.
	a.route(mux, "GET /api/v1/agent-releases", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		items, _, e := a.store.AgentReleases(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Agent releases are temporarily unavailable.")
			return
		}
		// The release built with this server, and whether the library has
		// it: a refused import is otherwise only a log line.
		type bundledView struct {
			Version   string `json:"version"`
			Sequence  int64  `json:"sequence"`
			InLibrary bool   `json:"in_library"`
		}
		var bundled *bundledView
		if rel, ok := bundledRelease(); ok {
			bundled = &bundledView{Version: rel.Manifest.Version, Sequence: rel.Manifest.Sequence}
			id := agentupdate.ReleaseID(rel)
			for _, item := range items {
				bundled.InLibrary = bundled.InLibrary || item.ID == id
			}
		}
		writeJSON(w, http.StatusOK, struct {
			Releases []storage.AgentRelease `json:"releases"`
			Bundled  *bundledView           `json:"bundled"`
		}{items, bundled})
	})
	// Upload: signed manifest, public key, then the executable. The signature
	// and validity are checked before the binary is spooled to private storage.
	a.route(mux, "POST /api/v1/agent-releases", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		select {
		case agentReleaseSlots <- struct{}{}:
			defer func() { <-agentReleaseSlots }()
		default:
			w.Header().Set("Retry-After", "10")
			apiError(w, http.StatusTooManyRequests, "busy", "Another release is uploading. Try again shortly.")
			return
		}
		transferDeadline(w, artifactTransferTime)
		r.Body = http.MaxBytesReader(w, r.Body, agentupdate.MaxArtifact+65536)
		reader, e := r.MultipartReader()
		if e != nil {
			apiError(w, http.StatusBadRequest, "invalid_request", "Send the release as a multipart upload.")
			return
		}
		values := map[string][]byte{}
		for _, name := range []string{"manifest", "public"} {
			part, e := reader.NextPart()
			if e != nil || part.FormName() != name {
				apiError(w, http.StatusBadRequest, "invalid_request", "Send the signed manifest, then the public key, then the executable.")
				return
			}
			raw, e := io.ReadAll(io.LimitReader(part, 16385))
			part.Close()
			if e != nil || len(raw) > 16384 {
				apiError(w, http.StatusBadRequest, "invalid_request", "The manifest or key is too large.")
				return
			}
			values[name] = raw
		}
		var release protocol.SignedAgentRelease
		public := strings.TrimSpace(string(values["public"]))
		if agentupdate.Decode(values["manifest"], &release) != nil || !agentupdate.Verify(release, public) || !agentupdate.Fresh(release.Manifest, time.Now()) {
			apiError(w, http.StatusBadRequest, "invalid_request", "The signature, manifest or validity period is not valid for this public key.")
			return
		}
		part, e := reader.NextPart()
		if e != nil || part.FormName() != "binary" {
			apiError(w, http.StatusBadRequest, "invalid_request", "The agent executable is missing.")
			return
		}
		defer part.Close()
		f, e := a.store.NewAgentReleaseTemp()
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Release storage is unavailable.")
			return
		}
		defer os.Remove(f.Name())
		defer f.Close()
		e = storage.SpoolAgentRelease(f, part)
		if closeErr := f.Close(); e == nil {
			e = closeErr
		}
		if e == nil {
			if _, next := reader.NextPart(); next != io.EOF {
				e = agentupdate.ErrInvalid
			}
		}
		if e == nil {
			e = a.store.AddAgentRelease(r.Context(), release, public, f.Name(), s.Actor(), time.Now())
		}
		if e != nil {
			refused(w, "Release rejected. The executable must match the signed hash and size, be a Windows x64 program, and use a key and sequence number not already in the library.")
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	a.route(mux, "POST /api/v1/agent-releases/{release}/withdraw", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.WithdrawAgentRelease(r.Context(), r.PathValue("release"), s.Actor(), time.Now()); e != nil {
			refused(w, "This release can't be withdrawn while an update using it is in progress.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Fleet status: which devices run the latest usable release, and why the
	// others can or cannot be updated from here.
	a.route(mux, "GET /api/v1/agent-fleet", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		fleet, e := a.store.AgentFleet(r.Context(), time.Now(), a.offlineAfter())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Agent fleet status is temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, fleet)
	})
	// Automatic rollouts in rings (owner-only).
	a.route(mux, "GET /api/v1/agent-rings", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		p, e := a.store.AgentRingPolicy(r.Context())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Automatic update settings are temporarily unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	a.route(mux, "POST /api/v1/agent-rings", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in storage.AgentRingChange
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		if in.PilotGroups == nil {
			in.PilotGroups = []string{}
		}
		p, e := a.store.ChangeAgentRingPolicy(r.Context(), in, s.Actor(), time.Now())
		if e != nil {
			refused(w, "These settings can't be saved. Choose up to 10 existing pilot groups and a delay of 1 to 720 hours. The settings may also have changed — reload and try again.")
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	a.route(mux, "GET /api/v1/agent-upgrades", anyAccount, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		device := r.URL.Query().Get("device")
		if device != "" {
			if !protocol.ValidID(device) {
				apiError(w, http.StatusBadRequest, "invalid_request", "Invalid device.")
				return
			}
			if e := a.store.AuthorizeDevice(r.Context(), s, device, "read"); e != nil {
				apiError(w, http.StatusForbidden, "forbidden", "Your account does not have access to this device.")
				return
			}
		}
		jobs, e := a.store.AgentUpgradeJobs(r.Context(), s, device, time.Now())
		if e != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "Agent updates are temporarily unavailable.")
			return
		}
		var support *storage.AgentUpgradeSupport
		if device != "" {
			v, e := a.store.AgentUpgradeSupport(r.Context(), device)
			if e == nil {
				support = &v
			}
		}
		writeJSON(w, http.StatusOK, struct {
			Jobs    []storage.AgentUpgradeJob    `json:"jobs"`
			Support *storage.AgentUpgradeSupport `json:"support"`
		}{jobs, support})
	})
	for _, op := range []string{"review", "apply"} {
		a.route(mux, "POST /api/v1/agent-rollouts/"+op, ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
			var in struct {
				Change storage.AgentRolloutChange `json:"change"`
				Digest string                     `json:"digest"`
			}
			if !decodeJSON(w, r, &in, 16384) {
				return
			}
			digest, ok := needDigest(w, op, in.Digest)
			if !ok {
				return
			}
			if in.Change.Devices == nil {
				in.Change.Devices = []string{}
			}
			if in.Change.Groups == nil {
				in.Change.Groups = []string{}
			}
			review, e := a.store.QueueAgentRollout(r.Context(), in.Change, s.Actor(), digest, time.Now(), a.offlineAfter())
			if e != nil {
				refused(w, "This rollout can't go ahead. Every target needs the agent updater enabled and recently reporting, this release's signing key pinned locally, a newer sequence than it has installed, and no update already pending. The review may also be out of date.")
				return
			}
			type rolloutTarget struct {
				ID          string `json:"id"`
				Hostname    string `json:"hostname"`
				CurrentHash string `json:"current_sha256"`
				HighWater   int64  `json:"high_water"`
			}
			targets := []rolloutTarget{}
			for _, t := range review.Targets {
				targets = append(targets, rolloutTarget{t.ID, t.Hostname, t.CurrentHash, t.HighWater})
			}
			writeJSON(w, http.StatusOK, struct {
				Release storage.AgentRelease `json:"release"`
				Targets []rolloutTarget      `json:"targets"`
				Digest  string               `json:"digest"`
			}{review.Release, targets, review.Digest})
		})
	}
	a.route(mux, "POST /api/v1/agent-upgrades/{job}/cancel", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if e := a.store.CancelAgentUpgrade(r.Context(), r.PathValue("job"), s.Actor(), time.Now()); e != nil {
			refused(w, "Only updates that are still queued can be cancelled.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
