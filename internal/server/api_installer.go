package server

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentinstaller"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// Installer downloads. The owner downloads a ZIP holding the
// signed agent MSI and an enrollment file with a single-device token (24
// hours) or a reusable deployment token (device limit, expiry, revocable).
// Tokens never appear in URLs; the request body carries the choices.

// readInstallerCA returns the configured CA bundle; empty means system trust.
func readInstallerCA(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("installer CA unreadable")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(b) > 32768 {
		return "", errors.New("installer CA unreadable")
	}
	rest, certs := b, 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil || !c.IsCA {
			return "", errors.New("installer CA invalid")
		}
		certs++
	}
	if certs == 0 || strings.TrimSpace(string(rest)) != "" {
		return "", errors.New("installer CA invalid")
	}
	return string(b), nil
}

func validLabel(s string) bool {
	if len(s) > 80 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

func registerInstallerAPI(mux *http.ServeMux, a *api) {
	unavailable := func(w http.ResponseWriter) {
		apiError(w, http.StatusServiceUnavailable, "unavailable", "Installer downloads are temporarily unavailable.")
	}
	a.route(mux, "GET /api/v1/installer", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		if a.devices == nil {
			unavailable(w)
			return
		}
		settings, e1 := a.store.InstallerSettings(r.Context())
		tokens, e2 := a.store.DeploymentTokens(r.Context(), time.Now())
		release, e3 := a.store.LatestAgentRelease(r.Context(), time.Now())
		if errors.Join(e1, e2, e3) != nil {
			unavailable(w)
			return
		}
		type releaseView struct {
			Version  string `json:"version"`
			Sequence int64  `json:"sequence"`
			MSI      bool   `json:"msi"`
		}
		var rv *releaseView
		if release != nil {
			rv = &releaseView{release.Release.Manifest.Version, release.Release.Manifest.Sequence, agentupdate.MSI(release.Release.Manifest)}
		}
		trust := "system"
		if a.devices.InstallerCA != "" {
			trust = "ca"
		}
		writeJSON(w, http.StatusOK, struct {
			Settings   storage.InstallerSettings `json:"settings"`
			DevicePort int                       `json:"device_port"`
			Trust      string                    `json:"trust"`
			Release    *releaseView              `json:"release"`
			Tokens     []storage.EnrollmentToken `json:"tokens"`
		}{settings, a.devices.DevicePort, trust, rv, tokens})
	})

	a.route(mux, "PUT /api/v1/installer/settings", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in storage.InstallerSettings
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		server, ok1 := protocol.HTTPSOrigin(in.ServerURL)
		device, ok2 := protocol.HTTPSOrigin(in.DeviceURL)
		if !ok1 || !ok2 || server == device {
			apiError(w, http.StatusBadRequest, "invalid_request", "Enter two different HTTPS addresses such as https://rmm.example.com:8443, without a path.")
			return
		}
		v := storage.InstallerSettings{ServerURL: server, DeviceURL: device}
		if a.store.SetInstallerSettings(r.Context(), v, s.Actor(), time.Now()) != nil {
			unavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})

	a.route(mux, "POST /api/v1/installer/download", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		var in struct {
			Kind       string `json:"kind"`
			Label      string `json:"label"`
			MaxDevices int    `json:"max_devices"`
			Days       int    `json:"days"`
		}
		if !decodeJSON(w, r, &in, 4096) {
			return
		}
		request := devices.TokenRequest{Actor: s.Actor(), Label: in.Label}
		switch {
		case in.Kind == "single" && validLabel(in.Label) && in.MaxDevices == 0 && in.Days == 0:
		case in.Kind == "deployment" && validLabel(in.Label) && in.Label != "" && in.MaxDevices >= 1 && in.MaxDevices <= 10000 && in.Days >= 1 && in.Days <= 365:
			request.Reusable, request.MaxDevices, request.Lifetime = true, in.MaxDevices, time.Duration(in.Days)*24*time.Hour
		default:
			apiError(w, http.StatusBadRequest, "invalid_request", "Check the installer options: a deployment needs a name, 1 to 10,000 devices and 1 to 365 days.")
			return
		}
		if a.devices == nil {
			unavailable(w)
			return
		}
		settings, err := a.store.InstallerSettings(r.Context())
		if err != nil {
			unavailable(w)
			return
		}
		if settings.ServerURL == "" || settings.DeviceURL == "" {
			apiError(w, http.StatusConflict, "settings", "Save the server addresses agents use before downloading an installer.")
			return
		}
		ca, err := readInstallerCA(a.devices.InstallerCA)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, "unavailable", "The server's TLS CA file is unreadable or invalid; check OPENRMM_SERVER_TLS_CA.")
			return
		}
		release, msi, err := a.store.InstallerRelease(r.Context(), time.Now())
		if err != nil {
			unavailable(w)
			return
		}
		if release == nil {
			apiError(w, http.StatusConflict, "release", "No current signed agent MSI release is available. Publish an agent release first.")
			return
		}
		defer msi.Close()
		token, _, err := a.devices.CreateToken(r.Context(), request)
		if errors.Is(err, storage.ErrEnrollmentToken) {
			apiError(w, http.StatusConflict, "limit", "Too many unused installers or active deployments. Revoke a deployment or wait for unused installers to expire.")
			return
		}
		if err != nil {
			unavailable(w)
			return
		}
		name := "OpenRMM-Agent-Setup.zip"
		if request.Reusable {
			name = "OpenRMM-Agent-Deployment.zip"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		enrollment := protocol.EnrollmentFile{Version: 1, ServerURL: settings.ServerURL, DeviceURL: settings.DeviceURL, ServerCA: ca, Token: token}
		transferDeadline(w, artifactTransferTime)
		// Headers are sent; a failure now only truncates the download, which
		// install.ps1 detects. The token expires or can be revoked.
		_ = agentinstaller.Write(w, msi, release.Release.Manifest.Size, release.Release, enrollment, time.Now())
	})

	a.route(mux, "POST /api/v1/installer/tokens/{token}/revoke", ownerOnly, func(w http.ResponseWriter, r *http.Request, s storage.Session) {
		err := a.store.RevokeDeploymentToken(r.Context(), r.PathValue("token"), s.Actor(), time.Now())
		if errors.Is(err, storage.ErrEnrollmentToken) {
			apiError(w, http.StatusNotFound, "not_found", "This deployment was already revoked or no longer exists.")
			return
		}
		if err != nil {
			unavailable(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
