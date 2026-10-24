package server

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// The dashboard shows a newer signed release, hands it to the
// updater as a request, refuses a second one and releases it cannot verify,
// and records the updater's outcome.
func TestServerUpdateAPI(t *testing.T) {
	base := newAPIFixture(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	updates := &serverUpdates{dir: dir, current: serverupdate.Current{Version: "1.0.0", Sequence: 10, Keys: []string{hex.EncodeToString(pub)}}}
	s := httptest.NewTLSServer(handler(base.store, base.auth, base.devices, updates))
	t.Cleanup(s.Close)
	client := s.Client()
	client.Jar, _ = cookiejar.New(nil)
	f := &apiFixture{server: s, client: client, store: base.store, devices: base.devices, auth: base.auth, secret: base.secret, recovery: base.recovery}
	f.login(t)

	now := time.Now()
	release := func(seq int64, key ed25519.PrivateKey) string {
		m := serverupdate.Manifest{Product: serverupdate.Product, Version: "1.1.0", Sequence: seq, Image: "ghcr.io/example/openrmm-server",
			ImageID: "sha256:" + strings.Repeat("2", 64), Notes: "Fixes the thing.", KeyID: agentupdate.Digest(key.Public().(ed25519.PublicKey)),
			Issued: now.Add(-time.Hour).Unix(), Expires: now.Add(24 * time.Hour).Unix()}
		b, _ := json.Marshal(serverupdate.Sign(key, m))
		return string(b)
	}
	type view struct {
		Current   serverupdate.Current `json:"current"`
		Available *struct {
			Version  string `json:"version"`
			Sequence int64  `json:"sequence"`
			Notes    string `json:"notes"`
		} `json:"available"`
		Updater *struct {
			Phase string `json:"phase"`
		} `json:"updater"`
		CheckEnabled bool                   `json:"check_enabled"`
		Configured   bool                   `json:"repository_configured"`
		History      []storage.ServerUpdate `json:"history"`
	}
	get := func() view {
		resp, body := f.do(t, "GET", "/api/v1/server/update", nil, false)
		var v view
		if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil {
			t.Fatal(resp.StatusCode, string(body))
		}
		return v
	}
	install := func(seq int64) int {
		resp, _ := f.do(t, "POST", "/api/v1/server/update/install", map[string]int64{"sequence": seq}, true)
		return resp.StatusCode
	}

	// A release signed by another key is never offered.
	_, other, _ := ed25519.GenerateKey(nil)
	base.store.RecordServerUpdateCheck(t.Context(), release(11, other), "", now)
	if v := get(); v.Available != nil || !v.CheckEnabled || !v.Configured || v.Current.Sequence != 10 || v.Updater != nil {
		t.Fatalf("%+v", v)
	}
	base.store.RecordServerUpdateCheck(t.Context(), release(11, priv), "", now)
	if v := get(); v.Available == nil || v.Available.Sequence != 11 || v.Available.Notes != "Fixes the thing." {
		t.Fatalf("%+v", v)
	}
	// Without an updater the request is refused.
	if status := install(11); status != http.StatusConflict {
		t.Fatal("installed without an updater", status)
	}
	// A status from long ago is no updater; a fresh heartbeat is.
	os.WriteFile(filepath.Join(dir, serverupdate.StatusFile), []byte(`{"id":"","phase":"idle","version":"","sequence":0,"updated_at":1,"updater":1}`), 0600)
	if status := install(11); status != http.StatusConflict {
		t.Fatal("installed with a stopped updater", status)
	}
	idle, _ := json.Marshal(serverupdate.Status{Phase: "idle", UpdatedAt: now.Unix(), Alive: now.Unix(), Updater: 1})
	os.WriteFile(filepath.Join(dir, serverupdate.StatusFile), idle, 0600)
	if status := install(12); status != http.StatusConflict {
		t.Fatal("unknown release installed", status)
	}
	if status := install(11); status != http.StatusAccepted {
		t.Fatal("install", status)
	}
	var req serverupdate.Request
	raw, err := os.ReadFile(filepath.Join(dir, serverupdate.RequestFile))
	if err != nil || json.Unmarshal(raw, &req) != nil || req.Release.Manifest.Sequence != 11 || req.RequestedBy != "admin" {
		t.Fatal("request", string(raw), err)
	}
	if status := install(11); status != http.StatusConflict {
		t.Fatal("second install accepted", status)
	}
	// The updater's outcome reaches the history.
	os.Remove(filepath.Join(dir, serverupdate.RequestFile))
	st := serverupdate.Status{ID: req.ID, Phase: serverupdate.PhaseRolledBack, Version: "1.1.0", Sequence: 11, Detail: "The new version did not become healthy.", Backup: "update-x", UpdatedAt: now.Unix(), Updater: 1}
	b, _ := json.Marshal(st)
	os.WriteFile(filepath.Join(dir, serverupdate.StatusFile), b, 0600)
	if s, ok := updates.status(); !ok || base.store.ApplyServerUpdateStatus(t.Context(), s.ID, s.Phase, s.Detail, s.Backup, serverupdate.Done(s.Phase), now) != nil {
		t.Fatal("status")
	}
	v := get()
	if len(v.History) != 1 || v.History[0].Phase != "rolled_back" || v.History[0].FromVersion != "1.0.0" || v.Updater == nil || v.Updater.Phase != "rolled_back" {
		t.Fatalf("%+v", v)
	}
	// Turning the check off is stored; technicians cannot see updates.
	if resp, _ := f.do(t, "PUT", "/api/v1/server/update/settings", map[string]bool{"check_enabled": false}, true); resp.StatusCode != 200 || get().CheckEnabled {
		t.Fatal("settings")
	}
	tech := f.technicianClient(t, storage.TechnicianAccess{})
	if resp, _ := tech.do(t, "GET", "/api/v1/server/update", nil, false); resp.StatusCode != http.StatusForbidden {
		t.Fatal("technician", resp.StatusCode)
	}
}
