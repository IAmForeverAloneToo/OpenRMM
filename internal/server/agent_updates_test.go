package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentbundle"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func readResponse(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func signedRelease(t *testing.T, artifact []byte, sequence int64) (protocol.SignedAgentRelease, string) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	m := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.2", Sequence: sequence, Size: int64(len(artifact)), Hash: agentupdate.Digest(artifact), KeyID: agentupdate.Digest(public), Issued: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix()}
	return protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, agentupdate.Message(m)))}, hex.EncodeToString(public)
}

func (f *apiFixture) uploadRelease(t *testing.T, release protocol.SignedAgentRelease, public string, artifact []byte) (int, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	raw, _ := json.Marshal(release)
	_ = w.WriteField("manifest", string(raw))
	_ = w.WriteField("public", public)
	part, _ := w.CreateFormFile("binary", "agent.exe")
	_, _ = part.Write(artifact)
	w.Close()
	req, _ := http.NewRequest("POST", f.server.URL+"/api/v1/agent-releases", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-CSRF-Token", f.csrf)
	r, e := f.client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	return r.StatusCode, readResponse(t, r)
}

func TestAgentReleaseAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	ctx := context.Background()
	artifact := agentUpdatePEFixture()
	release, public := signedRelease(t, artifact, 2)

	tampered := release
	tampered.Manifest.Sequence++
	if status, body := f.uploadRelease(t, tampered, public, artifact); status != 400 {
		t.Fatal("signature", status, body)
	}
	bad := append([]byte{}, artifact...)
	bad[len(bad)-1]++
	if status, body := f.uploadRelease(t, release, public, bad); status != 409 {
		t.Fatal("artifact digest", status, body)
	}
	saved := f.csrf
	f.csrf = "wrong"
	if status, _ := f.uploadRelease(t, release, public, artifact); status != 403 {
		t.Fatal("csrf", status)
	}
	f.csrf = saved
	if status, body := f.uploadRelease(t, release, public, artifact); status != 201 {
		t.Fatal("upload", status, body)
	}
	if status, _ := f.uploadRelease(t, release, public, artifact); status != 409 {
		t.Fatal("duplicate release", status)
	}
	id := agentupdate.ReleaseID(release)
	if resp, body := f.do(t, "GET", "/api/v1/agent-releases", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), id) {
		t.Fatalf("releases: %d %s", resp.StatusCode, body)
	}

	now := time.Now()
	d := storage.Device{ID: strings.Repeat("a", 32), Hostname: "updater <device>", OS: "windows", Architecture: "amd64", Certificate: "public", Fingerprint: "fp"}
	if e := f.store.NewEnrollmentToken(ctx, "upgrade-token", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := f.store.EnrollDevice(ctx, "upgrade-token", d, now); e != nil {
		t.Fatal(e)
	}
	if e := f.store.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: d.OS, Architecture: d.Architecture, AgentVersion: "test.1"}, now); e != nil {
		t.Fatal(e)
	}
	support, _ := json.Marshal(protocol.AgentUpgradeSupport{Broker: "enabled", CurrentHash: strings.Repeat("c", 64), KeyIDs: []string{release.Manifest.KeyID}})
	if e := f.store.RecordAgentUpgradeSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: agentupdate.Capability, Status: "ok", Data: support}, now); e != nil {
		t.Fatal(e)
	}
	fleetStatus := func(device string) string {
		t.Helper()
		resp, body := f.do(t, "GET", "/api/v1/agent-fleet", nil, false)
		var fleet storage.AgentFleet
		if resp.StatusCode != 200 || json.Unmarshal(body, &fleet) != nil || fleet.Latest == nil || fleet.Latest.ID != id {
			t.Fatalf("fleet: %d %s", resp.StatusCode, body)
		}
		for _, v := range fleet.Devices {
			if v.ID == device {
				return v.Status
			}
		}
		return ""
	}
	if got := fleetStatus(d.ID); got != storage.FleetAvailable {
		t.Fatal("eligible device not offered the update", got)
	}
	silent := f.enroll(t, "WS-NO-UPDATER")
	if got := fleetStatus(silent); got != storage.FleetUnknown && got != storage.FleetOffline {
		t.Fatal("device without an updater report shown as updatable", got)
	}
	change := map[string]any{"id": strings.Repeat("e", 32), "release_id": id, "devices": []string{d.ID}}
	resp, body := f.do(t, "POST", "/api/v1/agent-rollouts/review", map[string]any{"change": change}, true)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"high_water":0`) || !strings.Contains(string(body), d.ID) {
		t.Fatalf("rollout review: %d %s", resp.StatusCode, body)
	}
	var review struct {
		Digest string `json:"digest"`
	}
	_ = json.Unmarshal(body, &review)
	changed := map[string]any{"id": strings.Repeat("e", 32), "release_id": id, "devices": []string{strings.Repeat("b", 32)}}
	if resp, _ := f.do(t, "POST", "/api/v1/agent-rollouts/apply", map[string]any{"change": changed, "digest": review.Digest}, true); resp.StatusCode != 409 {
		t.Fatal("target changed after review", resp.StatusCode)
	}
	for range 2 { // applying the same review twice is idempotent
		if resp, body := f.do(t, "POST", "/api/v1/agent-rollouts/apply", map[string]any{"change": change, "digest": review.Digest}, true); resp.StatusCode != 200 {
			t.Fatalf("rollout apply: %d %s", resp.StatusCode, body)
		}
	}
	if got := fleetStatus(d.ID); got != storage.FleetUpdating {
		t.Fatal("queued update not shown", got)
	}
	resp, body = f.do(t, "GET", "/api/v1/agent-upgrades?device="+d.ID, nil, false)
	var jobs struct {
		Jobs []storage.AgentUpgradeJob `json:"jobs"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &jobs) != nil || len(jobs.Jobs) != 1 || jobs.Jobs[0].Status != "queued" || !strings.Contains(string(body), `"support":{`) {
		t.Fatalf("jobs: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/agent-upgrades/"+jobs.Jobs[0].ID+"/cancel", nil, true); resp.StatusCode != 204 {
		t.Fatal("cancel", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/agent-releases/"+id+"/withdraw", nil, true); resp.StatusCode != 204 {
		t.Fatal("withdraw", resp.StatusCode)
	}
	if resp, body := f.do(t, "GET", "/api/v1/agent-releases", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"withdrawn":true`) {
		t.Fatalf("withdrawn release: %d %s", resp.StatusCode, body)
	}
}

func agentUpdatePEFixture() []byte {
	// Minimal inert PE header: parsed as Windows AMD64, never launched.
	artifact := make([]byte, 64+4+20+240)
	copy(artifact, "MZ")
	binary.LittleEndian.PutUint32(artifact[60:], 64)
	copy(artifact[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(artifact[68:], 0x8664)
	binary.LittleEndian.PutUint16(artifact[84:], 240)
	binary.LittleEndian.PutUint16(artifact[86:], 2)
	binary.LittleEndian.PutUint16(artifact[88:], 0x20b)
	binary.LittleEndian.PutUint32(artifact[88+108:], 16)
	return artifact
}

func TestAgentUpdateMTLSArtifactBoundToOneDispatchedDevice(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, e := storage.Open(ctx, filepath.Join(root, "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	now := time.Now()
	if e = store.SetAdministrator(ctx, storage.Administrator{Username: "admin", PasswordHash: "test", TOTPCipher: []byte("test")}, nil, false, now); e != nil {
		t.Fatal(e)
	}
	if e = store.ConfirmAdministrator(ctx, 1, 1, now); e != nil {
		t.Fatal(e)
	}
	ds, e := devices.New(ctx, store, filepath.Join(root, "secrets", "authority.pem"))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(DeviceHandler(ds))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ds.Roots()}
	server.StartTLS()
	defer server.Close()
	enroll := func() (*http.Client, protocol.Credential, string) {
		t.Helper()
		token, _, e := ds.NewToken(ctx)
		if e != nil {
			t.Fatal(e)
		}
		key, e := deviceidentity.NewKey()
		if e != nil {
			t.Fatal(e)
		}
		csr, _ := deviceidentity.CSR(key)
		cred, e := ds.Enroll(ctx, protocol.Enrollment{Token: token, CSR: csr, Hostname: "test updater", OS: "windows", Architecture: "amd64"}, "test")
		if e != nil {
			t.Fatal(e)
		}
		kpem, _ := deviceidentity.KeyPEM(key)
		pair, e := tls.X509KeyPair([]byte(cred.Certificate), kpem)
		if e != nil {
			t.Fatal(e)
		}
		client := server.Client()
		tr := client.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{pair}
		client = &http.Client{Transport: tr}
		t.Cleanup(tr.CloseIdleConnections)
		return client, cred, deviceidentity.Fingerprint(pair.Certificate[0])
	}
	client, cred, fp := enroll()
	other, _, _ := enroll()
	artifact := agentUpdatePEFixture()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	m := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.2", Sequence: 2, Size: int64(len(artifact)), Hash: agentupdate.Digest(artifact), KeyID: agentupdate.Digest(public), Issued: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix()}
	release := protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, agentupdate.Message(m)))}
	f, e := store.NewAgentReleaseTemp()
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.Write(artifact)
	f.Close()
	defer os.Remove(f.Name())
	if e != nil {
		t.Fatal(e)
	}
	if e = store.AddAgentRelease(ctx, release, hex.EncodeToString(public), f.Name(), "admin", now); e != nil {
		t.Fatal(e)
	}
	if e = store.RecordHeartbeat(ctx, cred.DeviceID, fp, protocol.Heartbeat{Hostname: "test updater", OS: "windows", Architecture: "amd64", AgentVersion: "test.1"}, now); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(protocol.AgentUpgradeSupport{Broker: "enabled", CurrentHash: strings.Repeat("c", 64), KeyIDs: []string{m.KeyID}})
	if e = store.RecordAgentUpgradeSupport(ctx, cred.DeviceID, fp, protocol.FeatureReport{Capability: agentupdate.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	change := storage.AgentRolloutChange{ID: strings.Repeat("a", 32), ReleaseID: agentupdate.ReleaseID(release), Devices: []string{cred.DeviceID}, Groups: []string{}}
	review, e := store.QueueAgentRollout(ctx, change, "admin", "", now, 120*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.QueueAgentRollout(ctx, change, "admin", review.Digest, now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
	poll := func(raw string) (int, string) {
		r, e := client.Post(server.URL+"/api/v1/agent/agent-upgrades/poll", "application/json", strings.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		return r.StatusCode, readResponse(t, r)
	}
	if status, _ := poll(`{"unexpected":true}`); status != 400 {
		t.Fatal("strict fields", status)
	}
	status, body := poll("{}")
	if status != 200 {
		t.Fatal(status, body)
	}
	var dispatch protocol.AgentUpgradeDispatch
	if json.Unmarshal([]byte(body), &dispatch) != nil || dispatch.Job == nil {
		t.Fatal(body)
	}
	status, body = poll("{}")
	if status != 200 || strings.Contains(body, dispatch.Job.ID) {
		t.Fatal("dispatch redelivered", status, body)
	}
	url := server.URL + "/api/v1/agent/agent-upgrades/" + dispatch.Job.ID + "/artifact"
	r, e := other.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	readResponse(t, r)
	if r.StatusCode != 409 {
		t.Fatal("cross-device download", r.StatusCode)
	}
	r, e = client.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	download := readResponse(t, r)
	if r.StatusCode != 200 || download != string(artifact) {
		t.Fatal("artifact changed", r.StatusCode)
	}
	for _, route := range []string{"/api/v1/agent-releases", "/api/v1/agent-upgrades", "/agent-updates"} {
		r, e = client.Get(server.URL + route)
		if e != nil {
			t.Fatal(e)
		}
		readResponse(t, r)
		if r.StatusCode != 404 {
			t.Fatal("admin route on device listener", route, r.StatusCode)
		}
	}
	result, _ := json.Marshal(protocol.AgentUpgradeResult{ID: dispatch.Job.ID, Outcome: "succeeded", Hash: m.Hash, Sequence: m.Sequence})
	r, e = client.Post(server.URL+"/api/v1/agent/agent-upgrades/result", "application/json", bytes.NewReader(result))
	if e != nil {
		t.Fatal(e)
	}
	readResponse(t, r)
	if r.StatusCode != 200 {
		t.Fatal("result rejected", r.StatusCode)
	}
	r, e = client.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	readResponse(t, r)
	if r.StatusCode != 409 {
		t.Fatal("artifact available after completion", r.StatusCode)
	}
	if e = store.RevokeDevice(ctx, cred.DeviceID, time.Now()); e != nil {
		t.Fatal(e)
	}
	if status, _ = poll("{}"); status != 403 {
		t.Fatal("revoked identity", status)
	}
}

func TestBundledReleaseImportIsIdempotentAndNeedsNoSession(t *testing.T) {
	f := newAPIFixture(t)
	artifact := agentUpdatePEFixture()
	release, public := signedRelease(t, artifact, 9)
	b := agentbundle.Bundle{Release: release, PublicKey: public, Binary: artifact}
	ctx := context.Background()
	if added, e := importBundle(ctx, f.store, b, time.Now()); e != nil || !added {
		t.Fatal("bundled release not imported", added, e)
	}
	if added, e := importBundle(ctx, f.store, b, time.Now()); e != nil || added {
		t.Fatal("bundled release imported twice", added, e)
	}
	releases, _, e := f.store.AgentReleases(ctx)
	if e != nil || len(releases) != 1 || releases[0].Actor != storage.BundledReleaseActor || releases[0].Release.Manifest.Sequence != 9 {
		t.Fatal("bundled release missing from the library", releases, e)
	}
	// A release not yet in the library is verified against its signed hash.
	next, nextPublic := signedRelease(t, artifact, 10)
	altered := append([]byte{}, artifact...)
	altered[len(altered)-1]++
	if _, e := importBundle(ctx, f.store, agentbundle.Bundle{Release: next, PublicKey: nextPublic, Binary: altered}, time.Now()); e == nil {
		t.Fatal("bundle with mismatched bytes imported")
	}
}

// A full library makes room for the bundled
// release by withdrawing the oldest release the server imported itself.
func TestBundledReleaseRetiresOldest(t *testing.T) {
	f := newAPIFixture(t)
	artifact := agentUpdatePEFixture()
	ctx := context.Background()
	for seq := int64(1); seq <= 9; seq++ {
		release, public := signedRelease(t, artifact, seq)
		if added, e := importBundle(ctx, f.store, agentbundle.Bundle{Release: release, PublicKey: public, Binary: artifact}, time.Now()); e != nil || !added {
			t.Fatal("bundled release not imported", seq, e)
		}
	}
	releases, _, e := f.store.AgentReleases(ctx)
	if e != nil {
		t.Fatal(e)
	}
	active := map[int64]bool{}
	for _, r := range releases {
		if !r.Withdrawn {
			active[r.Release.Manifest.Sequence] = true
		}
	}
	if len(active) != 8 || active[1] || !active[9] {
		t.Fatal("oldest bundled release not retired", active)
	}
	// An older bundled release never pushes out a newer one.
	old, public := signedRelease(t, artifact, 1)
	if _, e := importBundle(ctx, f.store, agentbundle.Bundle{Release: old, PublicKey: public, Binary: artifact}, time.Now()); e == nil {
		t.Fatal("older bundled release imported into a full library")
	}
}
