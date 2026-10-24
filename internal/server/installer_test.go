package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func signedMSIRelease(t *testing.T, artifact []byte, sequence int64) (protocol.SignedAgentRelease, string) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	m := protocol.AgentManifest{Format: 2, Package: "msi", AgentHash: strings.Repeat("a", 64), Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.msi", Sequence: sequence, Size: int64(len(artifact)), Hash: agentupdate.Digest(artifact), KeyID: agentupdate.Digest(public), Issued: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix()}
	return protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, agentupdate.Message(m)))}, hex.EncodeToString(public)
}

func unzip(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if e != nil {
		t.Fatal("not a ZIP", e)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		files[f.Name], _ = io.ReadAll(r)
		r.Close()
	}
	return files
}

// The owner saves the agents' addresses and downloads installers
// with a single-device token or a reusable, revocable deployment token.
func TestInstallerDownloadAPI(t *testing.T) {
	f := newAPIFixture(t)
	tlsPath := filepath.Join(t.TempDir(), "tls")
	if e := devtls.Generate(tlsPath); e != nil {
		t.Fatal(e)
	}
	f.devices.InstallerCA, f.devices.DevicePort = filepath.Join(tlsPath, "ca.pem"), 8444
	f.login(t)
	ctx := context.Background()
	single := map[string]any{"kind": "single", "label": ""}

	resp, body := f.do(t, "GET", "/api/v1/installer", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"trust":"ca"`) || !strings.Contains(string(body), `"release":null`) || !strings.Contains(string(body), `"device_port":8444`) {
		t.Fatalf("installer view: %d %s", resp.StatusCode, body)
	}
	if resp, body = f.do(t, "POST", "/api/v1/installer/download", single, true); resp.StatusCode != 409 || !strings.Contains(string(body), "addresses") {
		t.Fatalf("download without settings: %d %s", resp.StatusCode, body)
	}
	for _, bad := range []map[string]string{
		{"server_url": "http://rmm.example.com", "device_url": "https://rmm.example.com:8444"},
		{"server_url": "https://rmm.example.com/path", "device_url": "https://rmm.example.com:8444"},
		{"server_url": "https://rmm.example.com:8444", "device_url": "https://rmm.example.com:8444"},
	} {
		if resp, _ = f.do(t, "PUT", "/api/v1/installer/settings", bad, true); resp.StatusCode != 400 {
			t.Fatal("invalid address accepted", bad)
		}
	}
	if resp, body = f.do(t, "PUT", "/api/v1/installer/settings", map[string]string{"server_url": "https://rmm.example.com:8443/", "device_url": "https://rmm.example.com:8444"}, true); resp.StatusCode != 200 {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	if resp, body = f.do(t, "POST", "/api/v1/installer/download", single, true); resp.StatusCode != 409 || !strings.Contains(string(body), "release") {
		t.Fatalf("download without a release: %d %s", resp.StatusCode, body)
	}
	msi := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, bytes.Repeat([]byte("package"), 100)...)
	release, public := signedMSIRelease(t, msi, 3)
	if status, body := f.uploadRelease(t, release, public, msi); status != 201 {
		t.Fatal("upload MSI release", status, body)
	}

	enroll := func(token string) error {
		key, _ := deviceidentity.NewKey()
		csr, _ := deviceidentity.CSR(key)
		_, e := f.devices.Enroll(ctx, protocol.Enrollment{Token: token, CSR: csr, Hostname: "new-pc", OS: "windows", Architecture: "amd64"}, "test")
		return e
	}
	download := func(in any) map[string][]byte {
		t.Helper()
		resp, body := f.do(t, "POST", "/api/v1/installer/download", in, true)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/zip" || !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
			t.Fatalf("download: %d %s", resp.StatusCode, body)
		}
		return unzip(t, body)
	}
	files := download(single)
	var e protocol.EnrollmentFile
	if json.Unmarshal(files["enrollment.json"], &e) != nil || e.ServerURL != "https://rmm.example.com:8443" || e.DeviceURL != "https://rmm.example.com:8444" || !strings.Contains(e.ServerCA, "BEGIN CERTIFICATE") || len(e.Token) != 43 {
		t.Fatal("enrollment file", e.ServerURL, e.DeviceURL)
	}
	if !bytes.Equal(files["openrmm-agent.msi"], msi) || len(files["install.cmd"]) == 0 || len(files["install.ps1"]) == 0 {
		t.Fatal("installer files")
	}
	var r protocol.SignedAgentRelease
	if json.Unmarshal(files["release.json"], &r) != nil || agentupdate.ReleaseID(r) != agentupdate.ReleaseID(release) {
		t.Fatal("release file")
	}
	if err := enroll(e.Token); err != nil {
		t.Fatal("single-device enrollment", err)
	}
	if err := enroll(e.Token); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("single-device token reused", err)
	}

	for _, bad := range []map[string]any{
		{"kind": "deployment", "label": "", "max_devices": 5, "days": 7},
		{"kind": "deployment", "label": "Office", "max_devices": 0, "days": 7},
		{"kind": "deployment", "label": "Office", "max_devices": 5, "days": 400},
		{"kind": "single", "label": "", "max_devices": 5},
		{"kind": "other", "label": ""},
	} {
		if resp, _ = f.do(t, "POST", "/api/v1/installer/download", bad, true); resp.StatusCode != 400 {
			t.Fatal("invalid options accepted", bad)
		}
	}
	files = download(map[string]any{"kind": "deployment", "label": "Office", "max_devices": 2, "days": 7})
	if json.Unmarshal(files["enrollment.json"], &e) != nil {
		t.Fatal("deployment enrollment file")
	}
	for i := 0; i < 2; i++ {
		if err := enroll(e.Token); err != nil {
			t.Fatal("deployment enrollment", i, err)
		}
	}
	if err := enroll(e.Token); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("device limit exceeded", err)
	}
	resp, body = f.do(t, "GET", "/api/v1/installer", nil, false)
	var view struct {
		Release *struct {
			Sequence int64 `json:"sequence"`
			MSI      bool  `json:"msi"`
		} `json:"release"`
		Tokens []storage.EnrollmentToken `json:"tokens"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &view) != nil || view.Release == nil || !view.Release.MSI || len(view.Tokens) != 1 || view.Tokens[0].Used != 2 || view.Tokens[0].Actor != "admin" {
		t.Fatalf("installer view: %s", body)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/installer/tokens/"+view.Tokens[0].ID+"/revoke", nil, true); resp.StatusCode != 204 {
		t.Fatal("revoke", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/installer/tokens/"+view.Tokens[0].ID+"/revoke", nil, true); resp.StatusCode != 404 {
		t.Fatal("revoked twice", resp.StatusCode)
	}
	if strings.Contains(string(body), e.Token) {
		t.Fatal("token listed")
	}
}
