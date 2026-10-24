package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/server"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// The installed service enrolls with the installer's enrollment
// file into the state folder Windows Installer created, deletes the file, and
// never enrolls again once it has an identity.
func TestServiceEnrollsWithInstallerFile(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("enrollment supports Windows x64")
	}
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, "data", "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := devices.New(ctx, store, filepath.Join(root, "secrets", "ca", "authority.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tlsPath := filepath.Join(root, "tls")
	if err := devtls.Generate(tlsPath); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(tlsPath, "server.pem"), filepath.Join(tlsPath, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewUnstartedServer(server.Handler(store, nil, service))
	admin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	admin.StartTLS()
	defer admin.Close()
	device := httptest.NewUnstartedServer(server.DeviceHandler(service))
	device.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: service.Roots()}
	device.StartTLS()
	defer device.Close()
	ca, err := os.ReadFile(filepath.Join(tlsPath, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "ProgramData")
	c := config.Agent{State: filepath.Join(data, "state"), Timeout: 5 * time.Second}
	// Windows Installer creates the state folder; an interrupted attempt left a key.
	if err := os.MkdirAll(c.State, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.State, "pending-key.pem"), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	write := func(token string) {
		b, _ := json.Marshal(protocol.EnrollmentFile{Version: 1, ServerURL: admin.URL + "/", DeviceURL: device.URL, ServerCA: string(ca), Token: token})
		if err := os.WriteFile(enrollmentFilePath(c), b, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// A rejected token keeps the file and retries until the service stops.
	write("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	err = enrollFromFile(short, c, logger)
	cancel()
	if err == nil {
		t.Fatal("rejected token enrolled")
	}
	if _, err := os.Stat(enrollmentFilePath(c)); err != nil {
		t.Fatal("enrollment file removed after a failure")
	}

	token, _, err := service.CreateToken(ctx, devices.TokenRequest{Actor: "owner", Label: "Test", Reusable: true, MaxDevices: 5, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	write(token)
	if err := enrollFromFile(ctx, c, logger); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(enrollmentFilePath(c)); !os.IsNotExist(err) {
		t.Fatal("enrollment file kept after enrolling")
	}
	saved, _, _, err := loadCredentials(c.State)
	if err != nil || saved.DeviceURL != device.URL {
		t.Fatal("saved identity", saved.DeviceURL, err)
	}
	if id, err := Connect(ctx, c); err != nil || id != saved.Credential.DeviceID {
		t.Fatal("enrolled identity not usable", err)
	}
	recordDevice(c, logger)
	var record deviceRecord
	if b, err := os.ReadFile(filepath.Join(data, "device.json")); err != nil || json.Unmarshal(b, &record) != nil || record.DeviceID != saved.Credential.DeviceID || record.DeviceURL != device.URL {
		t.Fatal("device record", record, err)
	}

	// An enrolled service only removes a leftover file.
	write(token)
	if err := enrollFromFile(ctx, c, logger); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(enrollmentFilePath(c)); !os.IsNotExist(err) {
		t.Fatal("leftover enrollment file kept")
	}
	if again, _, _, _ := loadCredentials(c.State); again.Credential.DeviceID != saved.Credential.DeviceID {
		t.Fatal("enrolled device enrolled again")
	}
	if tokens, _ := store.DeploymentTokens(ctx, time.Now()); len(tokens) != 1 || tokens[0].Used != 1 {
		t.Fatal("token use", tokens)
	}
}

func TestEnrollmentFileValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment.json")
	good := protocol.EnrollmentFile{Version: 1, ServerURL: "https://rmm.example.com:8443", DeviceURL: "https://rmm.example.com:8444", Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for name, mutate := range map[string]func(*protocol.EnrollmentFile){
		"good":    func(*protocol.EnrollmentFile) {},
		"version": func(f *protocol.EnrollmentFile) { f.Version = 2 },
		"http":    func(f *protocol.EnrollmentFile) { f.ServerURL = "http://rmm.example.com" },
		"path":    func(f *protocol.EnrollmentFile) { f.DeviceURL = "https://rmm.example.com/x" },
		"token":   func(f *protocol.EnrollmentFile) { f.Token = "short" },
		"ca":      func(f *protocol.EnrollmentFile) { f.ServerCA = "not a certificate" },
	} {
		f := good
		mutate(&f)
		b, _ := json.Marshal(f)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readEnrollmentFile(path)
		if (err == nil) != (name == "good") {
			t.Fatal(name, err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"extra":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnrollmentFile(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}
