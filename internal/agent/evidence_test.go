package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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

// The agent collects a multi-chunk file over the real mTLS device
// API; the server verifies it and stores it by hash, and the case's custody
// log records it.
func TestAgentCollectsEvidence(t *testing.T) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Skip("evidence collection supports Windows x64")
	}
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, "data", "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.UseEvidence(filepath.Join(root, "evidence"), 0); err != nil {
		t.Fatal(err)
	}
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
	c := config.Agent{ServerURL: admin.URL, DeviceURL: device.URL, CAFile: filepath.Join(tlsPath, "ca.pem"), State: filepath.Join(root, "agent"), Timeout: 5 * time.Second}
	token, _, err := service.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := enroll(ctx, c, token, "evidence-test", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	session, err := newHeartbeatSession(c, protocol.Heartbeat{Hostname: "evidence-test", OS: "windows", Architecture: "amd64", AgentVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()

	data := make([]byte, 20<<20+12345)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "collected.bin")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	kase, err := store.CreateCase(ctx, "Agent evidence test", "owner", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.QueueEvidence(ctx, kase.ID, id, source, "owner", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var d protocol.EvidenceDispatch
	if err := session.call(ctx, "/api/v1/agent/evidence/poll", struct{}{}, &d); err != nil || d.Job == nil || d.Job.ID != job {
		t.Fatal("poll", d, err)
	}
	journal, err := openJournal(c.State)
	if err != nil {
		t.Fatal(err)
	}
	if d.Job.DeviceID != id || !session.boundHere(d.Job.DeviceID) || session.boundHere("0123456789abcdef0123456789abcdef") {
		t.Fatal("job not bound to this device", d.Job.DeviceID)
	}
	if outcome := session.handleEvidence(ctx, journal, *d.Job, nil, slog.New(slog.NewTextHandler(io.Discard, nil))); outcome != "ok" {
		t.Fatal("collection outcome", outcome)
	}
	if handled, err := store.VerifyEvidence(ctx, time.Now); !handled || err != nil {
		t.Fatal("verify", handled, err)
	}
	f, j, err := store.OpenCaseEvidence(ctx, kase.ID, job, "owner", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if j.ServerSHA256 != want || !bytes.Equal(got, data) {
		t.Fatal("stored evidence differs from the source file")
	}
	detail, _ := store.CaseDetail(ctx, kase.ID)
	if !detail.Verified || detail.Entries[2].Action != "evidence_collected" || detail.Entries[2].Details["device_sha256"] != want || detail.Entries[2].Details["chunks"] != "3" {
		t.Fatalf("custody %+v", detail.Entries)
	}

	// The same job dispatched again is not run again (the source
	// file is gone); the recorded result is sent again instead.
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if outcome := session.handleEvidence(ctx, journal, *d.Job, nil, slog.New(slog.NewTextHandler(io.Discard, nil))); outcome != "resent_ok" {
		t.Fatal("replayed job ran again:", outcome)
	}

	// A path in the agent's own folders is refused on the device.
	denied, _ := store.QueueEvidence(ctx, kase.ID, id, filepath.Join(c.State, "credentials.json"), "owner", time.Now())
	if err := session.call(ctx, "/api/v1/agent/evidence/poll", struct{}{}, &d); err != nil || d.Job == nil || d.Job.ID != denied {
		t.Fatal("poll denied job", err)
	}
	if f, _ := session.collectEvidence(ctx, *d.Job, []string{c.State}, false); f.Outcome != "denied" {
		t.Fatal("agent state folder collected", f.Outcome)
	}
}
