package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agent"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

type startupWriter struct{ started chan string }

func (w startupWriter) Write(p []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
		Listen  string `json:"listen"`
	}
	if err := json.Unmarshal(p, &record); err == nil && record.Message == "server started" {
		w.started <- record.Listen
	}
	return len(p), nil
}

func TestReadinessTracksStorageAvailability(t *testing.T) {
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "data", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := Handler(store, nil, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK || response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatal("initialized storage should be ready")
	}
	store.Close()
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"status\":\"unavailable\"}\n" {
		t.Fatal("closed storage should return a generic unavailable response")
	}
}

func TestHealthEndpoint(t *testing.T) {
	handler := Handler(nil, nil, nil)
	// Non-API paths serve the browser application shell (or 503 before the
	// frontend is built); unknown API paths are JSON 404s.
	ui := http.StatusServiceUnavailable
	if _, built := uiFiles(); built {
		ui = http.StatusOK
	}
	for _, test := range []struct {
		method string
		path   string
		status int
	}{{"GET", "/healthz", 200}, {"HEAD", "/healthz", 200}, {"POST", "/healthz", 405}, {"GET", "/", ui}, {"GET", "/api/v1/devices", 404}, {"GET", "/devices/anything", ui}, {"POST", "/", 405}} {
		request := httptest.NewRequest(test.method, "https://localhost"+test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s: got %d, want %d", test.method, test.path, response.Code, test.status)
		}
		if test.method == "GET" && test.path == "/healthz" {
			if response.Body.String() != "{\"status\":\"ok\"}\n" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("health must disclose only constant status and disable caching")
			}
		}
	}
}

func TestRunStopsOnCancellation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tls")
	if err := devtls.Generate(directory); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Port zero is used only inside this lifecycle test, not accepted by the CLI.
	c := config.Server{Listen: "127.0.0.1:0", DeviceListen: "127.0.0.1:0", CertFile: filepath.Join(directory, "server.pem"), KeyFile: filepath.Join(directory, "server-key.pem"), Database: filepath.Join(t.TempDir(), "data", "server.db"), EncryptionKey: filepath.Join(t.TempDir(), "secrets", "key.bin")}
	result := make(chan error, 1)
	started := make(chan string, 1)
	go func() { result <- Run(ctx, c, slog.New(slog.NewJSONHandler(startupWriter{started: started}, nil))) }()
	select {
	case address := <-started:
		probe := config.Agent{ServerURL: "https://" + address, CAFile: filepath.Join(directory, "ca.pem"), Timeout: time.Second, Ready: true}
		if err := agent.Check(context.Background(), probe); err != nil {
			t.Fatal(err)
		}
	case err := <-result:
		t.Fatalf("server exited before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not begin listening")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("server did not shut down after cancellation")
	}
}

func TestRunReportsOccupiedListener(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "tls")
	if err := devtls.Generate(directory); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := config.Server{Listen: listener.Addr().String(), CertFile: filepath.Join(directory, "server.pem"), KeyFile: filepath.Join(directory, "server-key.pem"), Database: filepath.Join(t.TempDir(), "data", "server.db"), EncryptionKey: filepath.Join(t.TempDir(), "secrets", "key.bin")}
	if err := Run(context.Background(), c, slog.New(slog.NewJSONHandler(io.Discard, nil))); err == nil {
		t.Fatal("occupied port must fail")
	}
}
