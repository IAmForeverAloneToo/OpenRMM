package agent

import (
	"context"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/server"
)

func testServer(t *testing.T, handler http.Handler) (*httptest.Server, config.Agent) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return s, config.Agent{ServerURL: s.URL, CAFile: caFile, Timeout: time.Second}
}

func TestHealthCheckWithTrustedServer(t *testing.T) {
	_, c := testServer(t, server.Handler(nil, nil, nil))
	if err := Check(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func TestHealthCheckRejectsUntrustedCertificate(t *testing.T) {
	_, c := testServer(t, server.Handler(nil, nil, nil))
	unrelated := filepath.Join(t.TempDir(), "unrelated")
	if err := devtls.Generate(unrelated); err != nil {
		t.Fatal(err)
	}
	c.CAFile = filepath.Join(unrelated, "ca.pem")
	if err := Check(context.Background(), c); err == nil {
		t.Fatal("untrusted server certificate accepted")
	}
}

func TestHealthCheckRejectsBadResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{{"unavailable", 503, `{"status":"ok"}`}, {"wrong-status", 200, `{"status":"failed"}`}, {"invalid-json", 200, `<html>ok</html>`}, {"extra-json", 200, `{"status":"ok"}{"extra":true}`}, {"too-large", 200, `{"status":"ok","data":"` + strings.Repeat("x", 4096) + `"}`}} {
		t.Run(test.name, func(t *testing.T) {
			_, c := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			if err := Check(context.Background(), c); err == nil {
				t.Fatal("bad response accepted")
			}
		})
	}
}

func TestHealthCheckDoesNotFollowRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("agent followed a redirect")
	}))
	defer destination.Close()
	_, c := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	if err := Check(context.Background(), c); err == nil {
		t.Fatal("redirect accepted as healthy")
	}
}

func TestHealthCheckHonorsCancellation(t *testing.T) {
	_, c := testServer(t, server.Handler(nil, nil, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Check(ctx, c); err == nil {
		t.Fatal("canceled request succeeded")
	}
}
