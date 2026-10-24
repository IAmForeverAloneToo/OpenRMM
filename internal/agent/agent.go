// Package agent owns outbound server communication. It opens no listener.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
)

// Check performs one authenticated-server TLS health probe, not device enrollment.
func Check(ctx context.Context, c config.Agent) error {
	caPEM, err := os.ReadFile(c.CAFile)
	if err != nil {
		return errors.New("cannot read trusted CA file; run the development certificate helper or check CA configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("trusted CA file does not contain a valid certificate")
	}
	transport := &http.Transport{
		// Explicit trust bundle; no system proxy or ambient CA trust for this probe.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   c.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	endpoint := "/healthz"
	if c.Ready {
		endpoint = "/readyz"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.ServerURL, "/")+endpoint, nil)
	if err != nil {
		return errors.New("cannot construct health request; check server configuration")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("server health check failed; check connectivity, server name, and trusted CA")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("server health endpoint returned an unsuccessful status")
	}
	const limit = 4096
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(body) > limit {
		return errors.New("server health response is unreadable or too large")
	}
	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &health); err != nil || health.Status != "ok" {
		return errors.New("server returned an invalid health response")
	}
	return nil
}
