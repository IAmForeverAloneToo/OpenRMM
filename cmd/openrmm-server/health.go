package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
)

// checkHealth asks the server on its own listen address whether it is ready
// (the container health check). It connects over loopback but checks
// the certificate for the public name, with the trust agents use.
func checkHealth(ctx context.Context, c config.Server) error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("invalid listen address")
	}
	if ip, e := netip.ParseAddr(host); e == nil && ip.IsUnspecified() {
		host = "127.0.0.1"
		if ip.Is6() {
			host = "::1"
		}
	}
	trust := &tls.Config{MinVersion: tls.VersionTLS13}
	switch {
	case c.ACMEDomain != "" && c.ACMEDirectory != "":
		// A test ACME CA (staging, Pebble) is not in the system trust store:
		// the server must present exactly the certificate it obtained, for
		// its domain.
		raw, e := os.ReadFile(filepath.Join(c.ACMECache, "certificate.pem"))
		block, _ := pem.Decode(raw)
		if e != nil || block == nil {
			return errors.New("the server has no certificate yet")
		}
		want := block.Bytes
		trust.ServerName = c.ACMEDomain
		trust.InsecureSkipVerify = true // replaced by the exact match below
		trust.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 || !bytes.Equal(s.PeerCertificates[0].Raw, want) {
				return errors.New("unexpected certificate")
			}
			return s.PeerCertificates[0].VerifyHostname(c.ACMEDomain)
		}
	case c.ACMEDomain != "":
		trust.ServerName = c.ACMEDomain
	case len(c.ServerHosts) > 0:
		trust.ServerName = c.ServerHosts[0]
	default:
		pair, e := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if e != nil || pair.Leaf == nil {
			return errors.New("cannot read the server certificate")
		}
		if len(pair.Leaf.DNSNames) > 0 {
			trust.ServerName = pair.Leaf.DNSNames[0]
		} else if len(pair.Leaf.IPAddresses) > 0 {
			trust.ServerName = pair.Leaf.IPAddresses[0].String()
		}
	}
	if c.ACMEDomain == "" && c.CAFile != "" {
		raw, e := os.ReadFile(c.CAFile)
		trust.RootCAs = x509.NewCertPool()
		if e != nil || !trust.RootCAs.AppendCertsFromPEM(raw) {
			return errors.New("cannot read the server CA")
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: trust}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(host, port)+"/readyz", nil)
	if err != nil {
		return errors.New("cannot build the readiness request")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("the server does not answer on its listen address with a valid certificate")
	}
	defer response.Body.Close()
	var health struct {
		Status string `json:"status"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || json.Unmarshal(body, &health) != nil || health.Status != "ok" {
		return errors.New("the server is not ready")
	}
	return nil
}
