package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func TestHeartbeatAutomaticallyRenewsAndUsesPersistedReplacement(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	ctx := context.Background()
	issuer, err := deviceidentity.NewAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deviceidentity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := deviceidentity.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := deviceidentity.ParseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	initial, err := issuer.Issue(id, csr, now, 24*time.Hour)
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
	ca, err := os.ReadFile(filepath.Join(tlsPath, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var renewals, beats atomic.Int32
	var failRenew atomic.Bool
	var replacement atomic.Value
	replacement.Store("")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/renew" {
			renewals.Add(1)
			if failRenew.Load() {
				http.Error(w, "renewal temporarily unavailable", 503)
				return
			}
			var input protocol.Renewal
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				http.Error(w, "bad test request", 400)
				return
			}
			request, err := deviceidentity.ParseCSR(input.CSR)
			if err != nil {
				http.Error(w, "bad test CSR", 400)
				return
			}
			issued, err := issuer.Issue(id, request, time.Now(), 30*24*time.Hour)
			if err != nil {
				http.Error(w, "test issuance failed", 500)
				return
			}
			replacement.Store(issued)
			_ = json.NewEncoder(w).Encode(protocol.Credential{DeviceID: id, Certificate: issued, DeviceCA: deviceidentity.CertificatePEM(issuer.Certificate.Raw)})
			return
		}
		if r.URL.Path == "/api/v1/agent/heartbeat" {
			beats.Add(1)
			cert, err := deviceidentity.ParseCertificate(replacement.Load().(string))
			if err != nil || len(r.TLS.PeerCertificates) == 0 || deviceidentity.Fingerprint(r.TLS.PeerCertificates[0].Raw) != deviceidentity.Fingerprint(cert.Raw) {
				http.Error(w, "replacement certificate not used", 403)
				return
			}
			_ = json.NewEncoder(w).Encode(protocol.HeartbeatReceipt{DeviceID: id, ReceivedAt: time.Now().Unix()})
			return
		}
		http.NotFound(w, r)
	})
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate)
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	defer s.Close()
	c := config.Agent{State: filepath.Join(root, "agent"), Timeout: time.Second}
	if err := privatefs.CreateDirectory(c.State); err != nil {
		t.Fatal(err)
	}
	keyPEM, err := deviceidentity.KeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	value := credentials{Version: 1, DeviceURL: s.URL, ServerCA: string(ca), PrivateKey: string(keyPEM), Credential: protocol.Credential{DeviceID: id, Certificate: initial, DeviceCA: deviceidentity.CertificatePEM(issuer.Certificate.Raw)}}
	if err := value.save(c.State, false); err != nil {
		t.Fatal(err)
	}
	session, err := newHeartbeatSession(c, protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: Version})
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	if err := session.pulse(ctx); err != nil {
		t.Fatal(err)
	}
	if err := session.pulse(ctx); err != nil {
		t.Fatal(err)
	}
	if renewals.Load() != 1 || beats.Load() != 2 {
		t.Fatal("automatic renewal was absent or repeated unnecessarily")
	}
	saved, _, _, err := loadCredentials(c.State)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Credential.Certificate == initial || saved.Credential.DeviceID != id || saved.PrivateKey != value.PrivateKey {
		t.Fatal("replacement persistence changed identity/key or retained old certificate")
	}
	// R2: a failed renewal never suppresses the heartbeat, and is retried
	// hourly rather than on every pulse.
	failRenew.Store(true)
	nearExpiry := session.certificate.NotAfter.Add(-24 * time.Hour)
	session.now = func() time.Time { return nearExpiry }
	session.nextRenew = time.Time{}
	before, beatsBefore := renewals.Load(), beats.Load()
	if err := session.pulse(ctx); err != nil {
		t.Fatal("renewal failure suppressed the heartbeat", err)
	}
	if err := session.pulse(ctx); err != nil {
		t.Fatal(err)
	}
	if renewals.Load() != before+1 || beats.Load() != beatsBefore+2 || !session.nextRenew.Equal(nearExpiry.Add(time.Hour)) {
		t.Fatal("renewal retry or heartbeat delivery wrong", renewals.Load()-before, beats.Load()-beatsBefore)
	}
	// R5: a local clock outside the certificate window is only reported; the
	// server's clock decides validity, so the heartbeat is still delivered.
	session.now = func() time.Time { return session.certificate.NotAfter.Add(time.Second) }
	if err := session.pulse(ctx); err != nil || errors.Is(err, ErrDeviceRejected) {
		t.Fatal("local clock skew blocked the heartbeat", err)
	}
}
