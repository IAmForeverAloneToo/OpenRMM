package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devicekey"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// renewalServer issues device certificates for renewal requests. As an
// older server it renews only the key of the connection's certificate; with
// lose set it issues but drops the reply.
type renewalServer struct {
	mu        sync.Mutex
	older     bool
	lose      bool
	requested [][]byte
}

func TestRenewalMovesToANewKey(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	issuer, _ := deviceidentity.NewAuthority(now)
	id := "0123456789abcdef0123456789abcdef"
	issue := func(csr *x509.CertificateRequest) string {
		cert, err := issuer.Issue(id, csr, time.Now(), 30*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	if err := devtls.Generate(filepath.Join(root, "tls")); err != nil {
		t.Fatal(err)
	}
	pair, _ := tls.LoadX509KeyPair(filepath.Join(root, "tls", "server.pem"), filepath.Join(root, "tls", "server-key.pem"))
	ca, _ := os.ReadFile(filepath.Join(root, "tls", "ca.pem"))
	var srv renewalServer
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input protocol.Renewal
		csr, err := (*x509.CertificateRequest)(nil), json.NewDecoder(r.Body).Decode(&input)
		if err == nil {
			csr, err = deviceidentity.ParseCSR(input.CSR)
		}
		if r.URL.Path != "/api/v1/agent/renew" || err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		srv.requested = append(srv.requested, csr.RawSubjectPublicKeyInfo)
		if srv.older && !bytes.Equal(csr.RawSubjectPublicKeyInfo, r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo) {
			http.Error(w, "another key", 403)
			return
		}
		cert := issue(csr)
		if srv.lose {
			http.Error(w, "reply lost", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.Credential{DeviceID: id, Certificate: cert, DeviceCA: deviceidentity.CertificatePEM(issuer.Certificate.Raw)})
	})
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate)
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	defer s.Close()

	c := config.Agent{State: filepath.Join(root, "agent"), Timeout: 5 * time.Second}
	if err := privatefs.CreateDirectory(c.State); err != nil {
		t.Fatal(err)
	}
	// Version 1 credentials: a plain key.
	plain, _ := deviceidentity.NewKey()
	keyPEM, _ := deviceidentity.KeyPEM(plain)
	csrPEM, _ := deviceidentity.CSR(plain)
	csr, _ := deviceidentity.ParseCSR(csrPEM)
	value := credentials{Version: 1, DeviceURL: s.URL, ServerCA: string(ca), PrivateKey: string(keyPEM), Credential: protocol.Credential{DeviceID: id, Certificate: issue(csr), DeviceCA: deviceidentity.CertificatePEM(issuer.Certificate.Raw)}}
	if err := value.save(c.State, false); err != nil {
		t.Fatal(err)
	}
	public := func() *ecdsa.PublicKey {
		t.Helper()
		_, key, _, err := loadCredentials(c.State)
		if err != nil {
			t.Fatal(err)
		}
		return key.Public().(*ecdsa.PublicKey)
	}
	// A version 1 renewal keeps the key and the format.
	if _, err := Renew(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if saved, _, _, _ := loadCredentials(c.State); saved.Version != 1 || !public().Equal(&plain.PublicKey) {
		t.Fatal("version 1 renewal changed the key or format")
	}
	if runtime.GOOS != "windows" {
		return
	}
	// Protection keeps the key but encrypts it.
	if moved, err := protectCredentials(c.State); err != nil || !moved {
		t.Fatal("not protected", err)
	}
	saved, _, _, _ := loadCredentials(c.State)
	raw, _ := os.ReadFile(filepath.Join(c.State, "credentials.json"))
	if saved.Version != 2 || saved.Key.Kind != "dpapi" || bytes.Contains(raw, []byte("PRIVATE KEY")) || !public().Equal(&plain.PublicKey) {
		t.Fatal("protected credentials wrong")
	}
	// An older server refuses the new key; the agent renews the current one
	// and keeps the new key pending.
	srv.older = true
	if _, err := Renew(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if !public().Equal(&plain.PublicKey) {
		t.Fatal("key changed with an older server")
	}
	if _, err := os.Stat(filepath.Join(c.State, pendingKeyFile)); err != nil {
		t.Fatal("pending key not kept")
	}
	// A lost reply is retried with the same pending key, which is then used.
	srv.older, srv.lose = false, true
	if _, err := Renew(context.Background(), c); err == nil {
		t.Fatal("lost reply reported as success")
	}
	srv.lose = false
	if _, err := Renew(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	n := len(srv.requested)
	if !bytes.Equal(srv.requested[n-1], srv.requested[n-2]) || !bytes.Equal(srv.requested[n-1], srv.requested[n-4]) {
		t.Fatal("pending key not reused across attempts")
	}
	rotated := public()
	if rotated.Equal(&plain.PublicKey) {
		t.Fatal("renewal did not move to a new key")
	}
	if _, err := os.Stat(filepath.Join(c.State, pendingKeyFile)); !os.IsNotExist(err) {
		t.Fatal("pending key file kept after use")
	}
	// The next renewal moves again.
	if _, err := Renew(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if public().Equal(rotated) {
		t.Fatal("second renewal kept the key")
	}
	// A pending file naming the current key is not reused.
	current, _, _, _ := loadCredentials(c.State)
	b, _ := json.Marshal(current.Key)
	_ = os.WriteFile(filepath.Join(c.State, pendingKeyFile), b, 0600)
	if k, err := pendingKey(c.State, false, current.Key); err != nil || devicekey.Same(k.Ref(), *current.Key) {
		t.Fatal("current key reused as the pending key", err)
	}
}
