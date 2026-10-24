package acmecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// fakeCA is a minimal RFC 8555 server: it validates the TLS-ALPN-01
// challenge for real by connecting to the manager's listener, and issues a
// certificate from a test CA.
type fakeCA struct {
	t        *testing.T
	srv      *httptest.Server
	target   string // the listener validated
	domain   string
	thumb    string
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	mu       sync.Mutex
	valid    bool
	cert     []byte
	attempts int
}

const token = "tok-123"

func payload(r *http.Request) []byte {
	var jws struct{ Payload string }
	json.NewDecoder(r.Body).Decode(&jws)
	b, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	return b
}

func (f *fakeCA) handler(w http.ResponseWriter, r *http.Request) {
	base := f.srv.URL
	w.Header().Set("Replay-Nonce", fmt.Sprintf("n%d", time.Now().UnixNano()))
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	order := func() map[string]any {
		o := map[string]any{"status": "pending", "identifiers": []map[string]string{{"type": "dns", "value": f.domain}}, "authorizations": []string{base + "/authz/1"}, "finalize": base + "/finalize/1"}
		if f.valid {
			o["status"] = "ready"
		}
		if f.cert != nil {
			o["status"], o["certificate"] = "valid", base+"/cert/1"
		}
		return o
	}
	switch r.URL.Path {
	case "/directory":
		json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order", "revokeCert": base + "/revoke", "keyChange": base + "/key"})
	case "/nonce":
		w.WriteHeader(http.StatusOK)
	case "/account":
		w.Header().Set("Location", base+"/acct/1")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
	case "/order":
		w.Header().Set("Location", base+"/order/1")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(order())
	case "/order/1":
		json.NewEncoder(w).Encode(order())
	case "/authz/1":
		status := "pending"
		if f.valid {
			status = "valid"
		}
		json.NewEncoder(w).Encode(map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": f.domain},
			"challenges": []map[string]string{{"type": "http-01", "url": base + "/chal/0", "token": token, "status": "pending"}, {"type": "tls-alpn-01", "url": base + "/chal/1", "token": token, "status": "pending"}}})
	case "/chal/1":
		f.attempts++
		f.valid = f.validate() == nil
		json.NewEncoder(w).Encode(map[string]string{"type": "tls-alpn-01", "url": base + "/chal/1", "token": token, "status": "valid"})
	case "/finalize/1":
		var in struct{ CSR string }
		json.Unmarshal(payload(r), &in)
		der, _ := base64.RawURLEncoding.DecodeString(in.CSR)
		csr, e := x509.ParseCertificateRequest(der)
		if e != nil || !f.valid {
			http.Error(w, `{"type":"urn:ietf:params:acme:error:badCSR"}`, http.StatusBadRequest)
			return
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.domain}, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		f.cert, _ = x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
		json.NewEncoder(w).Encode(order())
	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert}))
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw}))
	default:
		http.NotFound(w, r)
	}
}

// validate connects like a CA's validation server: SNI the domain, ALPN
// acme-tls/1, and the certificate must carry the key authorization's hash.
func (f *fakeCA) validate() error {
	conn, e := tls.Dial("tcp", f.target, &tls.Config{ServerName: f.domain, NextProtos: []string{ALPN}, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	if e != nil {
		return e
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != ALPN {
		return fmt.Errorf("protocol %q", conn.ConnectionState().NegotiatedProtocol)
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	want := sha256.Sum256([]byte(token + "." + f.thumb))
	for _, x := range cert.Extensions {
		if x.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
			var got []byte
			if _, e := asn1.Unmarshal(x.Value, &got); e == nil && string(got) == string(want[:]) && cert.VerifyHostname(f.domain) == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("no valid acmeIdentifier")
}

// The manager registers, answers TLS-ALPN-01 on its own listener,
// obtains and caches the certificate, serves it to normal clients and loads
// it from the cache after a restart.
func TestObtain(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumb, _ := acme.JWKThumbprint(accountKey.Public())
	f := &fakeCA{t: t, domain: "rmm.example.test", thumb: thumb, caCert: caCert, caKey: caKey}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handler))
	defer f.srv.Close()

	cache := t.TempDir()
	m := &Manager{Domain: f.domain, Cache: cache, Client: &acme.Client{Key: accountKey, DirectoryURL: f.srv.URL + "/directory"}}
	l, e := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	f.target = l.Addr().String()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	// Before a certificate exists, normal handshakes fail.
	if _, e := tls.Dial("tcp", f.target, &tls.Config{ServerName: f.domain, InsecureSkipVerify: true}); e == nil {
		t.Fatal("served without a certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e = m.Obtain(ctx); e != nil {
		t.Fatal(e)
	}
	if f.attempts != 1 || !f.valid {
		t.Fatal("challenge not validated", f.attempts)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	conn, e := tls.Dial("tcp", f.target, &tls.Config{ServerName: f.domain, RootCAs: roots})
	if e != nil {
		t.Fatal("served certificate", e)
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("normal connection below TLS 1.3")
	}
	conn.Close()
	if st := m.Status(); st.NotAfter == 0 || st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	// After a restart the cached certificate is used.
	again := &Manager{Domain: f.domain, Cache: cache}
	if c := again.loadCached(); c == nil || again.due() == false && c == nil {
		t.Fatal("cache")
	}
	if !ValidDomain("rmm.example.com") || ValidDomain("*.example.com") || ValidDomain("192.0.2.1") || ValidDomain("localhost") || ValidDomain("Rmm.example.com") {
		t.Fatal("domain rules")
	}
	if strings.Contains(fmt.Sprint(m.Status()), "BEGIN") {
		t.Fatal("status leaks key material")
	}
}
