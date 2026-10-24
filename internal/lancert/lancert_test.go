package lancert

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The server's own CA issues a certificate for the configured
// hosts, keeps it until 30 days before expiry, renews it with the same CA,
// reissues when the hosts change, and refuses a CA certificate without its
// key.
func TestManager(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	m := &Manager{Dir: dir, Hosts: ParseHosts(" RMM.lan, 192.168.1.20,rmm.lan "), Now: func() time.Time { return now }}
	if len(m.Hosts) != 2 {
		t.Fatal(m.Hosts)
	}
	if e := m.Ensure(); e != nil {
		t.Fatal(e)
	}
	first, _ := m.GetCertificate(nil)
	roots := x509.NewCertPool()
	raw, _ := os.ReadFile(m.CAFile())
	roots.AppendCertsFromPEM(raw)
	for _, name := range []string{"rmm.lan", "192.168.1.20"} {
		if _, e := first.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); e != nil {
			t.Fatal(name, e)
		}
	}
	if len(first.Certificate) != 2 {
		t.Fatal("chain without the CA")
	}
	// A restart reuses the certificate.
	again := &Manager{Dir: dir, Hosts: m.Hosts, Now: m.Now}
	if e := again.Ensure(); e != nil {
		t.Fatal(e)
	}
	c, _ := again.GetCertificate(nil)
	if c.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("reissued without need")
	}
	// Near expiry it is renewed by the same CA.
	now = now.Add(160 * 24 * time.Hour)
	if e := again.Ensure(); e != nil {
		t.Fatal(e)
	}
	c, _ = again.GetCertificate(nil)
	if c.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("not renewed")
	}
	if _, e := c.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "rmm.lan", CurrentTime: now}); e != nil {
		t.Fatal("renewed with another CA", e)
	}
	// Other hosts: reissued.
	other := &Manager{Dir: dir, Hosts: []string{"rmm.example.net"}, Now: m.Now}
	if e := other.Ensure(); e != nil {
		t.Fatal(e)
	}
	c, _ = other.GetCertificate(&tls.ClientHelloInfo{})
	if c.Leaf.VerifyHostname("rmm.example.net") != nil {
		t.Fatal("hosts not changed")
	}
	if h := ParseHosts("FD00:0::1, ::ffff:10.0.0.1"); len(h) != 2 || h[0] != "fd00::1" || h[1] != "10.0.0.1" {
		t.Fatal(h)
	}
	// A CA key without its certificate (crash while creating) is replaced.
	half := t.TempDir()
	os.WriteFile(filepath.Join(half, "ca-key.pem"), []byte("partial"), 0600)
	if e := (&Manager{Dir: half, Hosts: []string{"rmm.lan"}}).Ensure(); e != nil {
		t.Fatal("half-created CA not replaced", e)
	}
	// A CA certificate without its key is never replaced.
	os.Remove(filepath.Join(dir, "ca-key.pem"))
	os.Remove(filepath.Join(dir, "server.pem"))
	if e := (&Manager{Dir: dir, Hosts: m.Hosts}).Ensure(); e == nil {
		t.Fatal("incomplete CA accepted")
	}
	if ValidHost("0.0.0.0") || ValidHost("bad host") || !ValidHost("10.0.0.5") || !ValidHost("rmm") {
		t.Fatal("hosts")
	}
}
