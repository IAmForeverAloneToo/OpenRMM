package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestPeerKey(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.10:443":                   "192.0.2.10",
		"[::ffff:192.0.2.10]:443":          "192.0.2.10",
		"[2001:db8:1:2:aaaa::1]:443":       "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff:ffff::9]:5555": "2001:db8:1:2::/64",
		"garbage":                          "unknown",
	} {
		if got := peerKey(&http.Request{RemoteAddr: addr}); got != want {
			t.Errorf("peerKey(%s) = %s, want %s", addr, got, want)
		}
	}
}

func TestForwardedClient(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.1/32")}
	for _, c := range []struct {
		remote string
		header []string
		want   string
	}{
		{"10.1.1.1:5000", []string{"203.0.113.7"}, "203.0.113.7"},
		// A client's own header is left of what the proxy appends.
		{"10.1.1.1:5000", []string{"198.51.100.1, 203.0.113.7"}, "203.0.113.7"},
		{"10.1.1.1:5000", []string{"198.51.100.1", "203.0.113.7, 192.0.2.1"}, "203.0.113.7"},
		{"10.1.1.1:5000", []string{"10.2.2.2, 10.3.3.3"}, "10.2.2.2"},
		{"10.1.1.1:5000", []string{"203.0.113.7, junk"}, "10.1.1.1"},
		{"10.1.1.1:5000", nil, "10.1.1.1"},
		// An untrusted connection's header is ignored.
		{"198.51.100.9:5000", []string{"203.0.113.7"}, "198.51.100.9"},
	} {
		var got string
		h := forwardedClient(trusted, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = peerKey(r) }))
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.header {
			r.Header.Add("X-Forwarded-For", v)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
		if got != c.want {
			t.Errorf("%s %q: client %s, want %s", c.remote, c.header, got, c.want)
		}
	}
}

func TestStrictTransport(t *testing.T) {
	w := httptest.NewRecorder()
	strictTransport(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatal("HSTS header missing")
	}
}
