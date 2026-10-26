package server

import (
	"net/http"
	"net/http/httptest"
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

func TestStrictTransport(t *testing.T) {
	w := httptest.NewRecorder()
	strictTransport(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatal("HSTS header missing")
	}
}
