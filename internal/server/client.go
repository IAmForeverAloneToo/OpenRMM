package server

import (
	"net/http"
	"net/netip"
)

// peerKey identifies the client for throttling: its IPv4 address, or the
// /64 prefix of an IPv6 address, since one host can use any address in its
// /64. Forwarded headers are deliberately not trusted.
func peerKey(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	a := ap.Addr().Unmap()
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return "unknown"
	}
	return p.String()
}

// strictTransport adds HSTS. It is used only with an ACME certificate for a
// public DNS name: on a LAN name or IP address it could break other services
// that the same name serves over plain HTTP.
func strictTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}
