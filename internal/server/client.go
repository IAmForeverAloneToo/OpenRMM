package server

import (
	"net/http"
	"net/netip"
	"strings"
)

// peerKey identifies the client for throttling: its IPv4 address, or the
// /64 prefix of an IPv6 address, since one host can use any address in its
// /64. Forwarded headers count only from configured proxies (forwardedClient).
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

// forwardedClient replaces the connection address with the client named in
// X-Forwarded-For when the connection comes from a trusted reverse proxy.
// The header is read from the right, skipping trusted proxies, so a client
// cannot choose its own address by sending the header itself.
func forwardedClient(trusted []netip.Prefix, next http.Handler) http.Handler {
	if len(trusted) == 0 {
		return next
	}
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && isTrusted(ap.Addr().Unmap()) {
			if client, ok := forwardedFor(r.Header.Values("X-Forwarded-For"), isTrusted); ok {
				r.RemoteAddr = netip.AddrPortFrom(client, 0).String()
			}
		}
		next.ServeHTTP(w, r)
	})
}

// forwardedFor returns the rightmost address that is not a trusted proxy,
// or the leftmost one when all are. An unreadable entry ends the search
// without a result: whatever is left of it cannot be attributed.
func forwardedFor(values []string, trusted func(netip.Addr) bool) (netip.Addr, bool) {
	var hops []string
	for _, v := range values {
		hops = append(hops, strings.Split(v, ",")...)
	}
	var last netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil || a.Zone() != "" {
			return netip.Addr{}, false
		}
		if a = a.Unmap(); !trusted(a) {
			return a, true
		}
		last = a
	}
	return last, last.IsValid()
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
