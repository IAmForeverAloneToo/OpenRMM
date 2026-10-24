package server

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// The browser application is built from web/ into webui/dist and embedded. A
// checkout without a frontend build still compiles and serves the API; the page
// then explains that the interface has not been built.
//
//go:embed all:webui
var webUI embed.FS

func uiFiles() (fs.FS, bool) {
	sub, err := fs.Sub(webUI, "webui/dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}

func cookie(name, value string, seconds int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: seconds, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func newNonce() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

// registerUI serves hashed static assets and the single-page application shell.
// Any GET outside /api/ and the health probes returns index.html so client-side
// routes work on reload; the page itself never performs an operation.
func registerUI(mux *http.ServeMux) {
	files, built := uiFiles()
	mux.HandleFunc("GET /assets/{name...}", func(w http.ResponseWriter, r *http.Request) {
		if !built {
			http.NotFound(w, r)
			return
		}
		name := r.PathValue("name")
		if name == "" || strings.Contains(name, "..") || path.Clean(name) != name {
			http.NotFound(w, r)
			return
		}
		b, err := fs.ReadFile(files, "assets/"+name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if t := mime.TypeByExtension(path.Ext(name)); t != "" {
			w.Header().Set("Content-Type", t)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		// File names carry a content hash, so they never change in place.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "Unknown API endpoint.")
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if !built {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The OpenRMM web interface has not been built. Run scripts/build.ps1.\n"))
			return
		}
		// Root-level public files such as favicon.svg are served as-is.
		if name := strings.TrimPrefix(r.URL.Path, "/"); name != "" && name != "index.html" && !strings.Contains(name, "/") && path.Ext(name) != "" {
			if b, err := fs.ReadFile(files, name); err == nil {
				if t := mime.TypeByExtension(path.Ext(name)); t != "" {
					w.Header().Set("Content-Type", t)
				}
				_, _ = w.Write(b)
				return
			}
		}
		index, err := fs.ReadFile(files, "index.html")
		if err != nil {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		nonce := newNonce()
		// Some headless UI primitives insert <style> elements at runtime; they
		// read this nonce. Scripts stay limited to same-origin files.
		index = bytes.Replace(index, []byte("<head>"), []byte(`<head><meta name="csp-nonce" content="`+nonce+`">`), 1)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'nonce-"+nonce+"'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}

func secureWeb(next http.Handler) http.Handler {
	originProtection := http.NewCrossOriginProtection()
	protected := originProtection.Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.TLS == nil && r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			http.Error(w, "HTTPS is required.", http.StatusBadRequest)
			return
		}
		protected.ServeHTTP(w, r)
	})
}
