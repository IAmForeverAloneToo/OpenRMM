package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// The install command's one-time link creates the first
// administrator in the browser: a wrong link is refused, a setup started and
// abandoned can be redone, the link works once, and no link is made once an
// administrator exists.
func TestSetupLink(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(root, "data", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.New(ctx, store, filepath.Join(root, "secrets", "key.bin"))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := devices.New(ctx, store, filepath.Join(root, "secrets", "device-ca", "authority.pem"))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewTLSServer(Handler(store, service, ds))
	defer s.Close()
	client := s.Client()
	client.Jar, _ = cookiejar.New(nil)
	f := &apiFixture{server: s, client: client}

	if _, body := f.do(t, "GET", "/api/v1/setup", nil, false); !strings.Contains(string(body), `"needed":true`) {
		t.Fatal("setup not needed", string(body))
	}
	token, expires, err := service.NewSetupLink(ctx)
	if err != nil || time.Until(expires) < 59*time.Minute || time.Until(expires) > time.Hour {
		t.Fatal(token, expires, err)
	}
	begin := func(link string) (int, auth.Provisioning) {
		resp, body := f.do(t, "POST", "/api/v1/setup/begin", map[string]string{"link": link, "username": "owner", "password": testPassword}, false)
		var p auth.Provisioning
		json.Unmarshal(body, &p)
		return resp.StatusCode, p
	}
	if status, _ := begin(strings.Repeat("A", 43)); status != 400 {
		t.Fatal("wrong link accepted", status)
	}
	// Started, then abandoned and started again: the second one counts.
	if status, _ := begin(token); status != 200 {
		t.Fatal("begin", status)
	}
	status, p := begin(token)
	if status != 200 || p.Secret == "" || len(p.RecoveryCodes) == 0 {
		t.Fatal("begin again", status)
	}
	confirm := func(code string) int {
		resp, _ := f.do(t, "POST", "/api/v1/setup/confirm", map[string]string{"link": token, "code": code}, false)
		return resp.StatusCode
	}
	if confirm("000000") != 400 {
		t.Fatal("wrong code accepted")
	}
	if confirm(totpCode(t, p.Secret, time.Now().Add(-30*time.Second))) != 204 {
		t.Fatal("confirm")
	}
	if status, _ := begin(token); status != 400 {
		t.Fatal("link used twice", status)
	}
	if _, body := f.do(t, "GET", "/api/v1/setup", nil, false); !strings.Contains(string(body), `"needed":false`) {
		t.Fatal("setup still needed", string(body))
	}
	if _, _, err = service.NewSetupLink(ctx); !errors.Is(err, storage.ErrAlreadyConfigured) {
		t.Fatal("link made after setup", err)
	}
	resp, _ := f.do(t, "POST", "/api/v1/session", map[string]string{"username": "owner", "password": testPassword, "code": totpCode(t, p.Secret, time.Now())}, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-in after setup", resp.StatusCode)
	}
	// An expired link is refused.
	if err = store.CheckSetupLink(ctx, "x", time.Now().Add(2*time.Hour)); !errors.Is(err, storage.ErrSetupLink) {
		t.Fatal(err)
	}
}

// Past the failure limit even the right link is refused,
// so authenticator codes cannot be guessed at full speed.
func TestSetupLinkLimit(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(root, "data", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.New(ctx, store, filepath.Join(root, "secrets", "key.bin"))
	if err != nil {
		t.Fatal(err)
	}
	ds, err := devices.New(ctx, store, filepath.Join(root, "secrets", "device-ca", "authority.pem"))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewTLSServer(Handler(store, service, ds))
	defer s.Close()
	f := &apiFixture{server: s, client: s.Client()}
	token, _, err := service.NewSetupLink(ctx)
	if err != nil {
		t.Fatal(err)
	}
	begin := func(link string) int {
		resp, _ := f.do(t, "POST", "/api/v1/setup/begin", map[string]string{"link": link, "username": "owner", "password": testPassword}, false)
		return resp.StatusCode
	}
	for i := 0; i < 6; i++ {
		begin(strings.Repeat("B", 43))
	}
	if status := begin(token); status != http.StatusTooManyRequests {
		t.Fatal("attempt evaluated past the limit", status)
	}
}
