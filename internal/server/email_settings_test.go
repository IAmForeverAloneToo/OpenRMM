package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
)

// The dashboard's e-mail settings: the password is write-only and stored
// encrypted, invalid settings are refused, and saving switches the queue.
func TestEmailSettingsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	ctx := context.Background()
	const password = "smtp-test-secret-not-real"
	read := func() map[string]any {
		t.Helper()
		resp, body := f.do(t, "GET", "/api/v1/alert-settings/email", nil, false)
		var v map[string]any
		if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || strings.Contains(string(body), password) || strings.Contains(string(body), "cipher") {
			t.Fatalf("e-mail settings: %d %s", resp.StatusCode, body)
		}
		return v
	}
	v := read()
	if v["source"] != "dashboard" || v["enabled"] != false || v["has_password"] != false || v["active"] != false {
		t.Fatal("unexpected defaults", v)
	}
	// A closed local port: the test message reaches no server.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	p, _ := strconv.Atoi(port)
	in := map[string]any{"enabled": true, "host": "127.0.0.1", "port": p, "tls": "starttls", "username": "rmm", "password": "", "from": "rmm@example.invalid", "to": []string{"admin@example.invalid"}, "server_url": "https://rmm.example.invalid/", "revision": 1}
	if resp, body := f.do(t, "PUT", "/api/v1/alert-settings/email", in, true); resp.StatusCode != 400 {
		t.Fatalf("user name without a password accepted: %d %s", resp.StatusCode, body)
	}
	in["password"] = password
	in["to"] = []string{"admin@example.invalid", "admin@example.invalid"}
	if resp, body := f.do(t, "PUT", "/api/v1/alert-settings/email", in, true); resp.StatusCode != 400 {
		t.Fatalf("duplicate recipients accepted: %d %s", resp.StatusCode, body)
	}
	in["to"] = []string{"admin@example.invalid"}
	if resp, body := f.do(t, "PUT", "/api/v1/alert-settings/email", in, false); resp.StatusCode != 403 {
		t.Fatalf("change without CSRF token: %d %s", resp.StatusCode, body)
	}
	resp, body := f.do(t, "PUT", "/api/v1/alert-settings/email", in, true)
	if resp.StatusCode != 200 || strings.Contains(string(body), password) {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	stored, e := f.store.MailSettings(ctx)
	if e != nil || stored.PasswordCipher == nil || bytes.Contains(stored.PasswordCipher, []byte(password)) || stored.ServerURL != "https://rmm.example.invalid" {
		t.Fatal("password not stored encrypted", e)
	}
	runtime, e := f.store.AlertRuntime(ctx)
	if e != nil || runtime.MailConfig != alerting.ConfigID(mailConfig(stored)) {
		t.Fatal("queue not switched to the new settings", e)
	}
	if v = read(); v["has_password"] != true || v["active"] != true || v["revision"] != float64(2) {
		t.Fatal("unexpected settings after save", v)
	}
	// Saving again without a password keeps the stored one.
	in["password"], in["revision"] = "", 2
	if resp, body := f.do(t, "PUT", "/api/v1/alert-settings/email", in, true); resp.StatusCode != 200 {
		t.Fatalf("save keeping the password: %d %s", resp.StatusCode, body)
	}
	if again, _ := f.store.MailSettings(ctx); !bytes.Equal(again.PasswordCipher, stored.PasswordCipher) {
		t.Fatal("stored password not kept")
	}
	if resp, _ := f.do(t, "PUT", "/api/v1/alert-settings/email", in, true); resp.StatusCode != 409 {
		t.Fatal("stale revision accepted", resp.StatusCode)
	}
	// The test message goes through the saved settings and is rate limited.
	resp, body = f.do(t, "POST", "/api/v1/alert-settings/email/test", nil, true)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"retry"`) {
		t.Fatalf("test message: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/alert-settings/email/test", nil, true); resp.StatusCode != 429 {
		t.Fatal("test messages not rate limited", resp.StatusCode)
	}
	// Turning e-mail off stops the queue and refuses tests.
	in["enabled"], in["revision"] = false, 3
	if resp, body := f.do(t, "PUT", "/api/v1/alert-settings/email", in, true); resp.StatusCode != 200 {
		t.Fatalf("turn off: %d %s", resp.StatusCode, body)
	}
	if runtime, e = f.store.AlertRuntime(ctx); e != nil || runtime.MailConfig != "" {
		t.Fatal("queue still active after turning e-mail off", e)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/alert-settings/email/test", nil, true); resp.StatusCode != 409 {
		t.Fatal("test message while off", resp.StatusCode)
	}
}
