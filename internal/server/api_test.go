package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

const testPassword = "A sufficiently long API test passphrase"

func totpCode(t *testing.T, encoded string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	v := mac.Sum(nil)
	o := v[19] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(v[o:o+4])&0x7fffffff)%1000000)
}

type apiFixture struct {
	server  *httptest.Server
	client  *http.Client
	store   *storage.Store
	devices *devices.Service
	auth    *auth.Service
	secret  string
	csrf    string
	// Unused recovery codes for extra sessions of the same administrator.
	recovery []string
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	root := t.TempDir()
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(root, "data", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := auth.New(ctx, store, filepath.Join(root, "secrets", "key.bin"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := service.Setup(ctx, "admin", testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	// Confirm with the previous step so the current step stays free for login.
	if err := service.Confirm(ctx, totpCode(t, p.Secret, time.Now().Add(-30*time.Second))); err != nil {
		t.Fatal(err)
	}
	ds, err := devices.New(ctx, store, filepath.Join(root, "secrets", "device-ca", "authority.pem"))
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewTLSServer(Handler(store, service, ds))
	t.Cleanup(s.Close)
	client := s.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &apiFixture{server: s, client: client, store: store, devices: ds, auth: service, secret: p.Secret, recovery: p.RecoveryCodes}
}

func (f *apiFixture) do(t *testing.T, method, path string, body any, csrf bool) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if csrf {
		req.Header.Set("X-CSRF-Token", f.csrf)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (f *apiFixture) login(t *testing.T) {
	t.Helper()
	resp, body := f.do(t, "POST", "/api/v1/session", map[string]string{"username": "admin", "password": testPassword, "code": totpCode(t, f.secret, time.Now())}, false)
	if resp.StatusCode != 200 {
		t.Fatalf("login status %d: %s", resp.StatusCode, body)
	}
	var s sessionInfo
	if err := json.Unmarshal(body, &s); err != nil || s.CSRF == "" || s.Role != "owner" || !s.Permissions.Owner {
		t.Fatalf("unexpected session %s", body)
	}
	f.csrf = s.CSRF
}

func (f *apiFixture) enroll(t *testing.T, hostname string) string {
	t.Helper()
	token, _, err := f.devices.NewToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key, err := deviceidentity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := deviceidentity.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.devices.Enroll(context.Background(), protocol.Enrollment{Token: token, CSR: csr, Hostname: hostname, OS: "windows", Architecture: "amd64"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c.DeviceID
}

func TestAPISessionLifecycle(t *testing.T) {
	f := newAPIFixture(t)
	if resp, body := f.do(t, "GET", "/api/v1/session", nil, false); resp.StatusCode != 401 || !strings.Contains(string(body), `"unauthenticated"`) {
		t.Fatalf("anonymous session: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/devices", nil, false); resp.StatusCode != 401 {
		t.Fatalf("anonymous devices: %d", resp.StatusCode)
	}
	resp, body := f.do(t, "POST", "/api/v1/session", map[string]string{"username": "admin", "password": "wrong password for this account", "code": "000000"}, false)
	if resp.StatusCode != 401 || !strings.Contains(string(body), "invalid_credentials") {
		t.Fatalf("bad login: %d %s", resp.StatusCode, body)
	}
	f.login(t)
	if resp, _ := f.do(t, "GET", "/api/v1/session", nil, false); resp.StatusCode != 200 {
		t.Fatalf("session after login: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "DELETE", "/api/v1/session", nil, false); resp.StatusCode != 403 || !strings.Contains(string(body), `"csrf"`) {
		t.Fatalf("logout without CSRF: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "DELETE", "/api/v1/session", nil, true); resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/session", nil, false); resp.StatusCode != 401 {
		t.Fatalf("session after logout: %d", resp.StatusCode)
	}
}

func TestAPIRejectsCrossOriginMutation(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	req, _ := http.NewRequest("POST", f.server.URL+"/api/v1/enrollment-tokens", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", f.csrf)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://attacker.example")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin POST status %d", resp.StatusCode)
	}
}

func TestAPIFleetDashboardAndTypedRevocation(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-ALPHA")

	resp, body := f.do(t, "GET", "/api/v1/devices", nil, false)
	if resp.StatusCode != 200 {
		t.Fatalf("devices: %d %s", resp.StatusCode, body)
	}
	var list struct {
		Devices []struct {
			ID, Hostname, Status string
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list.Devices) != 1 || list.Devices[0].ID != id || list.Devices[0].Status != "awaiting_contact" {
		t.Fatalf("device list %s", body)
	}

	resp, body = f.do(t, "GET", "/api/v1/dashboard", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"awaiting_contact":1`) || !strings.Contains(string(body), `"running":[]`) {
		t.Fatalf("dashboard: %d %s", resp.StatusCode, body)
	}

	resp, body = f.do(t, "GET", "/api/v1/devices/"+id, nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"hostname":"WS-ALPHA"`) {
		t.Fatalf("device detail: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/devices/00000000000000000000000000000000", nil, false); resp.StatusCode != 404 {
		t.Fatalf("missing device: %d", resp.StatusCode)
	}

	if resp, _ := f.do(t, "POST", "/api/v1/devices/"+id+"/revoke", map[string]string{"confirm": "WS-ALPHA"}, false); resp.StatusCode != 403 {
		t.Fatalf("revoke without CSRF: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "POST", "/api/v1/devices/"+id+"/revoke", map[string]string{"confirm": "ws-alpha"}, true); resp.StatusCode != 400 || !strings.Contains(string(body), "confirmation") {
		t.Fatalf("revoke with wrong confirmation: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "POST", "/api/v1/devices/"+id+"/revoke", map[string]string{"confirm": "WS-ALPHA"}, true); resp.StatusCode != 204 {
		t.Fatalf("revoke: %d %s", resp.StatusCode, body)
	}
	d, err := f.store.Device(context.Background(), id)
	if err != nil || d.RevokedAt == nil {
		t.Fatalf("device not revoked: %v", err)
	}

	resp, body = f.do(t, "POST", "/api/v1/enrollment-tokens", map[string]string{}, true)
	if resp.StatusCode != 201 || !strings.Contains(string(body), `"token"`) {
		t.Fatalf("enrollment token: %d %s", resp.StatusCode, body)
	}
}

func TestAPIRejectsMalformedRequests(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-BETA")
	if resp, _ := f.do(t, "POST", "/api/v1/devices/"+id+"/revoke", map[string]any{"confirm": "WS-BETA", "extra": true}, true); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "GET", "/api/v1/nonexistent", nil, false); resp.StatusCode != 404 || !strings.Contains(string(body), "not_found") {
		t.Fatalf("unknown API path: %d %s", resp.StatusCode, body)
	}
}

func TestUIShellCarriesStyleNonce(t *testing.T) {
	f := newAPIFixture(t)
	resp, body := f.do(t, "GET", "/devices/abc", nil, false)
	if _, built := uiFiles(); !built {
		if resp.StatusCode != 503 {
			t.Fatalf("unbuilt UI status %d", resp.StatusCode)
		}
		return
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if resp.StatusCode != 200 || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "'nonce-") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("shell: %d %q", resp.StatusCode, csp)
	}
	nonce := csp[strings.Index(csp, "'nonce-")+7:]
	nonce = nonce[:strings.Index(nonce, "'")]
	if !strings.Contains(string(body), `content="`+nonce+`"`) {
		t.Fatal("page nonce does not match the policy")
	}
	if resp, _ := f.do(t, "GET", "/assets/../index.html", nil, false); resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatal("asset path traversal served")
	}
}

// technicianClient creates and activates a technician with the given access
// and returns a fixture copy signed in as that technician.
func (f *apiFixture) technicianClient(t *testing.T, access storage.TechnicianAccess) *apiFixture {
	t.Helper()
	tech, s := f.namedTechnician(t, strings.Repeat("c", 32), "tech", access)
	if s.Role != "technician" || s.Permissions.Owner || s.Permissions.Events {
		t.Fatalf("technician session %+v", s)
	}
	return tech
}

// namedTechnician creates, confirms and signs in a technician.
func (f *apiFixture) namedTechnician(t *testing.T, id, username string, access storage.TechnicianAccess) (*apiFixture, sessionInfo) {
	t.Helper()
	service := f.auth
	ctx := context.Background()
	c := storage.TechnicianChange{Action: "create", ID: id, Username: username, Enabled: true, Access: access}
	digest, err := service.ReviewTechnician(ctx, c, "admin")
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := service.ApplyTechnician(ctx, c, "admin", digest)
	if err != nil {
		t.Fatal(err)
	}
	p, err := service.BeginTechnician(ctx, invitation, testPassword, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfirmTechnician(ctx, p.Confirmation, totpCode(t, p.Secret, time.Now().Add(-30*time.Second)), "test"); err != nil {
		t.Fatal(err)
	}
	tech := &apiFixture{server: f.server, store: f.store, devices: f.devices, secret: p.Secret}
	tech.client = &http.Client{Transport: f.client.Transport, CheckRedirect: f.client.CheckRedirect}
	tech.client.Jar, _ = cookiejar.New(nil)
	resp, body := tech.do(t, "POST", "/api/v1/session", map[string]string{"username": username, "password": testPassword, "code": totpCode(t, p.Secret, time.Now())}, false)
	if resp.StatusCode != 200 {
		t.Fatalf("technician login %d %s", resp.StatusCode, body)
	}
	var s sessionInfo
	_ = json.Unmarshal(body, &s)
	tech.csrf = s.CSRF
	return tech, s
}

func TestDeviceToolsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-TOOLS")
	base := "/api/v1/devices/" + id

	for _, path := range []string{"/processes", "/service-actions", "/software", "/sessions", "/local-accounts", "/metrics?range=7d", "/updates"} {
		if resp, body := f.do(t, "GET", base+path, nil, false); resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
	}
	if resp, _ := f.do(t, "GET", base+"/metrics?range=1y", nil, false); resp.StatusCode != 400 {
		t.Fatalf("invalid metric range: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "GET", base+"/metrics.csv?range=24h", nil, false); resp.StatusCode != 200 || !strings.HasPrefix(string(body), "device_id,hostname,metric") {
		t.Fatalf("metrics CSV: %d %s", resp.StatusCode, body)
	}

	op := strings.Repeat("1", 32)
	if resp, _ := f.do(t, "POST", base+"/process-actions", map[string]any{"id": op, "pid": 700, "start": "133000000000000000", "name": "lsass.exe"}, true); resp.StatusCode != 400 {
		t.Fatalf("protected process accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/process-actions", map[string]any{"id": op, "pid": 7000, "start": "133000000000000000", "name": "notepad.exe"}, true); resp.StatusCode != 409 {
		t.Fatalf("process action without a fresh snapshot: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/service-actions", map[string]any{"id": op, "service": "OpenRMMAgent", "action": "stop"}, true); resp.StatusCode != 400 {
		t.Fatalf("agent self-stop accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/service-actions", map[string]any{"id": op, "service": "Spooler", "action": "stop"}, true); resp.StatusCode != 409 {
		t.Fatalf("service action without a fresh snapshot: %d", resp.StatusCode)
	}

	now := time.Now().Unix()
	filter := map[string]any{"channel": `C:\Windows\System32\winevt\Logs\Security.evtx`, "from": now - 3600, "to": now, "level": -1, "provider": "", "event_id": -1, "before": 0}
	if resp, _ := f.do(t, "POST", base+"/event-logs", map[string]any{"id": op, "filter": filter}, true); resp.StatusCode != 400 {
		t.Fatalf("file path accepted as a channel: %d", resp.StatusCode)
	}
	// Any channel and page sizes 25/100/250; XPath of the form *[...].
	filter["channel"], filter["limit"] = "Security", 100
	if resp, _ := f.do(t, "POST", base+"/event-logs", map[string]any{"id": op, "filter": filter}, true); resp.StatusCode != 409 {
		t.Fatalf("Security without an availability report: %d", resp.StatusCode)
	}
	for _, bad := range []map[string]any{{"limit": 50}, {"xpath": "*[System] or *[System]"}} {
		v := map[string]any{}
		for k, x := range filter {
			v[k] = x
		}
		for k, x := range bad {
			v[k] = x
		}
		if resp, _ := f.do(t, "POST", base+"/event-logs", map[string]any{"id": op, "filter": v}, true); resp.StatusCode != 400 {
			t.Fatalf("invalid filter %v accepted: %d", bad, resp.StatusCode)
		}
	}
	// Raw XPath needs the response permission.
	reader, _ := f.namedTechnician(t, strings.Repeat("a", 32), "reader", storage.TechnicianAccess{Devices: []string{id}, Events: true})
	filter["xpath"] = "*[EventData[Data[@Name='LogonType']='10']]"
	if resp, _ := reader.do(t, "POST", base+"/event-logs", map[string]any{"id": op, "filter": filter}, true); resp.StatusCode != 403 {
		t.Fatalf("XPath without the response permission: %d", resp.StatusCode)
	}
	delete(filter, "xpath")
	if resp, _ := reader.do(t, "POST", base+"/event-logs", map[string]any{"id": op, "filter": filter}, true); resp.StatusCode != 409 {
		t.Fatalf("structured query by an events reader: %d", resp.StatusCode)
	}

	resp, body := f.do(t, "GET", base+"/updates", nil, false)
	if !strings.Contains(string(body), `"can_scan":false`) {
		t.Fatalf("updates readiness without broker: %s", body)
	}
	if resp, _ = f.do(t, "POST", base+"/updates", map[string]any{"id": op, "action": "scan", "scan_id": "", "updates": []any{}}, true); resp.StatusCode != 409 {
		t.Fatalf("scan without broker: %d", resp.StatusCode)
	}
}

func TestTechnicianDeviceToolBoundaries(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-SCOPED")
	base := "/api/v1/devices/" + id
	tech := f.technicianClient(t, storage.TechnicianAccess{AllDevices: true})
	op := strings.Repeat("2", 32)
	now := time.Now().Unix()
	filter := map[string]any{"channel": "System", "from": now - 3600, "to": now, "level": -1, "provider": "", "event_id": -1, "before": 0}

	if resp, body := tech.do(t, "GET", base, nil, false); resp.StatusCode != 200 {
		t.Fatalf("technician device read: %d %s", resp.StatusCode, body)
	}
	if resp, _ := tech.do(t, "GET", base+"/processes", nil, false); resp.StatusCode != 200 {
		t.Fatalf("technician process read: %d", resp.StatusCode)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", base + "/updates", nil},
		{"POST", base + "/updates", map[string]any{"id": op, "action": "scan", "scan_id": "", "updates": []any{}}},
		{"POST", base + "/event-logs", map[string]any{"id": op, "filter": filter}},
		{"GET", base + "/event-logs/" + op, nil},
		{"POST", base + "/process-actions", map[string]any{"id": op, "pid": 7000, "start": "133000000000000000", "name": "notepad.exe"}},
		{"POST", base + "/service-actions", map[string]any{"id": op, "service": "Spooler", "action": "stop"}},
		{"POST", "/api/v1/enrollment-tokens", map[string]any{}},
		{"POST", base + "/revoke", map[string]any{"confirm": "WS-SCOPED"}},
	} {
		if resp, body := tech.do(t, c.method, c.path, c.body, c.method != "GET"); resp.StatusCode != 403 {
			t.Fatalf("technician %s %s: %d %s", c.method, c.path, resp.StatusCode, body)
		}
	}

	// The owner's event query is not readable by a technician without Events.
	if resp, body := f.do(t, "POST", base+"/event-logs", map[string]any{"id": op, "filter": filter}, true); resp.StatusCode != 409 && resp.StatusCode != 202 {
		t.Fatalf("owner event query: %d %s", resp.StatusCode, body)
	}
	if resp, _ := tech.do(t, "GET", base+"/event-logs/"+op, nil, false); resp.StatusCode != 403 {
		t.Fatalf("technician read owner's event results: %d", resp.StatusCode)
	}
}

func TestLiveToolsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-LIVE")
	base := "/api/v1/devices/" + id

	// No agent is connected, so sessions cannot start; nothing is created.
	if resp, body := f.do(t, "POST", base+"/terminal", map[string]any{}, true); resp.StatusCode != 409 {
		t.Fatalf("terminal without agent: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "POST", base+"/desktop", map[string]any{"mode": "control"}, true); resp.StatusCode != 409 {
		t.Fatalf("desktop without companion: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", base+"/desktop", map[string]any{"mode": "admin"}, true); resp.StatusCode != 400 {
		t.Fatalf("invalid desktop mode: %d", resp.StatusCode)
	}
	unknown := strings.Repeat("e", 32)
	for _, p := range []string{"/api/v1/terminal/" + unknown + "/output?after=0", "/api/v1/desktop/" + unknown, "/api/v1/desktop/" + unknown + "/frame"} {
		if resp, _ := f.do(t, "GET", p, nil, false); resp.StatusCode != 404 {
			t.Fatalf("unknown session %s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := f.do(t, "POST", "/api/v1/terminal/"+unknown+"/stop", nil, true); resp.StatusCode != 204 {
		t.Fatalf("stopping an ended session should be harmless: %d", resp.StatusCode)
	}

	resp, body := f.do(t, "GET", base+"/files", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"available":false`) {
		t.Fatalf("files without support: %d %s", resp.StatusCode, body)
	}
	op := strings.Repeat("3", 32)
	if resp, _ := f.do(t, "POST", base+"/files", map[string]any{"id": op, "operation": "list", "root": "docs", "path": "../etc"}, true); resp.StatusCode != 400 {
		t.Fatalf("path traversal accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/files", map[string]any{"id": op, "operation": "upload", "root": "docs", "path": "a.txt"}, true); resp.StatusCode != 400 {
		t.Fatalf("upload through JSON accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/files", map[string]any{"id": op, "operation": "list", "root": "docs", "path": "."}, true); resp.StatusCode != 409 {
		t.Fatalf("listing without a shared folder: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", base+"/files/"+op+"/download", nil, false); resp.StatusCode != 410 {
		t.Fatalf("missing download: %d", resp.StatusCode)
	}
}

func TestTechnicianLiveToolBoundaries(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-LIVE-SCOPED")
	base := "/api/v1/devices/" + id
	tech := f.technicianClient(t, storage.TechnicianAccess{AllDevices: true})
	unknown := strings.Repeat("e", 32)
	for _, c := range []struct{ method, path string }{
		{"POST", base + "/terminal"},
		{"GET", "/api/v1/terminal/" + unknown + "/output?after=0"},
		{"POST", base + "/desktop"},
		{"GET", "/api/v1/desktop/" + unknown + "/frame"},
		{"POST", "/api/v1/desktop/" + unknown + "/input"},
		{"GET", base + "/files"},
		{"GET", base + "/files/" + unknown + "/download"},
	} {
		var body any
		if c.method == "POST" {
			body = map[string]any{"mode": "view"}
		}
		if resp, out := tech.do(t, c.method, c.path, body, c.method == "POST"); resp.StatusCode != 403 {
			t.Fatalf("technician %s %s: %d %s", c.method, c.path, resp.StatusCode, out)
		}
	}
}

func TestScriptsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-SCRIPTS")
	def := map[string]any{"name": "Show date", "description": "", "body": "param([string]$Format)\nGet-Date -Format $Format", "parameters": []map[string]any{{"name": "Format", "description": "", "required": true}}, "timeout_seconds": 30, "run_as": "restricted"}
	if resp, _ := f.do(t, "POST", "/api/v1/scripts/versions", map[string]any{"definition": map[string]any{"name": "Bad", "description": "", "body": "x", "parameters": []map[string]any{{"name": "Verbose", "description": "", "required": false}}, "timeout_seconds": 30, "run_as": "restricted"}}, true); resp.StatusCode != 400 {
		t.Fatalf("reserved parameter accepted: %d", resp.StatusCode)
	}
	resp, body := f.do(t, "POST", "/api/v1/scripts/versions", map[string]any{"definition": def}, true)
	if resp.StatusCode != 201 {
		t.Fatalf("create script: %d %s", resp.StatusCode, body)
	}
	var v struct {
		ID       string `json:"id"`
		ScriptID string `json:"script_id"`
		Number   int    `json:"number"`
	}
	_ = json.Unmarshal(body, &v)
	resp, body = f.do(t, "POST", "/api/v1/scripts/versions", map[string]any{"script_id": v.ScriptID, "definition": def}, true)
	if resp.StatusCode != 201 || !strings.Contains(string(body), `"number":2`) {
		t.Fatalf("second version: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "GET", "/api/v1/scripts", nil, false); resp.StatusCode != 200 || strings.Count(string(body), `"script_id"`) != 1 {
		t.Fatalf("library should list the latest version once: %d %s", resp.StatusCode, body)
	}

	base := "/api/v1/devices/" + id
	op := strings.Repeat("4", 32)
	if resp, _ := f.do(t, "POST", base+"/script-runs", map[string]any{"id": op, "version": v.ID, "arguments": map[string]string{}}, true); resp.StatusCode != 400 {
		t.Fatalf("missing required argument accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/script-runs", map[string]any{"id": op, "version": v.ID, "arguments": map[string]string{"Format": "s", "Other": "x"}}, true); resp.StatusCode != 400 {
		t.Fatalf("undeclared argument accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/script-runs", map[string]any{"id": op, "version": v.ID, "arguments": map[string]string{"Format": "s"}}, true); resp.StatusCode != 409 {
		t.Fatalf("run without script support: %d", resp.StatusCode)
	}

	sched := strings.Repeat("5", 32)
	now := time.Now().Unix()
	if resp, _ := f.do(t, "POST", base+"/script-schedules", map[string]any{"id": sched, "revision": 0, "version": v.ID, "name": "Daily date", "start_at": now - 60, "interval_seconds": 86400, "arguments": map[string]string{"Format": "s"}}, true); resp.StatusCode != 400 {
		t.Fatalf("past start accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", base+"/script-schedules", map[string]any{"id": sched, "revision": 0, "version": v.ID, "name": "Daily date", "start_at": now + 3600, "interval_seconds": 120, "arguments": map[string]string{"Format": "s"}}, true); resp.StatusCode != 400 {
		t.Fatalf("too-short interval accepted: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "POST", base+"/script-schedules", map[string]any{"id": sched, "revision": 0, "version": v.ID, "name": "Daily date", "start_at": now + 3600, "interval_seconds": 86400, "arguments": map[string]string{"Format": "s"}}, true); resp.StatusCode != 200 {
		t.Fatalf("save schedule: %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", "/api/v1/script-schedules", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"hostname":"WS-SCRIPTS"`) || !strings.Contains(string(body), `"script_name":"Show date"`) {
		t.Fatalf("fleet schedules: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "POST", base+"/script-schedules/"+sched+"/state", map[string]any{"action": "pause", "revision": 1}, true); resp.StatusCode != 204 {
		t.Fatalf("pause: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", base+"/script-schedules/"+sched+"/state", map[string]any{"action": "pause", "revision": 1}, true); resp.StatusCode != 409 {
		t.Fatalf("stale revision accepted: %d", resp.StatusCode)
	}

	change := map[string]any{"id": strings.Repeat("6", 32), "version_id": v.ID, "name": "Fleet date", "devices": []string{id}, "groups": []string{}, "arguments": map[string]string{"Format": "s"}}
	resp, body = f.do(t, "POST", "/api/v1/script-batches/review", map[string]any{"change": change, "digest": ""}, true)
	if resp.StatusCode == 200 {
		if !strings.Contains(string(body), `"problems":{"`) {
			t.Fatalf("review of an unready device should report a problem: %s", body)
		}
	} else if resp.StatusCode != 409 {
		t.Fatalf("batch review: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/script-batches/apply", map[string]any{"change": change, "digest": "short"}, true); resp.StatusCode != 409 {
		t.Fatalf("apply without a reviewed digest: %d", resp.StatusCode)
	}

	tech := f.technicianClient(t, storage.TechnicianAccess{AllDevices: true})
	for _, p := range []string{"/api/v1/scripts", "/api/v1/script-schedules", "/api/v1/script-batches", base + "/scripts"} {
		if resp, _ := tech.do(t, "GET", p, nil, false); resp.StatusCode != 403 {
			t.Fatalf("technician GET %s: %d", p, resp.StatusCode)
		}
	}
}

func TestAlertsAndHealthAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-ALERTS")

	if resp, body := f.do(t, "GET", "/api/v1/alerts?status=active", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"alerts":[]`) {
		t.Fatalf("alerts: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/alerts?status=bogus", nil, false); resp.StatusCode != 400 {
		t.Fatalf("invalid filter accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/alerts/"+strings.Repeat("7", 32), nil, false); resp.StatusCode != 404 {
		t.Fatalf("unknown alert: %d", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/alerts/"+strings.Repeat("7", 32)+"/acknowledge", nil, true); resp.StatusCode != 409 {
		t.Fatalf("acknowledge unknown alert: %d", resp.StatusCode)
	}

	resp, body := f.do(t, "GET", "/api/v1/alert-settings", nil, false)
	if resp.StatusCode != 200 {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	var settings struct {
		Rules []map[string]any `json:"rules"`
	}
	_ = json.Unmarshal(body, &settings)
	var cpu map[string]any
	for _, r := range settings.Rules {
		if r["kind"] == "cpu" {
			cpu = r
		}
	}
	if cpu == nil {
		t.Fatalf("no cpu rule in %s", body)
	}
	bad := map[string]any{}
	for k, v := range cpu {
		bad[k] = v
	}
	bad["threshold"] = 150
	if resp, _ := f.do(t, "POST", "/api/v1/alert-settings/rules/cpu", bad, true); resp.StatusCode != 400 {
		t.Fatalf("invalid rule accepted: %d", resp.StatusCode)
	}
	cpu["threshold"] = 85
	if resp, body := f.do(t, "POST", "/api/v1/alert-settings/rules/cpu", cpu, true); resp.StatusCode != 204 {
		t.Fatalf("save rule: %d %s", resp.StatusCode, body)
	}
	// An identical resubmission is a harmless no-op; a different change based
	// on the old revision is refused.
	if resp, _ := f.do(t, "POST", "/api/v1/alert-settings/rules/cpu", cpu, true); resp.StatusCode != 204 {
		t.Fatalf("identical resubmission: %d", resp.StatusCode)
	}
	cpu["threshold"] = 70
	if resp, _ := f.do(t, "POST", "/api/v1/alert-settings/rules/cpu", cpu, true); resp.StatusCode != 409 {
		t.Fatalf("stale rule revision accepted: %d", resp.StatusCode)
	}

	check := map[string]any{"id": strings.Repeat("8", 32), "device_id": id, "name": "Print spooler", "kind": "service_running", "service": "Spooler", "enabled": true, "hold_seconds": 120, "recovery_seconds": 60, "severity": "warning", "email": false, "response": false, "cooldown_seconds": 3600, "revision": 0}
	if resp, _ := f.do(t, "POST", "/api/v1/health-checks/apply", map[string]any{"change": map[string]any{"check": check, "rearm": false}, "digest": ""}, true); resp.StatusCode != 400 {
		t.Fatalf("apply without review accepted: %d", resp.StatusCode)
	}
	resp, body = f.do(t, "POST", "/api/v1/health-checks/review", map[string]any{"change": map[string]any{"check": check, "rearm": false}, "digest": ""}, true)
	if resp.StatusCode != 200 {
		t.Fatalf("review check: %d %s", resp.StatusCode, body)
	}
	var review struct {
		Digest string `json:"digest"`
	}
	_ = json.Unmarshal(body, &review)
	if resp, body := f.do(t, "POST", "/api/v1/health-checks/apply", map[string]any{"change": map[string]any{"check": check, "rearm": false}, "digest": review.Digest}, true); resp.StatusCode != 200 {
		t.Fatalf("apply check: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "GET", "/api/v1/health-checks", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"name":"Print spooler"`) {
		t.Fatalf("health list: %d %s", resp.StatusCode, body)
	}

	tech := f.technicianClient(t, storage.TechnicianAccess{AllDevices: true})
	if resp, body := tech.do(t, "GET", "/api/v1/health-checks", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), "Print spooler") {
		t.Fatalf("technician health read: %d %s", resp.StatusCode, body)
	}
	if resp, _ := tech.do(t, "GET", "/api/v1/alerts", nil, false); resp.StatusCode != 200 {
		t.Fatalf("technician alerts read: %d", resp.StatusCode)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/alert-settings", nil},
		{"POST", "/api/v1/alert-settings/mail", map[string]any{"paused": true}},
		{"POST", "/api/v1/alerts/" + strings.Repeat("7", 32) + "/acknowledge", map[string]any{}},
		{"POST", "/api/v1/health-checks/review", map[string]any{"change": map[string]any{"check": check, "rearm": false}, "digest": ""}},
	} {
		if resp, _ := tech.do(t, c.method, c.path, c.body, c.method == "POST"); resp.StatusCode != 403 {
			t.Fatalf("technician %s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestOperationsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id := f.enroll(t, "WS-PATCH")

	if resp, body := f.do(t, "GET", "/api/v1/patch-policies", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"policies":[]`) {
		t.Fatalf("patch policies: %d %s", resp.StatusCode, body)
	}
	policy := map[string]any{"action": "save", "id": strings.Repeat("a", 32), "revision": 0, "enabled": false, "groups": []string{},
		"definition": map[string]any{"name": "Pilot", "ring": "pilot", "devices": []string{id}, "weekday": 2, "minute_utc": 120, "duration_minutes": 60, "install": false, "approved_kb": []string{}, "restart_after_deferral": false, "defer_hours": 24}}
	if resp, _ := f.do(t, "POST", "/api/v1/patch-policies/apply", policy, true); resp.StatusCode != 409 {
		t.Fatalf("apply without review accepted: %d", resp.StatusCode)
	}
	resp, body := f.do(t, "POST", "/api/v1/patch-policies/review", policy, true)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"hostname":"WS-PATCH"`) {
		t.Fatalf("review policy: %d %s", resp.StatusCode, body)
	}
	var review struct {
		Digest string `json:"digest"`
	}
	_ = json.Unmarshal(body, &review)
	policy["digest"] = strings.Repeat("0", 64)
	if resp, _ := f.do(t, "POST", "/api/v1/patch-policies/apply", policy, true); resp.StatusCode != 409 {
		t.Fatalf("wrong digest accepted: %d", resp.StatusCode)
	}
	policy["digest"] = review.Digest
	if resp, body := f.do(t, "POST", "/api/v1/patch-policies/apply", policy, true); resp.StatusCode != 200 {
		t.Fatalf("apply policy: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "GET", "/api/v1/patch-policies", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"state":"paused"`) {
		t.Fatalf("saved policy: %d %s", resp.StatusCode, body)
	}
	// Re-applying the same review is stale: the policy revision moved on.
	if resp, _ := f.do(t, "POST", "/api/v1/patch-policies/apply", policy, true); resp.StatusCode != 409 {
		t.Fatalf("replayed policy accepted: %d", resp.StatusCode)
	}
	resume := map[string]any{"action": "resume", "id": strings.Repeat("a", 32), "revision": 1}
	resp, body = f.do(t, "POST", "/api/v1/patch-policies/review", resume, true)
	_ = json.Unmarshal(body, &review)
	resume["digest"] = review.Digest
	if resp, body := f.do(t, "POST", "/api/v1/patch-policies/apply", resume, true); resp.StatusCode != 200 || !strings.Contains(string(body), `"state":"active"`) {
		t.Fatalf("resume policy: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/patch-guards/"+id+"/review", map[string]any{"action": "acknowledge", "revision": 0}, true); resp.StatusCode != 409 {
		t.Fatalf("acknowledge without hold: %d", resp.StatusCode)
	}

	if resp, body := f.do(t, "GET", "/api/v1/applications", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `{"revision":1,"versions":[]}`) {
		t.Fatalf("catalog: %d %s", resp.StatusCode, body)
	}
	app := map[string]any{"id": strings.Repeat("b", 32), "application_id": strings.Repeat("c", 32), "revision": 1,
		"definition": map[string]any{"name": "7-Zip", "description": "", "version": "24.9.0", "product_code": "{23170f69-40c1-2702-2409-000001000000}", "url": "https://example.test/7z.msi", "sha256": strings.Repeat("A", 64)}}
	resp, body = f.do(t, "POST", "/api/v1/applications/review", app, true)
	if resp.StatusCode != 200 {
		t.Fatalf("review app: %d %s", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &review)
	app["digest"] = review.Digest
	if resp, body := f.do(t, "POST", "/api/v1/applications/apply", app, true); resp.StatusCode != 200 {
		t.Fatalf("apply app: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "GET", "/api/v1/applications", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"product_code":"{23170F69-40C1-2702-2409-000001000000}"`) {
		t.Fatalf("catalog after save: %d %s", resp.StatusCode, body)
	}
	// Review resolves targets; the device never reported, so apply refuses it.
	deploy := map[string]any{"change": map[string]any{"id": strings.Repeat("d", 32), "version_id": strings.Repeat("b", 32), "operation": "install", "devices": []string{id}}, "digest": ""}
	resp, body = f.do(t, "POST", "/api/v1/deployments/review", deploy, true)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"hostname":"WS-PATCH"`) {
		t.Fatalf("review deployment: %d %s", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &review)
	if resp, _ := f.do(t, "POST", "/api/v1/deployments/apply", map[string]any{"change": deploy["change"], "digest": review.Digest}, true); resp.StatusCode != 409 {
		t.Fatalf("deploy to unready device: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "GET", "/api/v1/deployments?device="+id, nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"deployments":[]`) {
		t.Fatalf("deployments: %d %s", resp.StatusCode, body)
	}

	if resp, body := f.do(t, "GET", "/api/v1/agent-releases", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"releases":[]`) {
		t.Fatalf("releases: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/agent-releases", map[string]any{}, true); resp.StatusCode != 400 {
		t.Fatalf("non-multipart release accepted: %d", resp.StatusCode)
	}
	if resp, body := f.do(t, "GET", "/api/v1/agent-upgrades?device="+id, nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"jobs":[]`) {
		t.Fatalf("agent upgrades: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/agent-rollouts/review", map[string]any{"change": map[string]any{"id": strings.Repeat("e", 32), "release_id": strings.Repeat("f", 64), "devices": []string{id}}}, true); resp.StatusCode != 409 {
		t.Fatalf("rollout of unknown release: %d", resp.StatusCode)
	}

	tech := f.technicianClient(t, storage.TechnicianAccess{AllDevices: true})
	for _, path := range []string{"/api/v1/deployments", "/api/v1/agent-upgrades", "/api/v1/deployments?device=" + id} {
		if resp, _ := tech.do(t, "GET", path, nil, false); resp.StatusCode != 200 {
			t.Fatalf("technician %s: %d", path, resp.StatusCode)
		}
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/patch-policies", nil},
		{"POST", "/api/v1/patch-policies/review", policy},
		{"POST", "/api/v1/patch-guards/" + id + "/review", map[string]any{"action": "acknowledge"}},
		{"GET", "/api/v1/applications", nil},
		{"POST", "/api/v1/applications/review", app},
		{"POST", "/api/v1/deployments/review", deploy},
		{"POST", "/api/v1/deployments/" + strings.Repeat("d", 32) + "/cancel", map[string]any{}},
		{"GET", "/api/v1/agent-releases", nil},
		{"POST", "/api/v1/agent-releases/" + strings.Repeat("f", 64) + "/withdraw", map[string]any{}},
		{"POST", "/api/v1/agent-rollouts/review", map[string]any{}},
		{"POST", "/api/v1/agent-upgrades/" + strings.Repeat("e", 32) + "/cancel", map[string]any{}},
	} {
		if resp, _ := tech.do(t, c.method, c.path, c.body, c.method == "POST"); resp.StatusCode != 403 {
			t.Fatalf("technician %s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestReportsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	first := f.enroll(t, "WS-REPORT-1")
	second := f.enroll(t, "=WS-REPORT-2")

	resp, body := f.do(t, "GET", "/api/v1/reports/metrics?range=7d", nil, false)
	var metrics struct {
		Window  storage.MetricWindow `json:"window"`
		Devices []struct {
			ID      string                    `json:"id"`
			Metrics map[string]map[string]any `json:"metrics"`
		} `json:"devices"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &metrics) != nil || metrics.Window.Range != "7d" || len(metrics.Devices) != 2 || len(metrics.Devices[0].Metrics) != 3 {
		t.Fatalf("metrics report: %d %s", resp.StatusCode, body)
	}
	for _, bad := range []string{"range=1y", "range=24h&range=7d", "group=" + strings.Repeat("x", 80), "unknown=1"} {
		if resp, _ := f.do(t, "GET", "/api/v1/reports/metrics?"+bad, nil, false); resp.StatusCode != 400 {
			t.Fatalf("metrics filter %q accepted: %d", bad, resp.StatusCode)
		}
	}
	resp, body = f.do(t, "GET", "/api/v1/reports/metrics.csv?range=24h", nil, false)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") || strings.Count(string(body), "\n") != 7 || !strings.Contains(string(body), first) {
		t.Fatalf("metrics csv: %d %s", resp.StatusCode, body)
	}
	// Spreadsheet formulas in device-controlled text are neutralized.
	if !strings.Contains(string(body), "'=WS-REPORT-2") {
		t.Fatalf("csv formula not neutralized: %s", body)
	}

	resp, body = f.do(t, "GET", "/api/v1/reports/software?q=chrome", nil, false)
	if resp.StatusCode != 200 || strings.Count(string(body), `"result":"unknown"`) != 2 {
		t.Fatalf("software report: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "GET", "/api/v1/reports/software?q=chrome&result=current", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"devices":[]`) {
		t.Fatalf("software result filter: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/reports/software?result=maybe", nil, false); resp.StatusCode != 400 {
		t.Fatalf("software filter accepted: %d", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", "/api/v1/reports/software.csv?q=chrome", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "matching_registrations") || !strings.Contains(string(body), second) {
		t.Fatalf("software csv: %d %s", resp.StatusCode, body)
	}

	tech := f.technicianClient(t, storage.TechnicianAccess{Devices: []string{first}})
	resp, body = tech.do(t, "GET", "/api/v1/reports/metrics", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), first) || strings.Contains(string(body), second) {
		t.Fatalf("technician metrics scope: %d %s", resp.StatusCode, body)
	}
	resp, body = tech.do(t, "GET", "/api/v1/reports/software.csv", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), first) || strings.Contains(string(body), second) {
		t.Fatalf("technician software scope: %d %s", resp.StatusCode, body)
	}

	// The device list as CSV, scoped and with formulas neutralized.
	resp, body = f.do(t, "GET", "/api/v1/reports/devices.csv", nil, false)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "as_of_utc,device_id,hostname") || !strings.Contains(string(body), first) || !strings.Contains(string(body), "'=WS-REPORT-2") {
		t.Fatalf("devices csv: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/reports/devices.csv?status=online", nil, false); resp.StatusCode != 400 {
		t.Fatalf("devices csv accepted a filter: %d", resp.StatusCode)
	}
	resp, body = tech.do(t, "GET", "/api/v1/reports/devices.csv", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), first) || strings.Contains(string(body), second) {
		t.Fatalf("technician devices csv scope: %d %s", resp.StatusCode, body)
	}
}

func TestAdminAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	first := f.enroll(t, "WS-ORG-1")
	second := f.enroll(t, "WS-ORG-2")

	var org struct {
		Revision int64 `json:"revision"`
		Devices  []struct {
			ID      string   `json:"id"`
			GroupID string   `json:"group_id"`
			Tags    []string `json:"tags"`
			Source  string   `json:"policy_source"`
		} `json:"devices"`
	}
	read := func() {
		t.Helper()
		resp, body := f.do(t, "GET", "/api/v1/organization", nil, false)
		if resp.StatusCode != 200 || json.Unmarshal(body, &org) != nil {
			t.Fatalf("organization: %d %s", resp.StatusCode, body)
		}
	}
	change := func(c map[string]any) (int, string) {
		t.Helper()
		read()
		c["revision"] = org.Revision
		resp, body := f.do(t, "POST", "/api/v1/organization/review", map[string]any{"change": c}, true)
		if resp.StatusCode != 200 {
			return resp.StatusCode, string(body)
		}
		var review struct {
			Digest string `json:"digest"`
		}
		_ = json.Unmarshal(body, &review)
		resp, body = f.do(t, "POST", "/api/v1/organization/apply", map[string]any{"change": c, "digest": review.Digest}, true)
		return resp.StatusCode, string(body)
	}
	if status, body := change(map[string]any{"action": "group-create", "id": "lab", "name": "Lab"}); status != 200 {
		t.Fatal("group create", status, body)
	}
	if status, body := change(map[string]any{"action": "devices", "devices": []string{first, second}, "set_group": true, "group_id": "lab", "add_tags": []string{"pilot"}}); status != 200 {
		t.Fatal("bulk", status, body)
	}
	read()
	for _, d := range org.Devices {
		if d.GroupID != "lab" || len(d.Tags) != 1 || d.Tags[0] != "pilot" || d.Source == "" {
			t.Fatal("bulk result", d)
		}
	}
	if status, _ := change(map[string]any{"action": "device", "id": first, "group_id": "", "tags": []string{}}); status != 200 {
		t.Fatal("single device", status)
	}
	if status, _ := change(map[string]any{"action": "group-delete", "id": "lab"}); status != 409 {
		t.Fatal("group with members deleted", status)
	}
	read()
	stale := map[string]any{"action": "group-create", "id": "other", "name": "Other", "revision": org.Revision - 1}
	if resp, _ := f.do(t, "POST", "/api/v1/organization/review", map[string]any{"change": stale}, true); resp.StatusCode != 409 {
		t.Fatal("stale revision", resp.StatusCode)
	}

	techID := strings.Repeat("9", 32)
	tc := map[string]any{"action": "create", "id": techID, "username": "helpdesk", "revision": 0, "enabled": true, "access": map[string]any{"groups": []string{"lab"}, "services": true}}
	resp, body := f.do(t, "POST", "/api/v1/technicians/review", map[string]any{"change": tc}, true)
	var review struct {
		Digest     string `json:"digest"`
		Invitation string `json:"invitation"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &review) != nil || len(review.Digest) != 64 {
		t.Fatalf("technician review: %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "POST", "/api/v1/technicians/apply", map[string]any{"change": tc, "digest": review.Digest}, true)
	if resp.StatusCode != 200 || json.Unmarshal(body, &review) != nil || review.Invitation == "" {
		t.Fatalf("technician apply: %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "GET", "/api/v1/technicians", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"pending_activation":true`) {
		t.Fatalf("technician list: %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/activation/begin", map[string]any{"invitation": "wrong", "password": testPassword}, false); resp.StatusCode != 400 {
		t.Fatal("bad invitation", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/activation/begin", map[string]any{"invitation": review.Invitation, "password": "short"}, false); resp.StatusCode != 400 {
		t.Fatal("short password", resp.StatusCode)
	}
	resp, body = f.do(t, "POST", "/api/v1/activation/begin", map[string]any{"invitation": review.Invitation, "password": testPassword}, false)
	var provision struct {
		Secret        string   `json:"secret"`
		URI           string   `json:"uri"`
		RecoveryCodes []string `json:"recovery_codes"`
		Confirmation  string   `json:"confirmation"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &provision) != nil || provision.Secret == "" || provision.Confirmation == "" || len(provision.RecoveryCodes) == 0 {
		t.Fatalf("activation begin: %d %s", resp.StatusCode, body)
	}
	// S3: the one-time confirmation code must not restart activation (which
	// would let its holder replace the password and authenticator).
	if resp, _ := f.do(t, "POST", "/api/v1/activation/begin", map[string]any{"invitation": provision.Confirmation, "password": testPassword}, false); resp.StatusCode != 400 {
		t.Fatal("confirmation code accepted as an invitation", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/activation/confirm", map[string]any{"confirmation": provision.Confirmation, "code": "000000"}, false); resp.StatusCode != 400 {
		t.Fatal("wrong code", resp.StatusCode)
	}
	code := totpCode(t, provision.Secret, time.Now().Add(-30*time.Second))
	if resp, body := f.do(t, "POST", "/api/v1/activation/confirm", map[string]any{"confirmation": provision.Confirmation, "code": code}, false); resp.StatusCode != 204 {
		t.Fatalf("activation confirm: %d %s", resp.StatusCode, body)
	}
	tech := &apiFixture{server: f.server, store: f.store, devices: f.devices}
	tech.client = &http.Client{Transport: f.client.Transport, CheckRedirect: f.client.CheckRedirect}
	tech.client.Jar, _ = cookiejar.New(nil)
	resp, body = tech.do(t, "POST", "/api/v1/session", map[string]string{"username": "helpdesk", "password": testPassword, "code": totpCode(t, provision.Secret, time.Now())}, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"role":"technician"`) {
		t.Fatalf("technician login: %d %s", resp.StatusCode, body)
	}
	var s sessionInfo
	_ = json.Unmarshal(body, &s)
	tech.csrf = s.CSRF
	// The group grant scopes the device list to group members (only second is left in "lab").
	if resp, body := tech.do(t, "GET", "/api/v1/devices", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), second) || strings.Contains(string(body), first) {
		t.Fatalf("technician scope: %d %s", resp.StatusCode, body)
	}
	for _, c := range []struct{ method, path string }{{"GET", "/api/v1/organization"}, {"POST", "/api/v1/organization/review"}, {"GET", "/api/v1/technicians"}, {"POST", "/api/v1/technicians/review"}} {
		if resp, _ := tech.do(t, c.method, c.path, map[string]any{}, c.method == "POST"); resp.StatusCode != 403 {
			t.Fatalf("technician %s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
	// A group referenced by a technician grant can't be deleted.
	if status, _ := change(map[string]any{"action": "devices", "devices": []string{second}, "set_group": true, "group_id": ""}); status != 200 {
		t.Fatal("ungroup", status)
	}
	if status, _ := change(map[string]any{"action": "group-delete", "id": "lab"}); status != 409 {
		t.Fatal("granted group deleted", status)
	}
}
