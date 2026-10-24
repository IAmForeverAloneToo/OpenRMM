package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
)

// secondSession signs the same administrator in again (with a recovery code)
// in a separate cookie jar: a different browser session of the same account.
func (f *apiFixture) secondSession(t *testing.T) *apiFixture {
	t.Helper()
	other := &apiFixture{server: f.server, store: f.store, devices: f.devices, auth: f.auth}
	other.client = &http.Client{Transport: f.client.Transport, CheckRedirect: f.client.CheckRedirect}
	other.client.Jar, _ = cookiejar.New(nil)
	code := f.recovery[0]
	f.recovery = f.recovery[1:]
	resp, body := other.do(t, "POST", "/api/v1/session", map[string]string{"username": "admin", "password": testPassword, "code": code}, false)
	if resp.StatusCode != 200 {
		t.Fatalf("second session %d %s", resp.StatusCode, body)
	}
	var s sessionInfo
	_ = json.Unmarshal(body, &s)
	other.csrf = s.CSRF
	return other
}

// agentRelay enrolls a device and returns its ID plus a poster for the
// certificate-only device listener.
func (f *apiFixture) agentRelay(t *testing.T, hostname string) (string, func(path string, v any) []byte) {
	t.Helper()
	token, _, e := f.devices.NewToken(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	key, e := deviceidentity.NewKey()
	if e != nil {
		t.Fatal(e)
	}
	csr, _ := deviceidentity.CSR(key)
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: hostname, OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	kpem, _ := deviceidentity.KeyPEM(key)
	pair, e := tls.X509KeyPair([]byte(cred.Certificate), kpem)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(DeviceHandler(f.devices))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.devices.Roots()}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{pair}
	t.Cleanup(tr.CloseIdleConnections)
	client.Transport = tr
	return cred.DeviceID, func(path string, v any) []byte {
		t.Helper()
		b, _ := json.Marshal(v)
		r, e := client.Post(server.URL+path, "application/json", bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		body := readResponse(t, r)
		if r.StatusCode != 200 {
			t.Fatal("device exchange", path, r.StatusCode, body)
		}
		return []byte(body)
	}
}

func TestTerminalRelayOwnershipCSRFRevocationAndMemoryOnlyOutput(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	second := f.secondSession(t)
	id, post := f.agentRelay(t, "<test terminal>")
	peer := "22222222222222222222222222222222"
	exchange := func(p terminal.Exchange) terminal.Reply {
		t.Helper()
		var v terminal.Reply
		if e := json.Unmarshal(post("/api/v1/agent/terminal", p), &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	anonymous := &apiFixture{server: f.server, client: &http.Client{Transport: f.client.Transport}}
	if resp, _ := anonymous.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{}, false); resp.StatusCode != 401 {
		t.Fatal("anonymous start", resp.StatusCode)
	}
	p := terminal.Exchange{Peer: peer, Identity: "S-1-5-19"}
	exchange(p)
	saved := f.csrf
	f.csrf = "bad"
	if resp, _ := f.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{}, true); resp.StatusCode != 403 {
		t.Fatal("start CSRF", resp.StatusCode)
	}
	f.csrf = saved
	resp, body := f.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{}, true)
	var created struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &created) != nil || created.ID == "" {
		t.Fatalf("create %d %s", resp.StatusCode, body)
	}
	session := "/api/v1/terminal/" + created.ID
	if resp, _ := anonymous.do(t, "GET", session+"/output?after=0", nil, false); resp.StatusCode != 401 {
		t.Fatal("anonymous output", resp.StatusCode)
	}
	if resp, _ := second.do(t, "GET", session+"/output?after=0", nil, false); resp.StatusCode != 404 {
		t.Fatal("another browser session read the output", resp.StatusCode)
	}
	q := exchange(p)
	if q.Request == nil {
		t.Fatal("missing request")
	}
	p.ID, p.State, p.Sequence = q.Request.ID, "active", 1
	p.Output = []byte("<script>never execute</script>\x1b]52;c;no clipboard\x07")
	exchange(p)
	resp, body = f.do(t, "GET", session+"/output?after=0", nil, false)
	var v terminal.View
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || string(v.Output) != string(p.Output) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("literal output %d", resp.StatusCode)
	}
	input := map[string]any{"sequence": 1, "data": "diagnostic\r"}
	f.csrf = "bad"
	if resp, _ := f.do(t, "POST", session+"/input", input, true); resp.StatusCode != 403 {
		t.Fatal("input CSRF", resp.StatusCode)
	}
	f.csrf = saved
	// Another session of the same account, with its own valid CSRF token, still
	// does not own this terminal.
	if resp, _ := second.do(t, "POST", session+"/input", input, true); resp.StatusCode != 404 {
		t.Fatal("foreign input", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", session+"/input", input, true); resp.StatusCode != 204 {
		t.Fatal("input", resp.StatusCode)
	}
	p.Output = nil
	if q = exchange(p); len(q.Inputs) != 1 || q.Inputs[0].Data != "diagnostic\r" {
		t.Fatal("live input")
	}
	if len(exchange(p).Inputs) != 0 {
		t.Fatal("input replay")
	}
	if resp, _ := f.do(t, "POST", session+"/input", map[string]any{"sequence": 2, "data": "x", "extra": true}, true); resp.StatusCode != 400 {
		t.Fatal("unknown JSON field", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", session+"/output?after="+strconv.FormatUint(v.Offset, 10), nil, false)
	v = terminal.View{}
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || len(v.Output) != 0 {
		t.Fatal("erased output", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", session+"/stop", nil, true); resp.StatusCode != 204 {
		t.Fatal("stop", resp.StatusCode)
	}
	if resp, body := f.do(t, "GET", session+"/output?after=0", nil, false); resp.StatusCode != 410 || !strings.Contains(string(body), `"reason":"administrator_stopped"`) {
		t.Fatalf("owner ending %d %s", resp.StatusCode, body)
	}
	if resp, body := second.do(t, "GET", session+"/output?after=0", nil, false); resp.StatusCode != 404 || strings.Contains(string(body), "reason") {
		t.Fatalf("foreign ending leak %d %s", resp.StatusCode, body)
	}

	// Revocation ends a live shell, separately from ending metadata.
	resp, body = f.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{}, true)
	if resp.StatusCode != 201 || json.Unmarshal(body, &created) != nil {
		t.Fatalf("new terminal %d %s", resp.StatusCode, body)
	}
	session = "/api/v1/terminal/" + created.ID
	p.ID, p.State, p.Sequence, p.Output = "", "", 0, nil
	if q = exchange(p); q.Request == nil {
		t.Fatal("missing fresh terminal")
	}
	p.ID, p.State = q.Request.ID, "active"
	exchange(p)
	if e := f.store.RevokeDevice(t.Context(), id, time.Now()); e != nil {
		t.Fatal(e)
	}
	if resp, body := f.do(t, "GET", session+"/output?after=0", nil, false); resp.StatusCode != 404 || strings.Contains(string(body), "reason") {
		t.Fatalf("revocation survived %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/agent/terminal", map[string]any{}, true); resp.StatusCode != 404 && resp.StatusCode != 405 {
		t.Fatal("device API on the administrator listener", resp.StatusCode)
	}
}

func TestDesktopRelayConsentOwnershipRevocationAndMedia(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	second := f.secondSession(t)
	id, post := f.agentRelay(t, "<test desktop>")
	peer := "22222222222222222222222222222222"
	exchange := func(p desktop.Exchange) desktop.Reply {
		t.Helper()
		var out desktop.Reply
		if e := json.Unmarshal(post("/api/v1/agent/desktop", p), &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	exchange(desktop.Exchange{Ready: true, Peer: peer})
	if resp, _ := f.do(t, "POST", "/api/v1/devices/"+id+"/desktop", map[string]any{"mode": "both"}, true); resp.StatusCode != 400 {
		t.Fatal("invalid mode", resp.StatusCode)
	}
	saved := f.csrf
	f.csrf = "bad"
	if resp, _ := f.do(t, "POST", "/api/v1/devices/"+id+"/desktop", map[string]any{"mode": "control"}, true); resp.StatusCode != 403 {
		t.Fatal("CSRF bypass", resp.StatusCode)
	}
	f.csrf = saved
	resp, body := f.do(t, "POST", "/api/v1/devices/"+id+"/desktop", map[string]any{"mode": "control"}, true)
	var created struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &created) != nil || created.ID == "" {
		t.Fatalf("create %d %s", resp.StatusCode, body)
	}
	session := "/api/v1/desktop/" + created.ID
	if resp, _ := second.do(t, "GET", session+"/frame", nil, false); resp.StatusCode != 404 {
		t.Fatal("foreign session media access", resp.StatusCode)
	}
	if resp, _ := f.do(t, "GET", session+"/frame", nil, false); resp.StatusCode != 204 {
		t.Fatal("screen before consent", resp.StatusCode)
	}
	q := exchange(desktop.Exchange{Ready: true, Peer: peer})
	if q.Request == nil {
		t.Fatal("no request")
	}
	var img bytes.Buffer
	_ = jpeg.Encode(&img, image.NewRGBA(image.Rect(0, 0, 24, 16)), nil)
	exchange(desktop.Exchange{Ready: true, Peer: peer, ID: q.Request.ID, State: "active", Frame: img.Bytes()})
	resp, body = f.do(t, "GET", session+"/frame", nil, false)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/jpeg" || !bytes.Equal(body, img.Bytes()) || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Desktop-State") != "active" {
		t.Fatal("media handling", resp.StatusCode)
	}
	input := map[string]any{"sequence": 1, "events": []map[string]any{{"kind": "text", "text": "literal"}}}
	f.csrf = "bad"
	if resp, _ := f.do(t, "POST", session+"/input", input, true); resp.StatusCode != 403 {
		t.Fatal("input CSRF", resp.StatusCode)
	}
	f.csrf = saved
	if resp, _ := second.do(t, "POST", session+"/input", input, true); resp.StatusCode != 404 {
		t.Fatal("foreign input", resp.StatusCode)
	}
	if resp, body := f.do(t, "POST", session+"/input", input, true); resp.StatusCode != 204 {
		t.Fatalf("input %d %s", resp.StatusCode, body)
	}
	if out := exchange(desktop.Exchange{Ready: true, Peer: peer, ID: q.Request.ID, State: "active"}); len(out.Inputs) != 1 {
		t.Fatal("input delivery")
	}
	if out := exchange(desktop.Exchange{Ready: true, Peer: peer, ID: q.Request.ID, State: "active"}); len(out.Inputs) != 0 {
		t.Fatal("input replay")
	}
	exchange(desktop.Exchange{Ready: true, Peer: peer, ID: q.Request.ID, State: "ended"})
	if resp, body := f.do(t, "GET", session+"/frame", nil, false); resp.StatusCode != 410 || !strings.Contains(string(body), `"reason":"ended"`) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing safe end reason %d %s", resp.StatusCode, body)
	}
	if resp, body := second.do(t, "GET", session+"/frame", nil, false); resp.StatusCode != 404 || strings.Contains(string(body), "reason") {
		t.Fatalf("foreign end reason leaked %d %s", resp.StatusCode, body)
	}
	if e := f.store.RevokeDevice(t.Context(), id, time.Now()); e != nil {
		t.Fatal(e)
	}
	if resp, _ := f.do(t, "GET", session+"/frame", nil, false); resp.StatusCode != 404 {
		t.Fatal("media after device revocation", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/agent/desktop", map[string]any{}, true); resp.StatusCode != 404 && resp.StatusCode != 405 {
		t.Fatal("device API on the administrator listener", resp.StatusCode)
	}
}

// The certificate-only device listener serves no administrator API or page.
func TestAdministratorRoutesAbsentFromAgentListener(t *testing.T) {
	h := DeviceHandler(nil)
	id := strings.Repeat("a", 32)
	for _, path := range []string{"/", "/api/v1/session", "/api/v1/devices", "/api/v1/organization", "/api/v1/technicians", "/api/v1/devices/" + id + "/terminal", "/api/v1/agent-releases", "/api/v1/reports/metrics", "/activate"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			r := httptest.NewRequest(method, "https://agent.invalid"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 404 && w.Code != 405 {
				t.Fatal("administrator route served on the agent listener", method, path, w.Code)
			}
		}
	}
}

// A terminal opened from a case is recorded to it as evidence; an
// unknown case or a missing evidence store refuses the terminal.
func TestCaseBoundTerminal(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	id, post := f.agentRelay(t, "WS-CASE")
	start := func(caseID string) (int, string) {
		resp, body := f.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{"case_id": caseID}, true)
		var created struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &created)
		return resp.StatusCode, created.ID
	}
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Live response"}, true)
	var c struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatalf("case %d %s", resp.StatusCode, body)
	}
	p := terminal.Exchange{Peer: "33333333333333333333333333333333", Identity: "S-1-5-18"}
	post("/api/v1/agent/terminal", p)
	if status, _ := start(c.ID); status != 409 {
		t.Fatal("recorded terminal without an evidence store", status)
	}
	if e := f.store.UseEvidence(t.TempDir(), 0); e != nil {
		t.Fatal(e)
	}
	if status, _ := start("not-a-case"); status != 400 {
		t.Fatal("invalid case accepted", status)
	}
	if status, _ := start(strings.Repeat("f", 32)); status != 409 {
		t.Fatal("unknown case accepted", status)
	}
	status, session := start(c.ID)
	if status != 201 {
		t.Fatal("start", status)
	}
	var q terminal.Reply
	_ = json.Unmarshal(post("/api/v1/agent/terminal", p), &q)
	if q.Request == nil || q.Request.ID != session {
		t.Fatal("missing request")
	}
	p.ID, p.State, p.Sequence, p.Output = session, "active", 1, []byte("PS C:\\> ")
	post("/api/v1/agent/terminal", p)
	resp, body = f.do(t, "GET", "/api/v1/terminal/"+session+"/output?after=0", nil, false)
	var v terminal.View
	if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil || v.CaseID != c.ID {
		t.Fatalf("view %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/terminal/"+session+"/input", map[string]any{"sequence": 1, "data": "hostname\r"}, true); resp.StatusCode != 204 {
		t.Fatal("input", resp.StatusCode)
	}
	p.Output = nil
	post("/api/v1/agent/terminal", p)
	if resp, _ := f.do(t, "POST", "/api/v1/terminal/"+session+"/stop", nil, true); resp.StatusCode != 204 {
		t.Fatal("stop", resp.StatusCode)
	}
	var list struct {
		Collections []storage.EvidenceJob `json:"collections"`
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
		_ = json.Unmarshal(body, &list)
		if len(list.Collections) == 1 && list.Collections[0].Status == "succeeded" || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(list.Collections) != 1 || list.Collections[0].Kind != "transcript" || list.Collections[0].Status != "succeeded" {
		t.Fatalf("transcript %+v", list.Collections)
	}
	job := list.Collections[0]
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections/"+job.ID+"/file", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), "terminal-"+job.ID+".jsonl") || resp.Header.Get("X-Content-SHA256") != job.ServerSHA256 || !strings.Contains(string(body), `"dir":"in","text":"hostname\r"`) || !strings.Contains(string(body), `"end":"administrator_stopped"`) {
		t.Fatalf("transcript download %d %s", resp.StatusCode, body)
	}
}

// The device terminal is a live response session. Technicians with
// the response permission may open it; built-in commands queue response jobs
// into the session's case, or show results only when it has none; a case can
// be attached while the session runs.
func TestLiveResponseConsole(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if e := f.store.UseEvidence(t.TempDir(), 0); e != nil {
		t.Fatal(e)
	}
	id, post := f.agentRelay(t, "WS-LIVE")
	p := terminal.Exchange{Peer: "44444444444444444444444444444444", Identity: "S-1-5-18"}
	post("/api/v1/agent/terminal", p)
	responder, _ := f.namedTechnician(t, strings.Repeat("e", 32), "responder", storage.TechnicianAccess{Devices: []string{id}, Response: true})
	viewer, _ := f.namedTechnician(t, strings.Repeat("c", 32), "viewer", storage.TechnicianAccess{Devices: []string{id}})
	if resp, _ := viewer.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{}, true); resp.StatusCode != 403 {
		t.Fatal("technician without the response permission", resp.StatusCode)
	}
	if resp, _ := responder.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{"case_id": storage.LiveCase}, true); resp.StatusCode != 400 && resp.StatusCode != 409 {
		t.Fatal("the live record used as a case", resp.StatusCode)
	}
	resp, body := responder.do(t, "POST", "/api/v1/devices/"+id+"/terminal", map[string]any{}, true)
	var created struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &created) != nil {
		t.Fatalf("start %d %s", resp.StatusCode, body)
	}
	session := created.ID
	command := func(client *apiFixture, line string) (int, []byte) {
		resp, body := client.do(t, "POST", "/api/v1/terminal/"+session+"/command", map[string]string{"line": line}, true)
		return resp.StatusCode, body
	}
	if status, body := command(responder, "help"); status != 200 || !strings.Contains(string(body), "reg query") {
		t.Fatalf("help %d %s", status, body)
	}
	if status, _ := command(responder, "Get-Process"); status != 400 {
		t.Fatal("not a built-in command", status)
	}
	if status, body := command(responder, "kill 1234"); status != 400 || !strings.Contains(string(body), "Run ps first") {
		t.Fatalf("kill without ps %d %s", status, body)
	}
	if status, _ := command(f, "ps"); status != 404 && status != 409 {
		t.Fatal("another account used the session", status)
	}
	status, body := command(responder, "ps")
	var queued struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	if status != 201 || json.Unmarshal(body, &queued) != nil || queued.Label == "" {
		t.Fatalf("ps %d %s", status, body)
	}
	var jobs struct {
		Jobs []storage.EvidenceJob `json:"jobs"`
	}
	resp, body = responder.do(t, "GET", "/api/v1/terminal/"+session+"/jobs", nil, false)
	if resp.StatusCode != 200 || json.Unmarshal(body, &jobs) != nil || len(jobs.Jobs) != 1 || jobs.Jobs[0].ID != queued.ID || jobs.Jobs[0].CaseID != storage.LiveCase {
		t.Fatalf("jobs %d %s", resp.StatusCode, body)
	}
	if resp, _ := responder.do(t, "GET", "/api/v1/terminal/"+session+"/jobs/"+queued.ID+"/file", nil, false); resp.StatusCode != 404 {
		t.Fatal("result before the device sent it", resp.StatusCode)
	}
	// Only the account that ran a queued command cancels it.
	if resp, _ := f.do(t, "POST", "/api/v1/terminal/"+session+"/jobs/"+queued.ID+"/cancel", nil, true); resp.StatusCode != 404 {
		t.Fatal("another account cancelled", resp.StatusCode)
	}
	if resp, _ := responder.do(t, "POST", "/api/v1/terminal/"+session+"/jobs/"+queued.ID+"/cancel", nil, true); resp.StatusCode != 204 {
		t.Fatal("cancel", resp.StatusCode)
	}
	// The live record is not reachable through the case routes.
	for _, path := range []string{"/api/v1/cases/" + storage.LiveCase, "/api/v1/cases/" + storage.LiveCase + "/collections", "/api/v1/cases/" + storage.LiveCase + "/collections/" + queued.ID + "/file"} {
		if resp, _ := f.do(t, "GET", path, nil, false); resp.StatusCode == 200 {
			t.Fatal("case route served the live record", path)
		}
	}
	// A case created for an attach that fails (here: no quota room for the
	// transcript) is closed again.
	evidenceDir := t.TempDir()
	if e := f.store.UseEvidence(evidenceDir, 1<<20); e != nil {
		t.Fatal(e)
	}
	if resp, _ := responder.do(t, "POST", "/api/v1/terminal/"+session+"/case", map[string]string{"case_title": "Failed attach"}, true); resp.StatusCode != 409 {
		t.Fatal("attach without quota room", resp.StatusCode)
	}
	_, body = f.do(t, "GET", "/api/v1/cases", nil, false)
	if !strings.Contains(string(body), "Failed attach") || strings.Contains(string(body), `"title":"Failed attach","status":"open"`) {
		t.Fatalf("case of a failed attach %s", body)
	}
	if e := f.store.UseEvidence(evidenceDir, 0); e != nil {
		t.Fatal(e)
	}
	// Attach a new case: later commands are recorded there.
	resp, body = responder.do(t, "POST", "/api/v1/terminal/"+session+"/case", map[string]string{"case_title": "Attached later"}, true)
	var attached struct {
		CaseID string `json:"case_id"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &attached) != nil || attached.CaseID == "" {
		t.Fatalf("attach %d %s", resp.StatusCode, body)
	}
	if resp, _ := responder.do(t, "POST", "/api/v1/terminal/"+session+"/case", map[string]string{"case_title": "Again"}, true); resp.StatusCode != 409 {
		t.Fatal("attached twice", resp.StatusCode)
	}
	if status, body := command(responder, `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`); status != 201 {
		t.Fatalf("reg %d %s", status, body)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+attached.CaseID+"/collections", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`) || strings.Contains(string(body), queued.ID) {
		t.Fatalf("case collections %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+attached.CaseID, nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"action":"terminal_opened"`) || !strings.Contains(string(body), session) {
		t.Fatalf("case after attach %d %s", resp.StatusCode, body)
	}
	// Stopping finishes the transcript that started with the attach.
	if resp, _ := responder.do(t, "POST", "/api/v1/terminal/"+session+"/stop", nil, true); resp.StatusCode != 204 {
		t.Fatal("stop", resp.StatusCode)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body = f.do(t, "GET", "/api/v1/cases/"+attached.CaseID+"/collections", nil, false)
		if strings.Contains(string(body), `"kind":"transcript"`) && !strings.Contains(string(body), `"status":"uploading"`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(body), `"kind":"transcript"`) || strings.Contains(string(body), `"status":"uploading"`) {
		t.Fatalf("transcript not finished %s", body)
	}
	// Results stay listed for the account that ran them after the session
	// ends; nobody else sees them through the session.
	resp, body = responder.do(t, "GET", "/api/v1/terminal/"+session+"/jobs", nil, false)
	if resp.StatusCode != 200 || json.Unmarshal(body, &jobs) != nil || len(jobs.Jobs) != 2 {
		t.Fatalf("jobs after the session %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", "/api/v1/terminal/"+session+"/jobs", nil, false)
	if resp.StatusCode != 200 || json.Unmarshal(body, &jobs) != nil || len(jobs.Jobs) != 0 {
		t.Fatalf("another account's jobs %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/terminal/"+session+"/jobs/"+queued.ID+"/file", nil, false); resp.StatusCode != 404 {
		t.Fatal("another account read a result", resp.StatusCode)
	}
}
