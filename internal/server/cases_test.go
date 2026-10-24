package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// The owner opens a case, adds a note, closes it; the export verifies
// offline; technicians cannot use cases before the response permission.
func TestCasesAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Phishing on WS-1"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil || c.ID == "" {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/cases", map[string]string{"title": ""}, true); resp.StatusCode != 409 {
		t.Fatal("empty title accepted", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/notes", map[string]string{"text": "Reset the user's password."}, true); resp.StatusCode != 204 {
		t.Fatal("note", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/status", map[string]string{"status": "closed", "reason": "Contained"}, true); resp.StatusCode != 204 {
		t.Fatal("close", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/notes", map[string]string{"text": "late"}, true); resp.StatusCode != 409 {
		t.Fatal("note on closed case", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID, nil, false)
	var d storage.CaseDetail
	if resp.StatusCode != 200 || json.Unmarshal(body, &d) != nil || !d.Verified || len(d.Entries) != 3 || d.Entries[1].Actor != "admin" {
		t.Fatalf("detail: %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/custody.json", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d", resp.StatusCode)
	}
	if x, err := custody.VerifyExport(body); err != nil || x.Head != d.Head || len(x.Entries) != 3 {
		t.Fatal("export does not verify", err)
	}
	if resp, _ = f.do(t, "GET", "/api/v1/cases/0123456789abcdef0123456789abcdef", nil, false); resp.StatusCode != 404 {
		t.Fatal("unknown case", resp.StatusCode)
	}
	tech, _ := f.namedTechnician(t, strings.Repeat("c", 32), "helpdesk", storage.TechnicianAccess{AllDevices: true, Events: true, Services: true, Processes: true, Desktop: true, Files: true})
	for _, path := range []string{"/api/v1/cases", "/api/v1/cases/" + c.ID, "/api/v1/cases/" + c.ID + "/custody.json"} {
		if resp, _ := tech.do(t, "GET", path, nil, false); resp.StatusCode != 403 {
			t.Fatal("technician without response permission reached", path, resp.StatusCode)
		}
	}
	if resp, _ := tech.do(t, "POST", "/api/v1/cases", map[string]string{"title": "x"}, true); resp.StatusCode != 403 {
		t.Fatal("technician without response permission opened a case", resp.StatusCode)
	}

	// With the response permission a technician sees all cases, even
	// with access to no device, and the custody log names the technician.
	responder, _ := f.namedTechnician(t, strings.Repeat("d", 32), "responder", storage.TechnicianAccess{Response: true})
	resp, body = responder.do(t, "GET", "/api/v1/session", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"response":true`) {
		t.Fatalf("session permissions: %s", body)
	}
	if resp, body = responder.do(t, "GET", "/api/v1/cases", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), c.ID) {
		t.Fatalf("responder list: %d %s", resp.StatusCode, body)
	}
	if resp, _ = responder.do(t, "POST", "/api/v1/cases/"+c.ID+"/status", map[string]string{"status": "open"}, true); resp.StatusCode != 204 {
		t.Fatal("responder reopen", resp.StatusCode)
	}
	if resp, _ = responder.do(t, "POST", "/api/v1/cases/"+c.ID+"/notes", map[string]string{"text": "Technician note"}, true); resp.StatusCode != 204 {
		t.Fatal("responder note", resp.StatusCode)
	}
	resp, body = responder.do(t, "GET", "/api/v1/cases/"+c.ID, nil, false)
	if resp.StatusCode != 200 || json.Unmarshal(body, &d) != nil || !d.Verified || !strings.HasPrefix(d.Entries[len(d.Entries)-1].Actor, "technician:") || d.Actors[d.Entries[len(d.Entries)-1].Actor] != "responder" {
		t.Fatalf("responder detail: %s", body)
	}
	// Owner-only administration stays closed to the responder.
	if resp, _ := responder.do(t, "GET", "/api/v1/installer", nil, false); resp.StatusCode != 403 {
		t.Fatal("responder reached owner-only route", resp.StatusCode)
	}
}

// Collecting needs the response permission and access to the
// device; downloads stream the verified file with its hash.
func TestEvidenceAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	device := f.enroll(t, "WS-EVIDENCE")
	other := f.enroll(t, "WS-OTHER")
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Evidence API"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	collect := func(client *apiFixture, device, path string) (int, string) {
		resp, body := client.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]string{"device_id": device, "path": path}, true)
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &out)
		return resp.StatusCode, out.ID
	}
	if status, _ := collect(f, device, "relative.txt"); status != 409 {
		t.Fatal("invalid path accepted", status)
	}
	status, job := collect(f, device, `C:\Windows\System32\drivers\etc\hosts`)
	if status != 201 || job == "" {
		t.Fatal("collect", status)
	}
	responder, _ := f.namedTechnician(t, strings.Repeat("e", 32), "responder", storage.TechnicianAccess{Devices: []string{device}, Response: true})
	if status, _ := collect(responder, other, `C:\x.txt`); status != 403 {
		t.Fatal("responder collected from a device outside their scope", status)
	}
	if status, _ := collect(responder, device, `C:\x.txt`); status != 201 {
		t.Fatal("responder collect", status)
	}
	if status, _ := collect(f, device, `C:\y.txt`); status != 409 {
		t.Fatal("third active collection on one device accepted", status)
	}
	resp, body = responder.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if resp.StatusCode != 200 || strings.Count(string(body), `"status":"queued"`) != 2 {
		t.Fatalf("collections: %d %s", resp.StatusCode, body)
	}
	if resp, _ = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections/"+job+"/file", nil, false); resp.StatusCode != 404 {
		t.Fatal("download before collection", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collections/"+job+"/cancel", nil, true); resp.StatusCode != 204 {
		t.Fatal("cancel", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collections/"+job+"/cancel", nil, true); resp.StatusCode != 409 {
		t.Fatal("cancelled twice", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID, nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"action":"collection_cancelled"`) || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("custody: %s", body)
	}
}

func TestRangeIncludesStart(t *testing.T) {
	for header, want := range map[string]bool{"": true, "bytes=0-": true, "bytes=0-99": true, "bytes=-500": true, "bytes=100-": false, "bytes=100-200,0-10": true, "bytes=100-200, 300-": false, "items=0-1": true, "bytes=00-5": true, "bytes=x-5": true} {
		if rangeIncludesStart(header) != want {
			t.Fatal(header, !want)
		}
	}
}

// Hives and alternate data streams can be requested; anything
// else is refused.
func TestEvidenceSourcesAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	device := f.enroll(t, "WS-SOURCES")
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Sources"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	for _, x := range []struct {
		source, path string
		status       int
	}{{"hive", "SYSTEM", 201}, {"", `C:\x\file.txt:Zone.Identifier`, 201}, {"hive", "HARDWARE", 409}, {"registry", "SYSTEM", 409}, {"hive", `C:\Windows\System32\config\SAM`, 409}} {
		resp, body := f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]string{"device_id": device, "source": x.source, "path": x.path}, true)
		if resp.StatusCode != x.status {
			t.Fatal(x, resp.StatusCode, string(body))
		}
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"source":"hive"`) {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
}

// Actions need the response permission and access to the device;
// specs are validated.
func TestResponseActionsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	device := f.enroll(t, "WS-ACTIONS")
	other := f.enroll(t, "WS-ACTIONS-OTHER")
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Actions"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	act := func(client *apiFixture, device string, action map[string]any) int {
		resp, _ := client.do(t, "POST", "/api/v1/cases/"+c.ID+"/actions", map[string]any{"device_id": device, "action": action}, true)
		return resp.StatusCode
	}
	if status := act(f, device, map[string]any{"kind": "processes"}); status != 201 {
		t.Fatal("processes", status)
	}
	if status := act(f, device, map[string]any{"kind": "registry", "key": `HKCU\Software`}); status != 400 {
		t.Fatal("invalid key", status)
	}
	if status := act(f, device, map[string]any{"kind": "kill", "pid": 4, "start": "1", "name": "System"}); status != 400 {
		t.Fatal("kill System", status)
	}
	responder, _ := f.namedTechnician(t, strings.Repeat("f", 32), "actor", storage.TechnicianAccess{Devices: []string{device}, Response: true})
	if status := act(responder, other, map[string]any{"kind": "connections"}); status != 403 {
		t.Fatal("outside scope", status)
	}
	if status := act(responder, device, map[string]any{"kind": "connections"}); status != 201 {
		t.Fatal("responder", status)
	}
	// Cancelling another device's action needs access to that device.
	resp, body = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/actions", map[string]any{"device_id": other, "action": map[string]any{"kind": "tasks"}}, true)
	var queued struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("owner on other device %d %s", resp.StatusCode, body)
	}
	if resp, _ := responder.do(t, "POST", "/api/v1/cases/"+c.ID+"/collections/"+queued.ID+"/cancel", nil, true); resp.StatusCode != 403 {
		t.Fatal("responder cancelled another device's action", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"source":"action"`) || !strings.Contains(string(body), `"path":"Network connections"`) {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
}

// Only the owner adds tools; anyone with the response permission
// sees them and can drop them or run scripts on devices they may access.
func TestToolsAndResponseScriptsAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	upload := func(client *apiFixture, name string, content []byte) (*http.Response, string) {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		_ = w.WriteField("name", name)
		_ = w.WriteField("description", "test tool")
		part, _ := w.CreateFormFile("file", name)
		_, _ = part.Write(content)
		w.Close()
		req, _ := http.NewRequest("POST", client.server.URL+"/api/v1/response-tools", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-CSRF-Token", client.csrf)
		r, e := client.client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return r, readResponse(t, r)
	}
	device := f.enroll(t, "WS-DROP")
	second := f.enroll(t, "WS-DROP-2")
	responder, _ := f.namedTechnician(t, strings.Repeat("d", 32), "dropper", storage.TechnicianAccess{Devices: []string{device, second}, Response: true})
	if r, _ := upload(responder, "tool.exe", []byte("x")); r.StatusCode != 403 {
		t.Fatal("technician added a tool", r.StatusCode)
	}
	r, body := upload(f, "procdump.exe", []byte("procdump"))
	var tool storage.ResponseTool
	if r.StatusCode != 201 || json.Unmarshal([]byte(body), &tool) != nil || tool.SHA256 != filetransferDigest([]byte("procdump")) {
		t.Fatalf("upload %d %s", r.StatusCode, body)
	}
	resp, list := responder.do(t, "GET", "/api/v1/response-tools", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(list), tool.ID) {
		t.Fatalf("list %d %s", resp.StatusCode, list)
	}
	resp, created := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Drop"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(created, &c) != nil {
		t.Fatal("case", resp.StatusCode)
	}
	target := device
	act := func(client *apiFixture, action map[string]any) int {
		resp, _ := client.do(t, "POST", "/api/v1/cases/"+c.ID+"/actions", map[string]any{"device_id": target, "action": action}, true)
		return resp.StatusCode
	}
	if status := act(responder, map[string]any{"kind": "drop", "source": "tool", "ref": tool.ID, "path": `C:\Tools\procdump.exe`}); status != 201 {
		t.Fatal("drop", status)
	}
	if status := act(responder, map[string]any{"kind": "script", "script": "Get-Process", "timeout": 30}); status != 201 {
		t.Fatal("script", status)
	}
	if status := act(responder, map[string]any{"kind": "drop", "source": "tool", "ref": tool.ID, "path": `relative.exe`}); status != 400 {
		t.Fatal("bad destination", status)
	}
	target = second
	if status := act(responder, map[string]any{"kind": "drop", "source": "tool", "ref": tool.ID, "path": `C:\x.exe`, "sha256": strings.Repeat("0", 64), "size": 1}); status != 201 {
		t.Fatal("client-supplied hash should be replaced by the server's", status)
	}
	resp, jobs := f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if resp.StatusCode != 200 || strings.Contains(string(jobs), strings.Repeat("0", 64)) || !strings.Contains(string(jobs), tool.SHA256) {
		t.Fatalf("specs %s", jobs)
	}
}

func filetransferDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Event log exports from the case page and the device's Event logs
// tab; raw XPath needs the response permission.
func TestEventExportAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	old := f.enroll(t, "WS-EVTX-OLD")
	// The export needs an agent reporting event logs capability version 2.
	token, _, e := f.devices.NewToken(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	key, _ := deviceidentity.NewKey()
	csr, _ := deviceidentity.CSR(key)
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: "WS-EVTX", OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(cred.Certificate))
	support, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "readable"})
	if e = f.store.RecordEventLogs(t.Context(), cred.DeviceID, deviceidentity.Fingerprint(block.Bytes), protocol.FeatureReport{Capability: eventlogs.Capability, Status: "ok", Data: support}, time.Now()); e != nil {
		t.Fatal(e)
	}
	device := cred.DeviceID
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Logs"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatalf("case %d %s", resp.StatusCode, body)
	}
	now := time.Now().Unix()
	filter := map[string]any{"from": now - 3600, "to": now, "level": -1, "event_id": 4624, "provider": "", "xpath": "*[EventData[Data[@Name='LogonType']='10']]"}
	if resp, body := f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": device, "source": "evtx", "path": "Security", "filter": filter}, true); resp.StatusCode != 201 {
		t.Fatalf("filtered export %d %s", resp.StatusCode, body)
	}
	if resp, body := f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": old, "source": "evtx", "path": "Security"}, true); resp.StatusCode != 409 || !strings.Contains(string(body), `"agent"`) {
		t.Fatalf("export to an agent without the capability %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": device, "source": "evtx", "path": `C:\Windows\System32\winevt\Logs\Security.evtx`}, true); resp.StatusCode != 400 {
		t.Fatal("file path accepted as a channel", resp.StatusCode)
	}
	_, list := f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if !strings.Contains(string(list), `"source":"evtx"`) || !strings.Contains(string(list), `EventID=4624`) || !strings.Contains(string(list), `LogonType`) {
		t.Fatalf("collections %s", list)
	}
	export := "/api/v1/devices/" + device + "/event-logs/export"
	if resp, _ := f.do(t, "POST", export, map[string]any{"channel": "System"}, true); resp.StatusCode != 400 {
		t.Fatal("export without a case", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", export, map[string]any{"channel": "System", "case_id": storage.LiveCase}, true); resp.StatusCode != 400 {
		t.Fatal("export into the hidden record", resp.StatusCode)
	}
	resp, body = f.do(t, "POST", export, map[string]any{"channel": "System", "case_title": "System log export"}, true)
	var created struct {
		ID     string `json:"id"`
		CaseID string `json:"case_id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &created) != nil || created.CaseID == "" {
		t.Fatalf("export into a new case %d %s", resp.StatusCode, body)
	}
	// Two collections already run on the device: a third is refused and the
	// case created for it is closed again.
	resp, _ = f.do(t, "POST", export, map[string]any{"channel": "Setup", "case_title": "Not started"}, true)
	_, cases := f.do(t, "GET", "/api/v1/cases", nil, false)
	if resp.StatusCode != 409 || strings.Contains(string(cases), `"title":"Not started","status":"open"`) {
		t.Fatalf("third export %d %s", resp.StatusCode, cases)
	}
	viewer, _ := f.namedTechnician(t, strings.Repeat("e", 32), "logs", storage.TechnicianAccess{Devices: []string{device}, Events: true})
	if resp, _ := viewer.do(t, "POST", export, map[string]any{"channel": "System", "case_id": c.ID}, true); resp.StatusCode != 403 {
		t.Fatal("export without the response permission", resp.StatusCode)
	}
}
