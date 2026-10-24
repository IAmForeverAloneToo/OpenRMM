package server

import (
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// enrollEvents enrolls a device that reports event logs capability version.
func (f *apiFixture) enrollEvents(t *testing.T, hostname string, version int) string {
	t.Helper()
	token, _, e := f.devices.NewToken(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	key, _ := deviceidentity.NewKey()
	csr, _ := deviceidentity.CSR(key)
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: hostname, OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(cred.Certificate))
	support, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "readable"})
	if e = f.store.RecordEventLogs(t.Context(), cred.DeviceID, deviceidentity.Fingerprint(block.Bytes), protocol.FeatureReport{Capability: protocol.Capability{Name: "event_logs", Version: version}, Status: "ok", Data: support}, time.Now()); e != nil {
		t.Fatal(e)
	}
	return cred.DeviceID
}

// Fleet log search needs the response permission and reaches only
// devices the account may access; searches are visible to the account that
// started them and to the owner.
func TestLogSearchAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	a := f.enrollEvents(t, "WS-HUNT-A", 3)
	b := f.enrollEvents(t, "WS-HUNT-B", 3)
	old := f.enrollEvents(t, "WS-HUNT-OLD", 2)
	now := time.Now().Unix()
	filter := map[string]any{"channel": "Security", "from": now - 86400, "to": now, "level": -1, "event_id": 4625, "provider": "", "xpath": "*[EventData[Data[@Name='LogonType']='10']]"}
	start := func(client *apiFixture, body map[string]any) (int, []byte) {
		resp, out := client.do(t, "POST", "/api/v1/hunts/log-search", body, true)
		return resp.StatusCode, out
	}
	status, body := start(f, map[string]any{"devices": []string{a, b, old}, "filter": filter})
	var h storage.Hunt
	if status != 201 || json.Unmarshal(body, &h) != nil || len(h.Targets) != 2 || len(h.Problems) != 1 || h.Problems[0].DeviceID != old || h.CaseID != storage.LiveCase {
		t.Fatalf("search %d %s", status, body)
	}
	if status, body := start(f, map[string]any{"devices": []string{old}, "filter": filter}); status != 409 || !strings.Contains(string(body), "no_targets") {
		t.Fatalf("only an old agent %d %s", status, body)
	}
	bad := map[string]any{}
	for k, v := range filter {
		bad[k] = v
	}
	bad["xpath"] = "*[System] or *[System]"
	if status, _ := start(f, map[string]any{"devices": []string{a}, "filter": bad}); status != 400 {
		t.Fatal("invalid XPath", status)
	}
	// A new case is created for the search and closed again when it cannot start.
	status, body = start(f, map[string]any{"devices": []string{old}, "filter": filter, "case_title": "Unused search"})
	_, cases := f.do(t, "GET", "/api/v1/cases", nil, false)
	if status != 409 || strings.Contains(string(cases), `"title":"Unused search","status":"open"`) {
		t.Fatalf("case of a failed search %d %s", status, cases)
	}
	// Technicians: response permission and device scope.
	viewer, _ := f.namedTechnician(t, strings.Repeat("b", 32), "viewer", storage.TechnicianAccess{Devices: []string{a}, Events: true})
	if status, _ := start(viewer, map[string]any{"devices": []string{a}, "filter": filter}); status != 403 {
		t.Fatal("search without the response permission", status)
	}
	responder, _ := f.namedTechnician(t, strings.Repeat("c", 32), "responder", storage.TechnicianAccess{Devices: []string{a}, Response: true})
	// A device outside the scope is unknown: nothing about it is shown.
	if status, body := start(responder, map[string]any{"devices": []string{a, b}, "filter": filter}); status != 400 || strings.Contains(string(body), "WS-HUNT-B") {
		t.Fatalf("out-of-scope device %d %s", status, body)
	}
	status, body = start(responder, map[string]any{"devices": []string{a}, "filter": filter})
	var own storage.Hunt
	if status != 201 || json.Unmarshal(body, &own) != nil || len(own.Targets) != 1 || own.Targets[0].DeviceID != a || len(own.Problems) != 0 {
		t.Fatalf("responder search %d %s", status, body)
	}
	if resp, _ := responder.do(t, "GET", "/api/v1/hunts/"+h.ID, nil, false); resp.StatusCode != 404 {
		t.Fatal("responder read the owner's search", resp.StatusCode)
	}
	_, list := responder.do(t, "GET", "/api/v1/hunts", nil, false)
	if strings.Contains(string(list), h.ID) || !strings.Contains(string(list), own.ID) {
		t.Fatalf("responder list %s", list)
	}
	_, list = f.do(t, "GET", "/api/v1/hunts", nil, false)
	if !strings.Contains(string(list), h.ID) || !strings.Contains(string(list), own.ID) {
		t.Fatalf("owner list %s", list)
	}
	if resp, _ := f.do(t, "GET", "/api/v1/hunts/"+h.ID+"/jobs/"+h.Targets[0].JobID+"/result", nil, false); resp.StatusCode != 404 {
		t.Fatal("result before the device sent it", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/hunts/"+h.ID+"/cancel", nil, true); resp.StatusCode != 204 {
		t.Fatal("cancel", resp.StatusCode)
	}
	resp, body := f.do(t, "GET", "/api/v1/hunts/"+h.ID, nil, false)
	if resp.StatusCode != 200 || json.Unmarshal(body, &h) != nil || h.CancelledAt == nil || h.Targets[0].Status != "cancelled" {
		t.Fatalf("after cancel %d %s", resp.StatusCode, body)
	}
}
