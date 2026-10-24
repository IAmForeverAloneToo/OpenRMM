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

// The owner manages triage profiles; responders see them and
// collect packages from devices whose agent reports the triage ability.
func TestTriageAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	old := f.enroll(t, "WS-TRIAGE-OLD")
	token, _, e := f.devices.NewToken(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	key, _ := deviceidentity.NewKey()
	csr, _ := deviceidentity.CSR(key)
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: "WS-TRIAGE", OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(cred.Certificate))
	if e = f.store.RecordHeartbeat(t.Context(), cred.DeviceID, deviceidentity.Fingerprint(block.Bytes), protocol.Heartbeat{Hostname: "WS-TRIAGE", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityTriage}}, time.Now()); e != nil {
		t.Fatal(e)
	}
	device := cred.DeviceID
	responder, _ := f.namedTechnician(t, strings.Repeat("d", 32), "triager", storage.TechnicianAccess{Devices: []string{device, old}, Response: true})
	if resp, _ := responder.do(t, "POST", "/api/v1/triage-profiles", map[string]any{"name": "Mine", "items": []string{"prefetch"}}, true); resp.StatusCode != 403 {
		t.Fatal("technician added a profile", resp.StatusCode)
	}
	resp, body := f.do(t, "POST", "/api/v1/triage-profiles", map[string]any{"name": "Quick", "items": []string{"prefetch", "event_logs"}}, true)
	var quick storage.TriageProfile
	if resp.StatusCode != 201 || json.Unmarshal(body, &quick) != nil {
		t.Fatalf("add %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/triage-profiles", map[string]any{"name": "Bad", "items": []string{"nonsense"}}, true); resp.StatusCode != 400 {
		t.Fatal("unknown artifact type accepted", resp.StatusCode)
	}
	resp, body = responder.do(t, "GET", "/api/v1/triage-profiles", nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"id":"full"`) || !strings.Contains(string(body), quick.ID) || !strings.Contains(string(body), `"name":"srum"`) {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Triage"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatal("case", resp.StatusCode)
	}
	collect := func(device, profile string) (int, []byte) {
		resp, body := responder.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": device, "source": "triage", "profile": profile}, true)
		return resp.StatusCode, body
	}
	if status, body := collect(old, "full"); status != 409 || !strings.Contains(string(body), `"agent"`) {
		t.Fatalf("triage on an old agent %d %s", status, body)
	}
	if status, _ := collect(device, "missing"); status != 400 {
		t.Fatal("unknown profile", status)
	}
	if status, body := collect(device, quick.ID); status != 201 {
		t.Fatalf("triage %d %s", status, body)
	}
	_, list := f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if !strings.Contains(string(list), `"source":"triage"`) || !strings.Contains(string(list), `"query":"prefetch,event_logs"`) {
		t.Fatalf("collections %s", list)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/triage-profiles/full/withdraw", nil, true); resp.StatusCode != 404 {
		t.Fatal("built-in profile withdrawn", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/triage-profiles/"+quick.ID+"/withdraw", nil, true); resp.StatusCode != 204 {
		t.Fatal("withdraw", resp.StatusCode)
	}
}
