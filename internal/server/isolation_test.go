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

// Isolating needs the response permission, the device name typed
// and an agent that can isolate; the release code is shown only to accounts
// that may release; a device already isolating is refused; releasing a
// device that has not taken the isolation cancels it.
func TestIsolationAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	token, _, e := f.devices.NewToken(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	key, _ := deviceidentity.NewKey()
	csr, _ := deviceidentity.CSR(key)
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: "WS-ISO", OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(cred.Certificate))
	fp := deviceidentity.Fingerprint(block.Bytes)
	id := cred.DeviceID
	isolate := func(client *apiFixture, body map[string]any) (int, []byte) {
		resp, out := client.do(t, "POST", "/api/v1/devices/"+id+"/isolate", body, true)
		return resp.StatusCode, out
	}
	if status, body := isolate(f, map[string]any{"confirm": "ws-iso"}); status != 400 || !strings.Contains(string(body), "confirmation") {
		t.Fatalf("wrong confirmation %d %s", status, body)
	}
	if status, body := isolate(f, map[string]any{"confirm": "WS-ISO"}); status != 409 || !strings.Contains(string(body), `"agent"`) {
		t.Fatalf("old agent %d %s", status, body)
	}
	if e = f.store.RecordHeartbeat(t.Context(), id, fp, protocol.Heartbeat{Hostname: "WS-ISO", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityIsolation}}, time.Now()); e != nil {
		t.Fatal(e)
	}
	if status, _ := isolate(f, map[string]any{"confirm": "WS-ISO", "release_after": 8 * 24 * 3600}); status != 400 {
		t.Fatal("timed release over 7 days", status)
	}
	viewer, _ := f.namedTechnician(t, strings.Repeat("b", 32), "viewer", storage.TechnicianAccess{Devices: []string{id}, Events: true})
	if status, _ := isolate(viewer, map[string]any{"confirm": "WS-ISO"}); status != 403 {
		t.Fatal("isolated without the response permission", status)
	}
	status, body := isolate(f, map[string]any{"confirm": "WS-ISO", "release_after": 3600})
	var v storage.Isolation
	if status != 201 || json.Unmarshal(body, &v) != nil || v.Code == "" || v.Phase != "isolating" || v.CaseID != storage.LiveCase {
		t.Fatalf("isolate %d %s", status, body)
	}
	if status, body := isolate(f, map[string]any{"confirm": "WS-ISO"}); status != 409 || !strings.Contains(string(body), "isolated") {
		t.Fatalf("isolated twice %d %s", status, body)
	}
	_, detail := viewer.do(t, "GET", "/api/v1/devices/"+id, nil, false)
	if strings.Contains(string(detail), v.Code) || !strings.Contains(string(detail), `"phase":"isolating"`) {
		t.Fatalf("viewer sees the release code or no phase: %s", detail)
	}
	responder, _ := f.namedTechnician(t, strings.Repeat("c", 32), "responder", storage.TechnicianAccess{Devices: []string{id}, Response: true})
	if _, detail = responder.do(t, "GET", "/api/v1/devices/"+id, nil, false); !strings.Contains(string(detail), v.Code) {
		t.Fatalf("responder cannot see the release code: %s", detail)
	}
	_, list := f.do(t, "GET", "/api/v1/devices", nil, false)
	if !strings.Contains(string(list), `"isolation":"isolating"`) {
		t.Fatalf("device list %s", list)
	}
	resp, body := responder.do(t, "POST", "/api/v1/devices/"+id+"/release-isolation", nil, true)
	var released storage.Isolation
	if resp.StatusCode != 200 || json.Unmarshal(body, &released) != nil || released.Phase != "released" || released.Code != "" {
		t.Fatalf("release %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/devices/"+id+"/release-isolation", nil, true); resp.StatusCode != 409 {
		t.Fatal("released twice", resp.StatusCode)
	}
}
