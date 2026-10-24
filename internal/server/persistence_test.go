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

// enrollAbilities enrolls a device whose agent reported abilities.
func (f *apiFixture) enrollAbilities(t *testing.T, hostname string, abilities []string) string {
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
	if e = f.store.RecordHeartbeat(t.Context(), cred.DeviceID, deviceidentity.Fingerprint(block.Bytes), protocol.Heartbeat{Hostname: hostname, OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: abilities}, time.Now()); e != nil {
		t.Fatal(e)
	}
	return cred.DeviceID
}

// The persistence report is a case action and a live response
// command, refused for agents that do not report the ability.
func TestPersistenceAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	old := f.enroll(t, "WS-PERSIST-OLD")
	device := f.enrollAbilities(t, "WS-PERSIST", []string{protocol.AbilityPersistence, protocol.AbilityTriage})
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Persistence"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatal("case", resp.StatusCode)
	}
	act := func(device string) (int, []byte) {
		resp, body := f.do(t, "POST", "/api/v1/cases/"+c.ID+"/actions", map[string]any{"device_id": device, "action": map[string]any{"kind": "persistence"}}, true)
		return resp.StatusCode, body
	}
	if status, body := act(old); status != 409 || !strings.Contains(string(body), `"agent"`) {
		t.Fatalf("old agent %d %s", status, body)
	}
	if status, body := act(device); status != 201 {
		t.Fatalf("persistence %d %s", status, body)
	}
	_, list := f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if !strings.Contains(string(list), `"path":"Persistence report"`) {
		t.Fatalf("collections %s", list)
	}
}
