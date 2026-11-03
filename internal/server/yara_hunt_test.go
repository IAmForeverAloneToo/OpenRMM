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

// A YARA hunt stores the rules once: each device's job names their hash,
// and the rules are added when the job is handed to the device. Agents
// without the ability are listed as not searched.
func TestYaraHuntAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	enroll := func(host string, abilities []string) (string, string) {
		token, _, e := f.devices.NewToken(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		key, _ := deviceidentity.NewKey()
		csr, _ := deviceidentity.CSR(key)
		cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: host, OS: "windows", Architecture: "amd64"}, "test")
		if e != nil {
			t.Fatal(e)
		}
		block, _ := pem.Decode([]byte(cred.Certificate))
		fp := deviceidentity.Fingerprint(block.Bytes)
		if e = f.store.RecordHeartbeat(t.Context(), cred.DeviceID, fp, protocol.Heartbeat{Hostname: host, OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: abilities}, time.Now()); e != nil {
			t.Fatal(e)
		}
		return cred.DeviceID, fp
	}
	able, fp := enroll("WS-YARA", []string{protocol.AbilityHunt, protocol.AbilityYara})
	old, _ := enroll("WS-OLD", []string{protocol.AbilityHunt})
	const rules = "rule example_dumper {\n strings: $a = \"dumpcreds::allsessions\"\n condition: $a\n}"
	resp, body := f.do(t, "POST", "/api/v1/yara-rule-sets", map[string]string{"name": "Tools", "source": rules}, true)
	var set storage.YaraRuleSet
	if resp.StatusCode != 201 || json.Unmarshal(body, &set) != nil {
		t.Fatalf("set %d %s", resp.StatusCode, body)
	}
	// Broken pasted rules are refused with the reason.
	resp, body = f.do(t, "POST", "/api/v1/hunts/indicators", map[string]any{"devices": []string{able}, "files": true, "yara": map[string]any{"rules": "rule x {"}, "case_title": "YARA"}, true)
	if resp.StatusCode != 400 || !strings.Contains(string(body), "line 1") {
		t.Fatalf("broken rules %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "POST", "/api/v1/hunts/indicators", map[string]any{"devices": []string{able, old}, "files": true, "yara": map[string]any{"set": set.ID, "memory": true}, "case_title": "YARA hunt"}, true)
	var h storage.Hunt
	if resp.StatusCode != 201 || json.Unmarshal(body, &h) != nil {
		t.Fatalf("hunt %d %s", resp.StatusCode, body)
	}
	if len(h.Targets) != 1 || len(h.Problems) != 1 || !strings.Contains(h.Problems[0].Reason, "cannot run YARA rules") {
		t.Fatalf("%+v", h)
	}
	// The stored job and custody keep the hash, not the rules.
	jobs, _ := f.store.EvidenceJobs(t.Context(), h.CaseID)
	if len(jobs) != 1 || strings.Contains(jobs[0].Action, "dumpcreds") || !strings.Contains(jobs[0].Action, set.SHA256) || jobs[0].Path != "YARA scan (Tools v1)" {
		t.Fatalf("%+v", jobs)
	}
	// The device gets the rules.
	d, e := f.store.DispatchEvidence(t.Context(), able, fp, time.Now())
	if e != nil || d.Job == nil || d.Job.Action == nil || d.Job.Action.Hunt.Yara.Rules != rules || !d.Job.Action.Hunt.Yara.Memory {
		t.Fatalf("dispatch %+v %v", d.Job, e)
	}
	// The result's action is the stored one again.
	if d.Job.Action.WithoutRules().Text() != jobs[0].Action {
		t.Fatal("echoed action differs from the stored one")
	}
}
