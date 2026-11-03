package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// The owner keeps rule sets; a technician with the response permission
// reads and checks them but cannot change them.
func TestYaraAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	const rules = "rule example_dumper {\n strings: $a = \"dumpcreds::allsessions\" wide ascii\n condition: $a\n}"
	resp, body := f.do(t, "POST", "/api/v1/yara/check", map[string]string{"source": "rule x {\n condition: $missing\n}"}, true)
	if resp.StatusCode != 400 || !strings.Contains(string(body), "line 2: undefined string $missing") {
		t.Fatalf("check %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "POST", "/api/v1/yara/check", map[string]string{"source": rules}, true)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"rules":1`) {
		t.Fatalf("check %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "POST", "/api/v1/yara-rule-sets", map[string]string{"name": "Tools", "source": rules}, true)
	var set storage.YaraRuleSet
	if resp.StatusCode != 201 || json.Unmarshal(body, &set) != nil || set.Version != 1 {
		t.Fatalf("create %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "PUT", "/api/v1/yara-rule-sets/"+set.ID, map[string]string{"name": "Tools", "source": rules + "\nrule two { condition: false }"}, true)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"version":2`) {
		t.Fatalf("update %d %s", resp.StatusCode, body)
	}
	tech := f.technicianClient(t, storage.TechnicianAccess{AllDevices: true, Response: true})
	if resp, body = tech.do(t, "GET", "/api/v1/yara-rule-sets/"+set.ID, nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), "dumpcreds") {
		t.Fatalf("technician read %d", resp.StatusCode)
	}
	if resp, _ = tech.do(t, "POST", "/api/v1/yara-rule-sets", map[string]string{"name": "Mine", "source": rules}, true); resp.StatusCode != 403 {
		t.Fatal("technician created a set", resp.StatusCode)
	}
	if resp, _ = tech.do(t, "POST", "/api/v1/yara-rule-sets/"+set.ID+"/withdraw", nil, true); resp.StatusCode != 403 {
		t.Fatal("technician withdrew a set", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", "/api/v1/yara-rule-sets/"+set.ID+"/withdraw", nil, true); resp.StatusCode != 204 {
		t.Fatal("withdraw", resp.StatusCode)
	}
	if resp, body = f.do(t, "GET", "/api/v1/yara-rule-sets", nil, false); resp.StatusCode != 200 || !strings.Contains(string(body), `"sets":[]`) {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
}
