package scripting

import (
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"testing"
	"time"
)

func testJob() protocol.ScriptJob {
	v := protocol.ScriptVersion{ID: strings.Repeat("a", 32), ScriptID: strings.Repeat("b", 32), Number: 1, Definition: protocol.ScriptDefinition{Name: "Fixture", Description: "Harmless test", Body: "param([string]$Message)\nWrite-Output $Message", Parameters: []protocol.ScriptParameter{{Name: "Message", Required: true}}, Timeout: 5, RunAs: "restricted"}}
	v.Hash = Digest(v)
	return protocol.ScriptJob{ID: strings.Repeat("c", 32), Version: v, Arguments: map[string]string{"Message": "hello"}, ExpiresAt: time.Now().Add(time.Minute).Unix()}
}
func TestVersionHashParametersAndStrictSchemas(t *testing.T) {
	q := testJob()
	if !JobValid(q) {
		t.Fatal("valid definition rejected")
	}
	for _, mutate := range []func(*protocol.ScriptJob){func(q *protocol.ScriptJob) { q.Version.Definition.Body += "\nWrite-Output changed" }, func(q *protocol.ScriptJob) { q.Version.ID = strings.Repeat("d", 32) }, func(q *protocol.ScriptJob) { q.Arguments = map[string]string{"Message": "hi", "Unexpected": "x"} }, func(q *protocol.ScriptJob) { q.Arguments = map[string]string{} }, func(q *protocol.ScriptJob) { q.Version.Definition.Timeout = 301 }, func(q *protocol.ScriptJob) { q.Version.Definition.RunAs = "admin" }} {
		x := testJob()
		mutate(&x)
		if JobValid(x) {
			t.Fatal("invalid/tampered job")
		}
	}
	for _, name := range []string{"Verbose", "Confirm", "A;exit", "1Name", ""} {
		d := q.Version.Definition
		d.Parameters = []protocol.ScriptParameter{{Name: name}}
		if DefinitionValid(d) {
			t.Fatal("unsafe parameter")
		}
	}
	// Aliases of common parameters: new versions may not use them, versions
	// saved earlier still run.
	for _, name := range []string{"ea", "OV", "proga"} {
		d := q.Version.Definition
		d.Parameters = []protocol.ScriptParameter{{Name: name}}
		if NewDefinitionValid(d) || !DefinitionValid(d) {
			t.Fatal("alias rule wrong for", name)
		}
	}
	if !NewDefinitionValid(q.Version.Definition) {
		t.Fatal("ordinary definition rejected as new")
	}
	raw, _ := json.Marshal(q)
	var out protocol.ScriptJob
	if Decode(append(raw, []byte("{}")...), &out) == nil {
		t.Fatal("trailing JSON")
	}
	if Decode([]byte(`{"unknown":1}`), &out) == nil {
		t.Fatal("unknown field")
	}
	if !ResultValid(Failure(q.ID, "running")) || ResultValid(protocol.ScriptResult{ID: q.ID, Outcome: "succeeded"}) {
		t.Fatal("result contract")
	}
	r := protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(`{"restricted":true,"administrator":"disabled"}`)}
	if _, e := Normalize(r); e != nil {
		t.Fatal(e)
	}
	r.Data = json.RawMessage(`{"administrator":"disabled"}`)
	if _, e := Normalize(r); e == nil {
		t.Fatal("missing support")
	}
}
func FuzzScriptJob(f *testing.F) {
	raw, _ := json.Marshal(testJob())
	f.Add(raw)
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var q protocol.ScriptJob
		if Decode(b, &q) == nil && JobValid(q) {
			raw, e := json.Marshal(q)
			if e != nil || Decode(raw, &q) != nil || !JobValid(q) {
				t.Fatal("unstable")
			}
		}
	})
}
