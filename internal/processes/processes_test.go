package processes

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"testing"
	"time"
)

func report(v protocol.Processes) protocol.FeatureReport {
	b, _ := json.Marshal(v)
	return protocol.FeatureReport{Capability: Capability, Status: "ok", Data: b}
}
func TestSchemaAndBounds(t *testing.T) {
	v := protocol.Processes{Coverage: Coverage, Items: []protocol.Process{{PID: 100, Name: "fixture.exe", Start: "1234", CanTerminate: true}}}
	if _, e := Normalize(report(v)); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*protocol.Processes){func(v *protocol.Processes) { v.Coverage = "all" }, func(v *protocol.Processes) { v.Items = nil }, func(v *protocol.Processes) { v.Items = append(v.Items, v.Items[0]) }, func(v *protocol.Processes) { v.Items[0].Start = "01234" }, func(v *protocol.Processes) { v.Items[0].Name = "svchost.exe" }, func(v *protocol.Processes) { n := uint32(10001); v.Items[0].CPU = &n }, func(v *protocol.Processes) { v.Items[0].Name = "a\nb" }} {
		x := protocol.Processes{Coverage: v.Coverage, Items: append([]protocol.Process{}, v.Items...)}
		change(&x)
		if _, e := Normalize(report(x)); e == nil {
			t.Fatal("bad snapshot accepted", x)
		}
	}
	base := string(report(v).Data)
	for _, b := range []string{strings.Replace(base, `"can_terminate":true`, `"can_terminate":null`, 1), strings.Replace(base, `"working_set_bytes":null,`, "", 1), strings.Replace(base, `"pid":100`, `"pid":null`, 1), strings.Replace(base, `"name":"fixture.exe"`, `"name":null`, 1), base + `{}`, strings.Replace(base, `"coverage":`, `"unknown":0,"coverage":`, 1)} {
		r := report(v)
		r.Data = []byte(b)
		if _, e := Normalize(r); e == nil {
			t.Fatal("missing/hostile field accepted", b)
		}
	}
	too := protocol.Processes{Coverage: Coverage, Items: []protocol.Process{}}
	for i := 0; i < MaxItems+1; i++ {
		too.Items = append(too.Items, protocol.Process{PID: uint32(i), Name: "fixture.exe"})
	}
	if _, e := Normalize(report(too)); e == nil {
		t.Fatal("too many")
	}
	r := report(v)
	r.Capability.Version = 2
	if n, e := Normalize(r); e != nil || n.Status != "unsupported" || len(n.Data) != 0 {
		t.Fatal("future schema")
	}
	r = report(v)
	r.Status = "failed"
	if _, e := Normalize(r); e == nil {
		t.Fatal("failed data accepted")
	}
}
func TestCPUAndTargets(t *testing.T) {
	for _, x := range []struct {
		before, after uint64
		elapsed       time.Duration
		n             uint32
		want          int
	}{{0, 10000000, time.Second, 4, 2500}, {0, 0, time.Second, 4, 0}, {4, 3, time.Second, 4, -1}, {0, 1, time.Second, 0, -1}, {0, 1, 0, 4, -1}, {0, 50000000, time.Second, 1, -1}} {
		v := CPU(x.before, x.after, x.elapsed, x.n)
		if x.want < 0 {
			if v != nil {
				t.Fatal("invalid counters")
			}
		} else if v == nil || int(*v) != x.want {
			t.Fatal("CPU math", v, x)
		}
	}
	if Manageable(4, "fixture.exe") || Manageable(50, "OpenRMM-Agent.exe") || Manageable(50, "lsass.exe") || !Manageable(50, "fixture.exe") {
		t.Fatal("protected process")
	}
}

type fakeAdapter struct{}

func (fakeAdapter) Collect(context.Context) (protocol.Processes, error) {
	return protocol.Processes{Coverage: Coverage, Items: []protocol.Process{}}, nil
}
func (fakeAdapter) Execute(context.Context, protocol.ProcessAction) protocol.ProcessResult {
	return protocol.ProcessResult{}
}
func TestModule(t *testing.T) {
	if _, e := (Module{Adapter: fakeAdapter{}}).Collect(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func FuzzNormalize(f *testing.F) {
	f.Add([]byte(fmt.Sprintf(`{"coverage":%q,"items":[]}`, Coverage)))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := protocol.FeatureReport{Capability: Capability, Status: "ok", Data: b}
		if v, e := Normalize(r); e == nil {
			if _, e = Normalize(v); e != nil {
				t.Fatal("not stable")
			}
		}
	})
}

func TestBoundSkipsInvalidAndCapsDeterministically(t *testing.T) {
	items := []protocol.Process{{PID: 9, Name: "ok.exe"}, {PID: 8, Name: "bad\x01name"}, {PID: 7, Name: ""}, {PID: 9, Name: "dup.exe"}, {PID: 6, Name: " padded"}, {PID: 5, Name: "five.exe"}}
	kept, skipped := Bound(items, nil)
	if skipped != 4 || len(kept) != 2 || kept[0].PID != 5 || kept[1].PID != 9 || kept[1].Name != "ok.exe" {
		t.Fatal("invalid items not skipped", kept, skipped)
	}
	// A flood of processes is capped by ascending PID, but delegated targets
	// are always kept regardless of their PID.
	flood := []protocol.Process{}
	for i := MaxItems + 500; i > 0; i-- {
		flood = append(flood, protocol.Process{PID: uint32(i * 4), Name: "flood.exe"})
	}
	target := protocol.Process{PID: uint32((MaxItems + 400) * 4), Name: "target.exe"}
	flood = append(flood, target)
	kept, skipped = Bound(flood, func(p protocol.Process) bool { return p.Name == "target.exe" })
	if len(kept) != MaxItems || skipped != len(flood)-MaxItems {
		t.Fatal("cap not applied", len(kept), skipped)
	}
	found := false
	for i, p := range kept {
		if i > 0 && kept[i-1].PID >= p.PID {
			t.Fatal("not sorted by PID")
		}
		found = found || p == target
	}
	if !found || kept[0].PID != 4 {
		t.Fatal("delegated target or low PIDs displaced")
	}
	again, _ := Bound(flood, func(p protocol.Process) bool { return p.Name == "target.exe" })
	if fmt.Sprint(again) != fmt.Sprint(kept) {
		t.Fatal("selection not deterministic")
	}
	v := protocol.Processes{Coverage: Coverage, Items: kept, Skipped: skipped}
	if !Valid(v) {
		t.Fatal("bounded snapshot invalid")
	}
}
func TestBoundKeepsReportUnderByteLimit(t *testing.T) {
	// Maximum-length names that expand under JSON escaping cannot push the
	// report over 1 MiB; the excess is skipped, not a failed snapshot.
	items := []protocol.Process{}
	for i := range MaxItems {
		items = append(items, protocol.Process{PID: uint32(i + 5), Name: strings.Repeat("<", 260)})
	}
	kept, skipped := Bound(items, nil)
	cpu, memory := uint32(10000), uint64(1<<60)
	for i := range kept {
		kept[i].Start, kept[i].CPU, kept[i].Memory = "18446744073709551615", &cpu, &memory
	}
	if skipped == 0 || len(kept)+skipped != MaxItems {
		t.Fatal("byte budget not applied", len(kept), skipped)
	}
	b, e := (Module{Adapter: listAdapter{protocol.Processes{Coverage: Coverage, Items: kept, Skipped: skipped}}}).Collect(context.Background())
	if e != nil || len(b) > MaxBytes {
		t.Fatal("bounded snapshot rejected", e, len(b))
	}
}

type listAdapter struct{ v protocol.Processes }

func (a listAdapter) Collect(context.Context) (protocol.Processes, error) { return a.v, nil }
func (listAdapter) Execute(context.Context, protocol.ProcessAction) protocol.ProcessResult {
	return protocol.ProcessResult{}
}
func TestModuleSkipsInsteadOfFailing(t *testing.T) {
	v := protocol.Processes{Coverage: Coverage, Items: []protocol.Process{{PID: 100, Name: "ok.exe"}, {PID: 101, Name: "a\tb"}}, Skipped: 2}
	b, e := (Module{Adapter: listAdapter{v}}).Collect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	r, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: b})
	var out protocol.Processes
	if e != nil || json.Unmarshal(r.Data, &out) != nil || len(out.Items) != 1 || out.Skipped != 3 {
		t.Fatal("skip count not carried", string(r.Data), e)
	}
}
func TestSkippedFieldSchema(t *testing.T) {
	v := protocol.Processes{Coverage: Coverage, Items: []protocol.Process{{PID: 100, Name: "fixture.exe"}}}
	old := report(v)
	if strings.Contains(string(old.Data), "skipped") {
		t.Fatal("zero skip count serialized")
	}
	if _, e := Normalize(old); e != nil {
		t.Fatal("agent without skip count rejected", e)
	}
	for _, n := range []string{`0`, `12`, `1048576`} {
		r := report(v)
		r.Data = []byte(strings.Replace(string(r.Data), `"items":`, `"skipped":`+n+`,"items":`, 1))
		if _, e := Normalize(r); e != nil {
			t.Fatal("valid skip count rejected", n, e)
		}
	}
	for _, n := range []string{`-1`, `1048577`, `"3"`, `1.5`} {
		r := report(v)
		r.Data = []byte(strings.Replace(string(r.Data), `"items":`, `"skipped":`+n+`,"items":`, 1))
		if _, e := Normalize(r); e == nil {
			t.Fatal("invalid skip count accepted", n)
		}
	}
}
func TestOpenRMMExecutablesProtected(t *testing.T) {
	for _, name := range []string{"openrmm-agent.exe", "openrmm-update-helper.exe", "openrmm-desktop.exe", "OpenRMM-Desktop.EXE"} {
		if Manageable(50, name) {
			t.Fatal("OpenRMM component manageable", name)
		}
	}
	if !Manageable(50, "notepad.exe") {
		t.Fatal("ordinary process refused")
	}
}
