package software

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func goodReport() protocol.FeatureReport {
	return protocol.FeatureReport{Capability: CapabilityV1, Status: "ok", Data: json.RawMessage(`{"coverage":"machine_uninstall_registry_32_64","entries":[{"id":"` + strings.Repeat("a", 64) + `","registry_view":"64","name":"Example","version":"1","publisher":""}]}`)}
}
func TestSoftwareStrictSchema(t *testing.T) {
	good := goodReport()
	if _, e := Normalize(good); e != nil {
		t.Fatal(e)
	}
	for _, data := range []string{
		`{}`, `{"coverage":"machine_uninstall_registry_32_64","entries":null}`,
		strings.Replace(string(good.Data), `"version":"1",`, "", 1),
		strings.Replace(string(good.Data), `"publisher":""`, `"publisher":null`, 1),
		strings.Replace(string(good.Data), `"registry_view":"64"`, `"registry_view":"arm64"`, 1),
		strings.Replace(string(good.Data), `"Example"`, `"x\nscript"`, 1),
		strings.Replace(string(good.Data), `"Example"`, `" Example "`, 1),
		strings.Replace(string(good.Data), `"publisher":""`, `"publisher":"","command":"run"`, 1),
		string(good.Data) + `{}`, strings.Repeat(" ", MaxBytes+1),
	} {
		r := good
		r.Data = json.RawMessage(data)
		if _, e := Normalize(r); !errors.Is(e, features.ErrReport) {
			t.Fatal("invalid software accepted")
		}
	}
	var value protocol.Software
	json.Unmarshal(good.Data, &value)
	value.Entries = append(value.Entries, value.Entries[0])
	if Valid(value) {
		t.Fatal("duplicate identity accepted")
	}
	value.Entries = make([]protocol.SoftwareEntry, MaxEntries+1)
	if Valid(value) {
		t.Fatal("unbounded registrations")
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		r := good
		r.Status = status
		if _, e := Normalize(r); e == nil {
			t.Fatal("failure carried snapshot")
		}
		r.Data = nil
		if _, e := Normalize(r); e != nil {
			t.Fatal(e)
		}
	}
	good.Capability.Version = 3
	v, e := Normalize(good)
	if e != nil || v.Status != "unsupported" || v.Data != nil {
		t.Fatal("unknown version interpreted")
	}
}

type fakeCollector struct{ err error }

func (f fakeCollector) Collect(context.Context) (protocol.Software, error) {
	return protocol.Software{Coverage: Coverage, Entries: []protocol.SoftwareEntry{}}, f.err
}
func TestModuleFailureAndEmptyBaseline(t *testing.T) {
	if _, e := (Module{Collector: fakeCollector{features.ErrUnsupported}}).Collect(context.Background()); !errors.Is(e, features.ErrUnsupported) {
		t.Fatal("unsupported collector hidden")
	}
	b, e := (Module{Collector: fakeCollector{}}).Collect(context.Background())
	if e != nil || !strings.Contains(string(b), `"entries":[]`) {
		t.Fatal("empty complete snapshot lost")
	}
}
func FuzzSoftwareNormalize(f *testing.F) {
	f.Add([]byte(goodReport().Data))
	f.Add([]byte(`{"entries":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxBytes+1 {
			t.Skip()
		}
		r := protocol.FeatureReport{Capability: CapabilityV1, Status: "ok", Data: b}
		v, e := Normalize(r)
		if e == nil {
			var s protocol.Software
			if json.Unmarshal(v.Data, &s) != nil || !Valid(s) {
				t.Fatal("accepted invalid software")
			}
		}
	})
}

func TestSoftwareCountAndTextBoundaries(t *testing.T) {
	v := protocol.Software{Coverage: Coverage, Entries: []protocol.SoftwareEntry{}}
	for i := range MaxEntries {
		v.Entries = append(v.Entries, protocol.SoftwareEntry{ID: fmt.Sprintf("%064x", i), View: "64", Name: "Example", Version: "", Publisher: ""})
	}
	report := func() protocol.FeatureReport {
		b, _ := json.Marshal(v)
		return protocol.FeatureReport{Capability: CapabilityV1, Status: "ok", Data: b}
	}
	if _, e := Normalize(report()); e != nil {
		t.Fatal("maximum supported count rejected", e)
	}
	v.Entries = append(v.Entries, protocol.SoftwareEntry{ID: fmt.Sprintf("%064x", MaxEntries), View: "64", Name: "Example"})
	if _, e := Normalize(report()); e == nil {
		t.Fatal("count above streaming limit accepted")
	}
	v.Entries = v.Entries[:1]
	v.Entries[0].Name = strings.Repeat("x", 513)
	if _, e := Normalize(report()); e == nil {
		t.Fatal("oversized display name accepted")
	}
}

func entry(i int, name string) protocol.SoftwareEntry {
	return protocol.SoftwareEntry{ID: fmt.Sprintf("%064x", i), View: "64", Name: name}
}
func TestBoundSkipsInvalidEntries(t *testing.T) {
	in := []protocol.SoftwareEntry{entry(3, "Three"), entry(1, "bad\x07name"), entry(2, ""), entry(4, strings.Repeat("x", 513)), entry(3, "Duplicate"), entry(0, "Zero"), {ID: "not-hex", View: "64", Name: "x"}}
	kept, skipped := Bound(in)
	if skipped != 5 || len(kept) != 2 || kept[0].Name != "Zero" || kept[1].Name != "Three" {
		t.Fatal("invalid registrations not skipped", kept, skipped)
	}
}
func TestBoundCapsDeterministically(t *testing.T) {
	in := []protocol.SoftwareEntry{}
	for i := MaxEntries + 100; i > 0; i-- {
		in = append(in, entry(i, "Example"))
	}
	kept, skipped := Bound(in)
	if len(kept) != MaxEntries || skipped != 100 || kept[0].ID != fmt.Sprintf("%064x", 1) || kept[MaxEntries-1].ID != fmt.Sprintf("%064x", MaxEntries) {
		t.Fatal("cap not deterministic", len(kept), skipped)
	}
	// Long metadata that expands under JSON escaping stays under 1 MiB.
	for i := range in {
		in[i].Name, in[i].Publisher, in[i].Version = strings.Repeat("<", 512), strings.Repeat("&", 512), strings.Repeat(">", 256)
	}
	kept, skipped = Bound(in)
	b, _ := json.Marshal(protocol.Software{Coverage: Coverage, Entries: kept, Skipped: skipped})
	if skipped <= 100 || len(kept)+skipped != len(in) || len(b) > MaxBytes {
		t.Fatal("byte budget not applied", len(kept), skipped, len(b))
	}
}

type listCollector struct{ v protocol.Software }

func (c listCollector) Collect(context.Context) (protocol.Software, error) { return c.v, nil }
func TestModuleSkipsInsteadOfFailing(t *testing.T) {
	v := protocol.Software{Coverage: Coverage, Entries: []protocol.SoftwareEntry{entry(1, "Good"), entry(2, "Bad\x00")}, Skipped: 4}
	b, e := (Module{Collector: listCollector{v}}).Collect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	r, e := Normalize(protocol.FeatureReport{Capability: CapabilityV1, Status: "ok", Data: b})
	var out protocol.Software
	if e != nil || json.Unmarshal(r.Data, &out) != nil || len(out.Entries) != 1 || out.Skipped != 5 {
		t.Fatal("skip count not carried", string(r.Data), e)
	}
}
func TestSkippedFieldSchema(t *testing.T) {
	good := goodReport()
	for _, n := range []string{`0`, `7`, `1048576`} {
		r := good
		r.Data = json.RawMessage(strings.Replace(string(good.Data), `"entries":`, `"skipped":`+n+`,"entries":`, 1))
		if _, e := Normalize(r); e != nil {
			t.Fatal("valid skip count rejected", n, e)
		}
	}
	for _, n := range []string{`-1`, `1048577`, `"1"`, `true`} {
		r := good
		r.Data = json.RawMessage(strings.Replace(string(good.Data), `"entries":`, `"skipped":`+n+`,"entries":`, 1))
		if _, e := Normalize(r); e == nil {
			t.Fatal("invalid skip count accepted", n)
		}
	}
	r, _ := Normalize(good)
	if strings.Contains(string(r.Data), "skipped") {
		t.Fatal("zero skip count serialized")
	}
}

// Version 2 reports carry per-user registrations of the loaded
// user hives; each names a user that was read, and version 1 has none.
func TestPerUserSoftwareSchema(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	user := protocol.SoftwareEntry{ID: strings.Repeat("b", 64), View: "user", Name: "Per-user app", User: `PC\alice`, UserSID: sid}
	machine := protocol.SoftwareEntry{ID: strings.Repeat("a", 64), View: "64", Name: "Machine app"}
	report := func(c protocol.Capability, v protocol.Software) (protocol.FeatureReport, error) {
		b, _ := json.Marshal(v)
		return Normalize(protocol.FeatureReport{Capability: c, Status: "ok", Data: b})
	}
	good := protocol.Software{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{user, machine}, Users: []protocol.SoftwareUser{{SID: sid, Name: `PC\alice`}, {SID: "S-1-12-1-5-6-7-8", Name: `AzureAD\bob`}}}
	r, e := report(Capability, good)
	var back protocol.Software
	if e != nil || json.Unmarshal(r.Data, &back) != nil || len(back.Users) != 2 || back.Users[0].SID != "S-1-12-1-5-6-7-8" || back.Entries[1].UserSID != sid {
		t.Fatal("version 2", e, string(r.Data))
	}
	if _, e = report(Capability, protocol.Software{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{}}); e != nil {
		t.Fatal("nobody signed in", e)
	}
	for i, v := range []protocol.Software{
		{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{user}},
		{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{{ID: user.ID, View: "user", Name: "x", UserSID: sid}}, Users: good.Users},
		{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{{ID: machine.ID, View: "64", Name: "x", User: "a"}}},
		{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{}, Users: []protocol.SoftwareUser{{SID: "S-1-5-18", Name: "SYSTEM"}}},
		{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{}, Users: []protocol.SoftwareUser{{SID: sid, Name: "a"}, {SID: sid, Name: "b"}}},
		{Coverage: Coverage, Entries: []protocol.SoftwareEntry{machine}},
	} {
		if _, e = report(Capability, v); e == nil {
			t.Fatal("accepted", i)
		}
	}
	if _, e = report(CapabilityV1, good); e == nil {
		t.Fatal("version 1 accepted users")
	}
	if _, e = report(CapabilityV1, protocol.Software{Coverage: Coverage, Entries: []protocol.SoftwareEntry{machine}}); e != nil {
		t.Fatal("version 1", e)
	}
}
