package eventlogs

import (
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"testing"
)

func validFilter() protocol.EventFilter {
	return protocol.EventFilter{Channel: "System", From: 1800000000, To: 1800086400, Level: -1, EventID: -1, Limit: 25}
}
func TestStructuredFiltersAndInjectionRejection(t *testing.T) {
	f := validFilter()
	f.Provider = "Service Control Manager"
	f.Level = 2
	f.EventID = 7000
	f.Before = 123
	x, e := XPath(f)
	if e != nil || !strings.Contains(x, "Provider[@Name='Service Control Manager']") || !strings.Contains(x, "EventRecordID < 123") || !strings.Contains(x, "Level=2") {
		t.Fatal("wrong structured filter", e)
	}
	for _, mutate := range []func(*protocol.EventFilter){func(f *protocol.EventFilter) { f.Channel = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx" }, func(f *protocol.EventFilter) { f.Channel = "../System.evtx" }, func(f *protocol.EventFilter) { f.Channel = "System' or '" }, func(f *protocol.EventFilter) { f.Provider = "x'] or *['x" }, func(f *protocol.EventFilter) { f.From = 0 }, func(f *protocol.EventFilter) { f.To = f.From + 32*86400 }, func(f *protocol.EventFilter) { f.Level = 6 }, func(f *protocol.EventFilter) { f.EventID = 65536 }, func(f *protocol.EventFilter) { f.Limit = 251 }, func(f *protocol.EventFilter) { f.XPath = "*[System[Level=2]] or *[System]" }, func(f *protocol.EventFilter) { f.XPath = "Event[System]" }, func(f *protocol.EventFilter) { f.XPath = "*[EventData[Data='x]]" }, func(f *protocol.EventFilter) { f.XPath = "*[System]]" }} {
		v := validFilter()
		mutate(&v)
		if _, e := XPath(v); e == nil {
			t.Fatal("invalid/injectable filter accepted", v)
		}
	}
	// Any channel by name, raw XPath joined by "and".
	f = validFilter()
	f.Channel, f.Limit = "Microsoft-Windows-Sysmon/Operational", 250
	f.XPath = "*[EventData[Data[@Name='Image'] and (Data='C:\\x]y.exe' or Data=\"a[b\")]]"
	x, e = XPath(f)
	if e != nil || !strings.HasSuffix(x, "]] and "+f.XPath) {
		t.Fatal("raw XPath not combined", x, e)
	}
	if FilterValidV1(f) || !FilterValidV1(validFilter()) {
		t.Fatal("version 1 filter rules")
	}
}

const eventXML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Example"/><EventID Qualifiers="0">42</EventID><Level>2</Level><TimeCreated SystemTime="2027-01-15T08:00:00.1234567Z"/><EventRecordID>100</EventRecordID><Channel>System</Channel></System><EventData><Data>&lt;script&gt;untrusted&lt;/script&gt;</Data></EventData></Event>`

func TestEventParsingAndBoundedResults(t *testing.T) {
	v, e := ParseEvent(eventXML)
	if e != nil || v.RecordID != 100 || v.EventID != 42 || v.Provider != "Example" || v.MessageStatus != "unavailable" {
		t.Fatal("event XML parsing failed", e)
	}
	f := protocol.EventFilter{Channel: "System", From: v.Time - 10, To: v.Time + 10, Level: -1, EventID: -1, Limit: 25}
	r := protocol.EventResult{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Outcome: "ok", Events: []protocol.WindowsEvent{v}, More: true, NextBefore: 100}
	if !ResultValid(r, f) {
		t.Fatal("valid result rejected")
	}
	r.Events = append(r.Events, v)
	if ResultValid(r, f) {
		t.Fatal("duplicate/out-of-order event accepted")
	}
	r.Events = r.Events[:1]
	r.NextBefore = 99
	if ResultValid(r, f) {
		t.Fatal("incorrect next cursor accepted")
	}
	r.More = false
	r.NextBefore = 0
	// Forwarded events keep their original channel.
	r.Events[0].Channel = "Security"
	if !ResultValid(r, f) {
		t.Fatal("forwarded event rejected")
	}
	large := strings.Replace(eventXML, "</EventData>", strings.Repeat("é", 10000)+"</EventData>", 1)
	v, e = ParseEvent(large)
	if e != nil || !v.XMLTruncated || len(v.XML) > 8192 {
		t.Fatal("XML truncation failed", e)
	}
	for _, s := range []string{"", `<Event/>`, strings.Replace(eventXML, "SystemTime=", "MissingTime=", 1), `<!DOCTYPE x [<!ENTITY ext SYSTEM "file:///secret">]><Event>&ext;</Event>`} {
		if _, e := ParseEvent(s); e == nil {
			t.Fatal("invalid/entity event XML accepted")
		}
	}
}
func TestSupportNormalization(t *testing.T) {
	for _, s := range []string{`null`, `{}`, `{"system":"readable"}`, `{"system":"readable","application":"readable","device_id":"x"}`} {
		if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(s)}); e == nil {
			t.Fatal("invalid support accepted")
		}
	}
	r, e := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "event_logs", Version: 4}, Status: "ok", Data: json.RawMessage(`{"future":1}`)})
	if e != nil || r.Status != "unsupported" || len(r.Data) != 0 {
		t.Fatal("new version not discarded")
	}
	for _, s := range []string{`{"system":"readable","application":"denied"}`, `{"system":"readable","application":"denied","channels":{"Security":"readable","Microsoft-Windows-Sysmon/Operational":"unavailable"}}`} {
		if _, e := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "event_logs", Version: 1 + strings.Count(s, "channels")}, Status: "ok", Data: json.RawMessage(s)}); e != nil {
			t.Fatal("valid support rejected", s)
		}
	}
	if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(`{"system":"readable","application":"denied","channels":{"C:\\x.evtx":"readable"}}`)}); e == nil {
		t.Fatal("invalid channel name accepted")
	}
}
func FuzzEventXML(f *testing.F) {
	f.Add(eventXML)
	f.Add(`<Event/>`)
	f.Fuzz(func(t *testing.T, s string) {
		v, e := ParseEvent(s)
		if e == nil && !EventValid(v) {
			t.Fatal("invalid event accepted")
		}
	})
}

func TestOneBadEventIsSkippedNotFatal(t *testing.T) {
	good, e := ParseEvent(eventXML)
	if e != nil {
		t.Fatal(e)
	}
	f := protocol.EventFilter{Channel: "System", From: good.Time - 10, To: good.Time + 10, Level: -1, EventID: -1, Limit: 25}
	r := protocol.EventResult{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Outcome: "ok", Events: []protocol.WindowsEvent{}}
	// Provider-defined levels above 5 are legitimate Windows events.
	custom, e := ParseEvent(strings.Replace(eventXML, "<Level>2</Level>", "<Level>16</Level>", 1))
	if e != nil || custom.Level != 16 {
		t.Fatal("custom level rejected", e)
	}
	Accept(&r, f, custom, nil)
	_, badLevel := ParseEvent(strings.Replace(eventXML, "<Level>2</Level>", "<Level>300</Level>", 1))
	Accept(&r, f, protocol.WindowsEvent{}, badLevel)
	control, e := ParseEvent(strings.Replace(strings.Replace(eventXML, `Name="Example"`, `Name="Ex&#x1;ample"`, 1), "<EventRecordID>100", "<EventRecordID>99", 1))
	if e == nil {
		t.Fatal("control character provider accepted", control)
	}
	Accept(&r, f, control, e)
	Accept(&r, f, good, nil) // same record ID again: out of order
	older := good
	older.RecordID = 50
	Accept(&r, f, older, nil)
	other := good
	other.RecordID, other.Time = 40, good.Time+100 // outside the time range
	Accept(&r, f, other, nil)
	if len(r.Events) != 2 || r.Skipped != 4 || r.Events[1].RecordID != 50 || !ResultValid(r, f) {
		t.Fatal("bad events not skipped", r.Skipped, len(r.Events))
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"skipped":4`) {
		t.Fatal("skip count not serialized")
	}
	for _, n := range []int{-1, MaxSkipped + 1} {
		x := r
		x.Skipped = n
		if ResultValid(x, f) {
			t.Fatal("invalid skip count accepted", n)
		}
	}
	failed := protocol.EventResult{ID: r.ID, Outcome: "failed", Events: []protocol.WindowsEvent{}, Skipped: 1}
	if ResultValid(failed, f) {
		t.Fatal("skip count on failed result")
	}
	failed.Skipped = 0
	if !ResultValid(failed, f) {
		t.Fatal("failed result rejected")
	}
}
