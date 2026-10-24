package logons

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func event(record uint64, kind, user, sid, ip string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><EventRecordID>%d</EventRecordID><TimeCreated SystemTime="2026-10-23T03:40:%02d.1234567Z"/></System>
<EventData><Data Name="TargetUserSid">%s</Data><Data Name="TargetUserName">%s</Data><Data Name="TargetDomainName">PC</Data><Data Name="TargetLogonId">0x3e7a1</Data>
<Data Name="LogonType">%s</Data><Data Name="LogonProcessName">User32 </Data><Data Name="AuthenticationPackageName">Negotiate</Data><Data Name="WorkstationName">PC</Data>
<Data Name="IpAddress">%s</Data><Data Name="IpPort">51234</Data><Data Name="ElevatedToken">%%%%1842</Data></EventData></Event>`, record, record%60, sid, user, kind, ip)
}

type fake struct {
	events []string
	query  string
}

func (f *fake) Read(_ context.Context, xpath string, max int, each func(string) bool) error {
	var from uint64
	if _, e := fmt.Sscanf(xpath, "*[System[EventRecordID >= %d]]", &from); e == nil {
		for _, raw := range f.events {
			if r, _, ok := header(raw); ok && r >= from {
				each(raw)
				break
			}
		}
		return nil
	}
	f.query = xpath
	for i, raw := range f.events {
		if i == max || !each(raw) {
			break
		}
	}
	return nil
}

// Logons are parsed, service and machine logons left out, and the
// cursor advances only once the server settled the report.
func TestCollectCursorAndFilter(t *testing.T) {
	l, c, keep, e := Parse(event(7, "10", "alice", "S-1-5-21-1-2-3-1001", "::ffff:192.0.2.9"))
	if e != nil || !keep || l.Type != "remote" || l.User != "alice" || l.SourceIP != "192.0.2.9" || l.SourcePort != 51234 || !l.Elevated || l.LogonProcess != "User32" || c.Record != 7 || !LogonValid(l) {
		t.Fatalf("parse %+v %+v %v %v", l, c, keep, e)
	}
	for _, raw := range []string{event(8, "5", "svc", "S-1-5-21-1", "-"), event(9, "3", "PC$", "S-1-5-21-9", "-"), event(10, "2", "DWM-1", "S-1-5-90-0-1", "-"), event(11, "3", "ANONYMOUS LOGON", "S-1-5-7", "-")} {
		if _, c, keep, e := Parse(raw); e != nil || keep || c.Record == 0 {
			t.Fatal("kept", raw, e)
		}
	}
	if _, c, keep, e := Parse(strings.Replace(event(1, "2", "a", "S-1-5-21-1", "-"), "4624", "4625", 1)); e != nil || keep || c.Record != 1 {
		t.Fatal("other event accepted")
	}

	dir := t.TempDir()
	f := &fake{}
	for i := uint64(1); i <= MaxLogons+10; i++ {
		f.events = append(f.events, event(i, "2", "bob", "S-1-5-21-1-2-3-1002", "-"))
	}
	f.events = append([]string{event(100000, "5", "svc", "S-1-5-18", "-")}, f.events...)
	m := &Module{Reader: f, Path: filepath.Join(dir, "cursor.json")}
	raw, e := m.Collect(context.Background())
	var v protocol.Logons
	if e != nil || json.Unmarshal(raw, &v) != nil || len(v.Logons) != MaxLogons || !v.More || !strings.Contains(f.query, "timediff") {
		t.Fatal("first page", len(v.Logons), v.More, e, f.query)
	}
	// Not settled: the next collection starts again from the beginning.
	if _, e = m.Collect(context.Background()); e != nil || !strings.Contains(f.query, "timediff") {
		t.Fatal("unsettled cursor moved", f.query)
	}
	m.Settled(true)
	if !strings.Contains(f.query, "timediff") {
		t.Fatal(f.query)
	}
	// A restarted agent reads the cursor from its state directory.
	m = &Module{Reader: f, Path: filepath.Join(dir, "cursor.json")}
	f.events = f.events[MaxLogons+1:]
	raw, e = m.Collect(context.Background())
	v = protocol.Logons{}
	if e != nil || json.Unmarshal(raw, &v) != nil || len(v.Logons) != 10 || v.More || !strings.Contains(f.query, fmt.Sprintf("EventRecordID > %d", MaxLogons)) || strings.Contains(f.query, "SystemTime") {
		t.Fatal("second page", len(v.Logons), v.More, e, f.query)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "cursor.json")); e != nil || !strings.Contains(string(b), fmt.Sprintf(`"record":%d`, MaxLogons)) {
		t.Fatal("cursor file", string(b), e)
	}
}

func TestNormalizeLogons(t *testing.T) {
	good := protocol.Logons{Logons: []protocol.Logon{{RecordID: 1, Time: 1800000000, User: "a", Type: "network", SourceIP: "192.0.2.1"}}}
	b, _ := json.Marshal(good)
	if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: b}); e != nil {
		t.Fatal(e)
	}
	for _, edit := range []func(*protocol.Logon){
		func(l *protocol.Logon) { l.Type = "batch" },
		func(l *protocol.Logon) { l.SourceIP = "::ffff:192.0.2.1" },
		func(l *protocol.Logon) { l.SourceIP = "fe80::1%eth0" },
		func(l *protocol.Logon) { l.User = "a\nb" },
		func(l *protocol.Logon) { l.RecordID = 0 },
		func(l *protocol.Logon) { l.SourcePort = 70000 },
	} {
		v := protocol.Logons{Logons: []protocol.Logon{good.Logons[0]}}
		edit(&v.Logons[0])
		b, _ := json.Marshal(v)
		if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: b}); e == nil {
			t.Fatalf("accepted %+v", v)
		}
	}
	if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: []byte(`{"logons":null,"more":false}`)}); e == nil {
		t.Fatal("null list accepted")
	}
}

// An undecodable or invalid event is skipped and passed, a
// rejected report does not move the cursor, and a cleared log (the cursor's
// record gone with nothing after it, or reused by another event) is read by
// time once.
func TestCursorEdgeCases(t *testing.T) {
	bad := strings.Replace(event(3, "2", "eve", "S-1-5-21-1-2-3-1003", "-"), "<Data Name=\"TargetUserName\">eve", "<Data Name=\"TargetUserName\">&#x1;", 1)
	if _, c, keep, e := Parse(bad); e != nil || keep || c.Record != 3 {
		t.Fatal("undecodable event", c, keep, e)
	}
	f := &fake{events: []string{event(1, "2", "a", "S-1-5-21-1-2-3-1001", "-"), "<Event>garbage", bad, event(4, "2", "b", "S-1-5-21-1-2-3-1002", "-")}}
	m := &Module{Reader: f}
	raw, e := m.Collect(context.Background())
	var v protocol.Logons
	if e != nil || json.Unmarshal(raw, &v) != nil || len(v.Logons) != 2 {
		t.Fatal("skipping", string(raw), e)
	}
	m.Settled(false)
	if m.cursor.Record != 0 {
		t.Fatal("rejected report moved the cursor")
	}
	m.Collect(context.Background())
	m.Settled(true)
	if m.cursor.Record != 4 {
		t.Fatal("cursor", m.cursor)
	}
	// Nothing new: the cursor's own event is found; read by record ID.
	m.Collect(context.Background())
	if !strings.Contains(f.query, "EventRecordID > 4") {
		t.Fatal(f.query)
	}
	// Cleared: record 4 is gone and nothing follows it.
	f.events = []string{event(1, "2", "c", "S-1-5-21-1-2-3-1004", "-")}
	m.Collect(context.Background())
	if !strings.Contains(f.query, "@SystemTime > '2026-10-23T03:40:04") || strings.Contains(f.query, "EventRecordID") {
		t.Fatal("cleared", f.query)
	}
	// Cleared and refilled past the cursor: record 4 is another event.
	f.events = []string{strings.Replace(event(4, "2", "d", "S-1-5-21-1-2-3-1005", "-"), "03:40:04", "03:41:04", 1)}
	m.Collect(context.Background())
	if !strings.Contains(f.query, "@SystemTime >") {
		t.Fatal("reused record", f.query)
	}
	// Rolled off: record 4 is gone but newer records follow; by record ID.
	f.events = []string{event(9, "2", "e", "S-1-5-21-1-2-3-1006", "-")}
	m.Collect(context.Background())
	if !strings.Contains(f.query, "EventRecordID > 4") {
		t.Fatal("rolled off", f.query)
	}
}
