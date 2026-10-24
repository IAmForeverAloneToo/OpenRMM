// Package logons collects the logon history of a device: the
// successful interactive, remote and network logons (event 4624) from the
// Windows Security log. Unlike a snapshot module it is incremental: the agent
// keeps a cursor in its state directory and sends each logon once, oldest
// first, advancing the cursor only after the server settled the report. It
// belongs to the Sessions feature; the server keeps 365 days.
package logons

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "logon_history", Version: 1}

const (
	Interval = 5 * time.Minute
	Timeout  = time.Minute
	MaxBytes = 512 * 1024
	// MaxLogons are sent per report; MaxScan events are read per collection
	// (filtered service and machine logons included).
	MaxLogons = 500
	MaxScan   = 5000
	// Backfill is how far back a first collection (no cursor) reads.
	Backfill = 30 * 24 * time.Hour
)

// Types maps the 4624 LogonType values the history keeps.
var Types = map[string]string{"2": "interactive", "3": "network", "8": "network_cleartext", "10": "remote", "11": "cached"}

// Reader reads Security log events oldest first: each receives one event's
// XML and returns false to stop.
type Reader interface {
	Read(ctx context.Context, xpath string, max int, each func(raw string) bool) error
}

// Cursor is the last event sent: its record ID and exact SystemTime. Events
// with a higher record ID are new. The time only detects a cleared log
// (record IDs restart): then events after that time are read once.
type Cursor struct {
	Record uint64 `json:"record"`
	Time   string `json:"time"`
}

type Module struct {
	Reader Reader
	// Path keeps the cursor across restarts; empty keeps it in memory only.
	Path string

	mu      sync.Mutex
	loaded  bool
	cursor  Cursor
	pending *Cursor
}

func (*Module) Capability() protocol.Capability { return Capability }

var stampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)

func (c Cursor) valid() bool {
	return c.Record == 0 && c.Time == "" || c.Record > 0 && stampPattern.MatchString(c.Time)
}

// Probe is the XPath of the first event at or after the cursor's record: the
// cursor's own event when the log still holds it.
func Probe(c Cursor) string {
	return fmt.Sprintf("*[System[EventRecordID >= %d]]", c.Record)
}

// Query is the XPath of the logons after a cursor; cleared reads by time
// instead of record ID, once, after the log was cleared.
func Query(c Cursor, cleared bool) string {
	after := fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", Backfill.Milliseconds())
	switch {
	case c.Record > 0 && cleared:
		after = fmt.Sprintf("TimeCreated[@SystemTime > '%s']", c.Time)
	case c.Record > 0:
		after = fmt.Sprintf("EventRecordID > %d", c.Record)
	}
	types := make([]string, 0, len(Types))
	for _, k := range []string{"2", "3", "8", "10", "11"} {
		types = append(types, fmt.Sprintf("Data[@Name='LogonType']='%s'", k))
	}
	return fmt.Sprintf("*[System[EventID=4624 and %s]] and *[EventData[%s]]", after, strings.Join(types, " or "))
}

func (m *Module) load() {
	if m.loaded {
		return
	}
	m.loaded = true
	if m.Path == "" {
		return
	}
	raw, e := os.ReadFile(m.Path)
	var c Cursor
	if e == nil && len(raw) < 1024 && json.Unmarshal(raw, &c) == nil && c.valid() {
		m.cursor = c
	}
}

func (m *Module) Collect(ctx context.Context) (json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	m.pending = nil
	// The log was cleared when the cursor's record is gone and nothing
	// follows it, or its record ID now holds another event. A record that
	// rolled off a full log is followed by newer ones: not cleared.
	cleared := false
	if m.cursor.Record > 0 {
		found := false
		if e := m.Reader.Read(ctx, Probe(m.cursor), 1, func(raw string) bool {
			found = true
			if record, at, ok := header(raw); ok {
				cleared = record == m.cursor.Record && at != m.cursor.Time
			}
			return false
		}); e != nil {
			return nil, e
		}
		cleared = cleared || !found
	}
	v := protocol.Logons{Logons: []protocol.Logon{}}
	next, used, scanned := m.cursor, 0, 0
	e := m.Reader.Read(ctx, Query(m.cursor, cleared), MaxScan, func(raw string) bool {
		scanned++
		l, c, keep, e := Parse(raw)
		if e != nil {
			return true // unreadable: skipped; later events move the cursor past it
		}
		if keep && LogonValid(l) {
			b, _ := json.Marshal(l)
			if len(v.Logons) == MaxLogons || used+len(b)+64 > MaxBytes {
				v.More = true
				return false
			}
			used += len(b) + 1
			v.Logons = append(v.Logons, l)
		}
		next = c
		return true
	})
	if e != nil {
		return nil, e
	}
	if scanned >= MaxScan {
		v.More = true
	}
	if !Valid(v) {
		return nil, features.ErrReport
	}
	m.pending = &next
	return json.Marshal(v)
}

// Settled advances the cursor past the last collected report once the server
// accepted it. A rejected report (for example by a server that predates
// logon history) is collected again: events invalid on their own were already
// left out by Collect, so a rejection never blocks on one event.
func (m *Module) Settled(accepted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil || !accepted {
		m.pending = nil
		return
	}
	m.cursor, m.pending = *m.pending, nil
	if m.Path == "" {
		return
	}
	raw, _ := json.Marshal(m.cursor)
	if os.WriteFile(m.Path+".tmp", raw, 0600) == nil {
		_ = os.Rename(m.Path+".tmp", m.Path)
	}
}

// Service, anonymous and machine accounts are left out: they log on all the
// time and say nothing about who used the device.
func skipped(sid, user string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7":
		return true
	}
	return strings.HasPrefix(sid, "S-1-5-90-") || strings.HasPrefix(sid, "S-1-5-96-") || strings.HasSuffix(user, "$") || strings.EqualFold(user, "ANONYMOUS LOGON")
}

func clean(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "-" {
		return ""
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

type eventXML struct {
	System struct {
		ID      uint32 `xml:"EventID"`
		Record  uint64 `xml:"EventRecordID"`
		Created struct {
			At string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

var (
	recordPattern  = regexp.MustCompile(`<EventRecordID>([0-9]{1,19})</EventRecordID>`)
	createdPattern = regexp.MustCompile(`<TimeCreated SystemTime=['"]([^'"<>]{1,40})['"]`)
)

// header reads an event's record ID and exact SystemTime from the fixed
// System section, also when the event data would not decode as XML, so the
// cursor still moves past such an event.
func header(raw string) (uint64, string, bool) {
	if len(raw) > 512*1024 {
		return 0, "", false
	}
	r, t := recordPattern.FindStringSubmatch(raw), createdPattern.FindStringSubmatch(raw)
	if r == nil || t == nil || !stampPattern.MatchString(t[1]) {
		return 0, "", false
	}
	record, e := strconv.ParseUint(r[1], 10, 64)
	if e != nil || record == 0 || record > 1<<62 {
		return 0, "", false
	}
	return record, t[1], true
}

// Parse reads one 4624 event: the logon, the cursor it advances to, and
// whether the history keeps it. An error means not even the record ID and
// time could be read.
func Parse(raw string) (protocol.Logon, Cursor, bool, error) {
	record, stamp, ok := header(raw)
	if !ok {
		return protocol.Logon{}, Cursor{}, false, features.ErrReport
	}
	c := Cursor{Record: record, Time: stamp}
	var v eventXML
	if xml.Unmarshal([]byte(raw), &v) != nil || v.System.ID != 4624 {
		return protocol.Logon{}, c, false, nil
	}
	at, e := time.Parse(time.RFC3339Nano, stamp)
	if e != nil || at.Unix() <= 0 {
		return protocol.Logon{}, c, false, nil
	}
	data := map[string]string{}
	for _, d := range v.Data {
		data[d.Name] = d.Value
	}
	kind, ok := Types[strings.TrimSpace(data["LogonType"])]
	sid, user := clean(data["TargetUserSid"], 184), clean(data["TargetUserName"], 256)
	if !ok || skipped(sid, user) {
		return protocol.Logon{}, c, false, nil
	}
	l := protocol.Logon{RecordID: v.System.Record, Time: at.Unix(), User: user, Domain: clean(data["TargetDomainName"], 256), SID: sid, Type: kind,
		Workstation: clean(data["WorkstationName"], 256), AuthPackage: clean(data["AuthenticationPackageName"], 64), LogonProcess: clean(data["LogonProcessName"], 64),
		LogonID: clean(data["TargetLogonId"], 32), Elevated: strings.TrimSpace(data["ElevatedToken"]) == "%%1842"}
	if ip, e := netip.ParseAddr(clean(data["IpAddress"], 64)); e == nil {
		l.SourceIP = ip.Unmap().WithZone("").String()
	}
	if port, e := strconv.Atoi(clean(data["IpPort"], 8)); e == nil && port > 0 && port <= 65535 {
		l.SourcePort = port
	}
	return l, c, true, nil
}

func text(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func LogonValid(l protocol.Logon) bool {
	kinds := []string{"interactive", "network", "network_cleartext", "remote", "cached"}
	if l.RecordID == 0 || l.RecordID > 1<<62 || l.Time <= 0 || l.Time > 253402300799 || !slices.Contains(kinds, l.Type) || l.SourcePort < 0 || l.SourcePort > 65535 {
		return false
	}
	if l.SourceIP != "" {
		if ip, e := netip.ParseAddr(l.SourceIP); e != nil || ip.Is4In6() || ip.Zone() != "" || ip.String() != l.SourceIP {
			return false
		}
	}
	return text(l.User, 256) && text(l.Domain, 256) && text(l.SID, 184) && text(l.Workstation, 256) && text(l.AuthPackage, 64) && text(l.LogonProcess, 64) && text(l.LogonID, 32)
}

func Valid(v protocol.Logons) bool {
	if v.Logons == nil || len(v.Logons) > MaxLogons {
		return false
	}
	for _, l := range v.Logons {
		if !LogonValid(l) {
			return false
		}
	}
	return true
}

func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return features.ErrReport
	}
	return nil
}

// Normalize checks a report received from an agent.
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	if r.Capability.Name != Capability.Name || r.Capability.Version < 1 || r.Capability.Version > 999 {
		return r, features.ErrReport
	}
	switch r.Status {
	case "ok", "failed", "disabled", "unsupported":
	default:
		return r, features.ErrReport
	}
	if r.Capability.Version != 1 {
		r.Status, r.Data = "unsupported", nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) > 0 {
			return r, features.ErrReport
		}
		return r, nil
	}
	var v protocol.Logons
	if len(r.Data) > MaxBytes || decode(r.Data, &v) != nil || !Valid(v) {
		return r, features.ErrReport
	}
	r.Data, _ = json.Marshal(v)
	return r, nil
}
