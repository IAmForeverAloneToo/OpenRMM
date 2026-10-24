// Package eventlogs provides structured, bounded, read-only local event queries.
package eventlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version 2: any channel by name, raw XPath, pages up to 250 events,
// readability of the key channels. Version 3: the agent
// runs event log searches (response action "events").
var Capability = protocol.Capability{Name: "event_logs", Version: 3}

const MaxResultBytes = 4 << 20

// resultBudget leaves room for the result envelope.
const resultBudget = MaxResultBytes - 64<<10
const MaxEvents = protocol.MaxEventPage

// MaxEventsV1 is the page size of version 1 agents.
const MaxEventsV1 = 25

// KeyChannels are probed for readability (capability version 2): the
// channels responders use most.
var KeyChannels = []string{
	"Security",
	"Setup",
	"Windows PowerShell",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
	"Microsoft-Windows-WinRM/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-Bits-Client/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	"Microsoft-Windows-CodeIntegrity/Operational",
}

type Adapter interface {
	Probe(context.Context) (protocol.EventLogSupport, error)
	Query(context.Context, protocol.EventQuery) protocol.EventResult
}
type Module struct{ Adapter Adapter }

func (Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Adapter.Probe(ctx)
	if e != nil {
		return nil, e
	}
	if !SupportValid(v) {
		return nil, features.ErrReport
	}
	return json.Marshal(v)
}
func SupportValid(v protocol.EventLogSupport) bool {
	valid := func(s string) bool { return s == "readable" || s == "denied" || s == "unavailable" }
	if !valid(v.System) || !valid(v.Application) || len(v.Channels) > 32 {
		return false
	}
	for name, state := range v.Channels {
		if !ValidChannel(name) || !valid(state) {
			return false
		}
	}
	return true
}

// ValidChannel accepts an event log channel name (protocol.ValidEventChannel).
func ValidChannel(s string) bool { return protocol.ValidEventChannel(s) }

// ValidXPath accepts one raw predicate (protocol.ValidEventXPath).
func ValidXPath(s string) bool { return protocol.ValidEventXPath(s) }
func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return features.ErrReport
	}
	return nil
}
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	if r.Capability.Name != Capability.Name || r.Capability.Version < 1 || r.Capability.Version > 999 {
		return r, features.ErrReport
	}
	switch r.Status {
	case "ok", "failed", "disabled", "unsupported":
	default:
		return r, features.ErrReport
	}
	if r.Capability.Version > Capability.Version {
		r.Status = "unsupported"
		r.Data = nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) > 0 {
			return r, features.ErrReport
		}
		return r, nil
	}
	var v protocol.EventLogSupport
	if decode(r.Data, &v) != nil || !SupportValid(v) {
		return r, features.ErrReport
	}
	r.Data, _ = json.Marshal(v)
	return r, nil
}
func text(s string, max int, empty bool) bool {
	if (!empty && s == "") || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func FilterValid(f protocol.EventFilter) bool { return protocol.EventFilterValid(f) }

// FilterValidV1 is what version 1 agents accept: System or Application, 25
// events, no raw XPath.
func FilterValidV1(f protocol.EventFilter) bool {
	return FilterValid(f) && (f.Channel == "System" || f.Channel == "Application") && f.Limit <= MaxEventsV1 && f.XPath == ""
}
func XPath(f protocol.EventFilter) (string, error) {
	if !FilterValid(f) {
		return "", features.ErrReport
	}
	parts := []string{"TimeCreated[@SystemTime >= '" + time.Unix(f.From, 0).UTC().Format(time.RFC3339) + "' and @SystemTime <= '" + time.Unix(f.To, 0).UTC().Format(time.RFC3339) + "']"}
	if f.Level >= 0 {
		parts = append(parts, "Level="+strconv.Itoa(f.Level))
	}
	if f.EventID >= 0 {
		parts = append(parts, "EventID="+strconv.Itoa(f.EventID))
	}
	if f.Provider != "" {
		parts = append(parts, "Provider[@Name='"+f.Provider+"']")
	}
	if f.Before > 0 {
		parts = append(parts, "EventRecordID < "+strconv.FormatUint(f.Before, 10))
	}
	query := "*[System[" + strings.Join(parts, " and ") + "]]"
	if f.XPath != "" {
		query += " and " + f.XPath
	}
	return query, nil
}

// ExportQuery is the event XPath of an .evtx export of the filter's events:
// the structured part without the page cursor, plus any raw XPath.
func ExportQuery(f protocol.EventFilter) (string, error) {
	f.Before, f.Limit = 0, 1
	return XPath(f)
}

// ValidExportQuery accepts the query of an export job: empty for the whole
// channel, one built by ExportQuery, or a raw predicate (ValidXPath) from the
// live response evtx command.
func ValidExportQuery(s string) bool {
	return s == "" || ValidXPath(s) || text(s, 8192, false) && strings.HasPrefix(s, "*[System[")
}
func clip(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s, true
}
func ParseEvent(raw string) (protocol.WindowsEvent, error) {
	var v struct {
		XMLName xml.Name `xml:"Event"`
		System  struct {
			Provider struct {
				Name string `xml:"Name,attr"`
			} `xml:"Provider"`
			ID      uint32 `xml:"EventID"`
			Level   int    `xml:"Level"`
			Record  uint64 `xml:"EventRecordID"`
			Channel string `xml:"Channel"`
			Created struct {
				At string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
		} `xml:"System"`
	}
	if len(raw) > 512*1024 || xml.Unmarshal([]byte(raw), &v) != nil {
		return protocol.WindowsEvent{}, features.ErrReport
	}
	stamp, e := time.Parse(time.RFC3339Nano, v.System.Created.At)
	if e != nil {
		return protocol.WindowsEvent{}, features.ErrReport
	}
	result := protocol.WindowsEvent{RecordID: v.System.Record, EventID: v.System.ID, Level: v.System.Level, Provider: v.System.Provider.Name, Channel: v.System.Channel, Time: stamp.Unix(), MessageStatus: "unavailable"}
	result.XML, result.XMLTruncated = clip(raw, 8192)
	if !EventValid(result) {
		return result, features.ErrReport
	}
	return result, nil
}

// Event levels are a UCHAR. 0–5 are the standard levels; providers may define
// their own levels up to 255, which are legitimate and shown as numbers.
const MaxLevel = 255

// MaxSkipped bounds the reported count of matching events left out of a result.
const MaxSkipped = 1 << 20

func EventValid(v protocol.WindowsEvent) bool {
	if v.RecordID == 0 || v.EventID > 65535 || v.Level < 0 || v.Level > MaxLevel || !text(v.Provider, 256, false) || !ValidChannel(v.Channel) || v.Time <= 0 || v.Time > 253402300799 || len(v.Message) > 4096 || len(v.XML) > 8192 || !utf8.ValidString(v.Message) || !utf8.ValidString(v.XML) {
		return false
	}
	return v.MessageStatus == "formatted" || v.MessageStatus == "unavailable" || v.MessageStatus == "truncated"
}

// eventFits checks one event against the filter and the descending record
// order after the previous accepted event (last, or 0 for none).
func eventFits(v protocol.WindowsEvent, f protocol.EventFilter, last uint64) bool {
	// The channel is not compared: the query is bound to the channel, and
	// forwarded events (ForwardedEvents) keep their original channel name.
	return EventValid(v) && v.Time >= f.From && v.Time <= f.To && (f.Level < 0 || v.Level == f.Level) && (f.EventID < 0 || v.EventID == uint32(f.EventID)) && (f.Provider == "" || v.Provider == f.Provider) && (f.Before == 0 || v.RecordID < f.Before) && (last == 0 || v.RecordID < last)
}

// Accept appends one parsed event to an in-progress result, or counts it as
// skipped when it could not be parsed or does not fit the result. One bad event
// never fails the query.
func Accept(r *protocol.EventResult, f protocol.EventFilter, v protocol.WindowsEvent, parseErr error) {
	var last uint64
	if len(r.Events) > 0 {
		last = r.Events[len(r.Events)-1].RecordID
	}
	if parseErr != nil || !eventFits(v, f, last) {
		r.Skipped = min(r.Skipped+1, MaxSkipped)
		return
	}
	r.Events = append(r.Events, v)
}
func ResultValid(r protocol.EventResult, f protocol.EventFilter) bool {
	if !protocol.ValidID(r.ID) || r.Events == nil || len(r.Events) > f.Limit || r.Skipped < 0 || r.Skipped > MaxSkipped {
		return false
	}
	if r.Outcome != "ok" {
		switch r.Outcome {
		case "denied", "unavailable", "failed", "timed_out", "unsupported", "too_large", "log_changed":
			return len(r.Events) == 0 && !r.More && r.NextBefore == 0 && r.Skipped == 0
		}
		return false
	}
	var last uint64
	for _, v := range r.Events {
		if !eventFits(v, f, last) {
			return false
		}
		last = v.RecordID
	}
	if r.More {
		return len(r.Events) > 0 && r.NextBefore == last
	}
	return r.NextBefore == 0
}
