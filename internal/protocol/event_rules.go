package protocol

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Event log filter rules, shared by the event log viewer, the .evtx export
// and fleet log search.

// MaxEventPage is the most events one query or search returns per device.
const MaxEventPage = 250

func eventText(s string, max int, empty bool) bool {
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

// ValidEventChannel accepts an event log channel name (never a file path:
// queries open channels only).
func ValidEventChannel(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" -_./%()", r)) {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

// ValidEventXPath accepts one raw event XPath predicate, *[...], that is
// combined with the structured filter by "and": the outer brackets must
// enclose the whole expression, so a top-level "or" cannot widen the time
// bounds.
func ValidEventXPath(s string) bool {
	if len(s) < 3 || len(s) > 4096 || !eventText(s, 4096, false) || !strings.HasPrefix(s, "*[") || !strings.HasSuffix(s, "]") {
		return false
	}
	depth, quote := 0, rune(0)
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '[':
			depth++
		case r == ']':
			depth--
			if depth < 0 || depth == 0 && i != len(s)-1 {
				return false
			}
		}
	}
	return depth == 0 && quote == 0
}

// EventFilterValid checks a structured event filter: a channel, a time range
// of at most 31 days, level, event ID, provider, page size and optional raw
// XPath.
func EventFilterValid(f EventFilter) bool {
	return ValidEventChannel(f.Channel) && f.From > 0 && f.To >= f.From && f.To <= 253402300799 && f.To-f.From <= 31*86400 && f.Level >= -1 && f.Level <= 5 && f.EventID >= -1 && f.EventID <= 65535 && f.Limit >= 1 && f.Limit <= MaxEventPage && eventText(f.Provider, 256, true) && !strings.ContainsAny(f.Provider, "'\"") && (f.XPath == "" || ValidEventXPath(f.XPath))
}
