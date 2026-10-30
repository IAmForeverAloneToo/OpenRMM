package protocol

import (
	"encoding/csv"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fleet hunting: an indicator hunt (response action "hunt")
// matches a list of indicators against files in common locations, running
// processes, network connections and the DNS cache, and the persistence
// report.

// AbilityHunt is reported by agents that run indicator hunts.
const AbilityHunt = "hunt"

// Indicator types: file hashes, a file or process name (wildcards * and ?),
// a full path (wildcards), a remote IP address or network, a domain name
// (exact, or *.example.com for the domain and its subdomains) and text in a
// command line.
var IndicatorTypes = []string{"sha256", "sha1", "md5", "name", "path", "ip", "domain", "cmd"}

const (
	MaxIndicators     = 1000
	MaxIndicatorValue = 1024
	// MaxHuntMatches bounds the matches one device reports.
	MaxHuntMatches = 1000
	// MaxHuntFileBytes: larger files (over 100 MB) are not hashed.
	MaxHuntFileBytes = 100 << 20
	// MaxIndicatorBytes bounds a hunt's indicator text: every target's job
	// and custody entry keeps a copy.
	MaxIndicatorBytes = 128 << 10
)

type Indicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// HuntSpec is an indicator hunt. Files turns on the file search in common
// locations (the slow part); processes, network and persistence are always
// searched for the indicator types that apply to them.
type HuntSpec struct {
	Indicators []Indicator `json:"indicators"`
	Files      bool        `json:"files"`
}

// HuntResult is one device's hunt. Outcome is ok, or partial when the time
// limit stopped the search. Scanned counts what was searched; Skipped counts
// files not hashed (too large or unreadable) and folders not readable.
type HuntResult struct {
	Outcome string      `json:"outcome"`
	Matches []HuntMatch `json:"matches"`
	More    bool        `json:"more"`
	Scanned HuntScanned `json:"scanned"`
	Skipped int         `json:"skipped"`
}

type HuntScanned struct {
	Files       int `json:"files"`
	Hashed      int `json:"hashed"`
	Processes   int `json:"processes"`
	Connections int `json:"connections"`
	DNS         int `json:"dns"`
	Persistence int `json:"persistence"`
	// MFTFiles are the files on fixed NTFS drives whose names and paths
	// were matched through the drives' MFT.
	MFTFiles int `json:"mft_files,omitempty"`
}

// HuntMatch is one object that matched one indicator. Area is file,
// process, connection, dns or persistence; the other fields describe the
// object (only those that apply).
type HuntMatch struct {
	Area      string    `json:"area"`
	Indicator Indicator `json:"indicator"`
	Path      string    `json:"path,omitempty"`
	Name      string    `json:"name,omitempty"`
	Size      int64     `json:"size,omitempty"`
	Modified  string    `json:"modified,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	PID       uint32    `json:"pid,omitempty"`
	User      string    `json:"user,omitempty"`
	Command   string    `json:"command,omitempty"`
	Address   string    `json:"address,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

var (
	hexPattern = regexp.MustCompile(`^[0-9a-f]+$`)
	// pathStart: a drive (C:\), an environment variable (%APPDATA%\) or a
	// wildcard. (A path from the root without a drive, \Windows\x.exe, could
	// never match: paths are compared in full.)
	pathStart     = regexp.MustCompile(`^([A-Za-z]:[\\/]|%[^%\\/]+%[\\/]|\*)`)
	envVariable   = regexp.MustCompile(`%[^%\\/]+%`)
	domainPattern = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
)

func indicatorText(s string) bool {
	if s == "" || len(s) > MaxIndicatorValue || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Valid checks one indicator in its canonical form (hashes and domains in
// lower case; IP addresses and networks as netip prints them).
func (i Indicator) Valid() bool {
	if !indicatorText(i.Value) {
		return false
	}
	switch i.Type {
	case "sha256":
		return len(i.Value) == 64 && hexPattern.MatchString(i.Value)
	case "sha1":
		return len(i.Value) == 40 && hexPattern.MatchString(i.Value)
	case "md5":
		return len(i.Value) == 32 && hexPattern.MatchString(i.Value)
	case "name":
		return len(i.Value) <= 260 && !strings.ContainsAny(i.Value, `\/:`) && strings.Trim(i.Value, "*?") != ""
	case "path":
		// The file name part must be more than wildcards: C:\* would match
		// every file.
		// (%VAR% matches any text, like *.)
		last := envVariable.ReplaceAllString(i.Value[strings.LastIndexAny(i.Value, `\/`)+1:], "*")
		return pathStart.MatchString(i.Value) && strings.ContainsAny(i.Value, `\/`) && strings.Trim(last, "*?") != ""
	case "ip":
		if p, e := netip.ParsePrefix(i.Value); e == nil {
			return p.Masked() == p && p.String() == i.Value && p.Bits() > 0
		}
		a, e := netip.ParseAddr(i.Value)
		return e == nil && a.Zone() == "" && !a.Is4In6() && a.String() == i.Value
	case "domain":
		// *.example.com needs a dot after the wildcard: never *.com.
		if len(i.Value) > 253 || strings.ToLower(i.Value) != i.Value || !domainPattern.MatchString(i.Value) {
			return false
		}
		return !strings.HasPrefix(i.Value, "*.") || strings.Contains(i.Value[2:], ".")
	case "cmd":
		return len(i.Value) >= 3
	}
	return false
}

// Valid checks a hunt spec: 1 to MaxIndicators distinct indicators.
func (h HuntSpec) Valid() bool {
	if len(h.Indicators) == 0 || len(h.Indicators) > MaxIndicators {
		return false
	}
	seen := make(map[Indicator]bool, len(h.Indicators))
	total := 0
	for _, i := range h.Indicators {
		total += len(i.Value)
		if !i.Valid() || seen[i] || total > MaxIndicatorBytes {
			return false
		}
		seen[i] = true
	}
	return true
}

// Needs reports whether the spec has an indicator of one of the types.
func (h HuntSpec) Needs(types ...string) bool {
	for _, i := range h.Indicators {
		for _, t := range types {
			if i.Type == t {
				return true
			}
		}
	}
	return false
}

// canonical turns a typed value into the canonical form, or "" when it is
// not valid for the type.
func canonical(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "sha256", "sha1", "md5":
		value = strings.ToLower(value)
	case "domain":
		value = strings.TrimSuffix(strings.ToLower(value), ".")
	case "ip":
		if p, e := netip.ParsePrefix(value); e == nil {
			value = p.Masked().String()
		} else if a, e := netip.ParseAddr(value); e == nil {
			value = a.Unmap().String()
		}
	}
	if i := (Indicator{kind, value}); i.Valid() {
		return value
	}
	return ""
}

// guess types an untyped value: hashes by length, IP addresses and
// networks, paths (with a backslash or slash); anything else is a name.
// Domains need the "domain:" prefix, since evil.com may be a file name.
func guess(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case hexPattern.MatchString(v) && len(v) == 64:
		return "sha256"
	case hexPattern.MatchString(v) && len(v) == 40:
		return "sha1"
	case hexPattern.MatchString(v) && len(v) == 32:
		return "md5"
	}
	if _, e := netip.ParseAddr(v); e == nil {
		return "ip"
	}
	if _, e := netip.ParsePrefix(v); e == nil {
		return "ip"
	}
	if strings.ContainsAny(v, `\/`) && pathStart.MatchString(v) {
		return "path"
	}
	return "name"
}

// ParseIndicators reads a pasted list: one indicator per line, optionally
// "type:value" (for example domain:example.com or cmd:-enc), or CSV lines
// "type,value". Blank lines and lines starting with # are ignored. Untyped
// values are typed by guess. Repeats are dropped. Problems name the lines
// that were not understood (at most 50).
func ParseIndicators(text string) ([]Indicator, []string) {
	out, problems := []Indicator{}, []string{}
	seen := map[Indicator]bool{}
	problem := func(n int, line string) {
		if len(problems) < 50 {
			if len(line) > 80 {
				line = line[:80] + "…"
			}
			problems = append(problems, "line "+strconv.Itoa(n)+": "+strings.ToValidUTF8(line, "?"))
		}
	}
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value := "", line
		if k, v, ok := strings.Cut(line, ","); ok && isType(strings.ToLower(strings.TrimSpace(k))) {
			if r, e := csv.NewReader(strings.NewReader(line)).Read(); e == nil && len(r) >= 2 {
				kind, value = strings.ToLower(strings.TrimSpace(r[0])), r[1]
			} else {
				kind, value = strings.ToLower(strings.TrimSpace(k)), v
			}
		} else if k, v, ok := strings.Cut(line, ":"); ok && isType(strings.ToLower(k)) {
			kind, value = strings.ToLower(k), v
		}
		if kind == "" {
			kind = guess(value)
		}
		c := canonical(kind, value)
		if c == "" {
			problem(n+1, line)
			continue
		}
		i := Indicator{kind, c}
		if seen[i] {
			continue
		}
		if len(out) == MaxIndicators {
			problem(n+1, "more than 1,000 indicators; the rest were left out")
			break
		}
		seen[i] = true
		out = append(out, i)
	}
	return out, problems
}

func isType(s string) bool {
	for _, t := range IndicatorTypes {
		if s == t {
			return true
		}
	}
	return false
}
