package protocol

import (
	"slices"
	"strings"
)

// Triage collection. An evidence job of source "triage" asks the
// agent for one ZIP of the chosen artifact types, read from a Volume Shadow
// Copy of the system drive, with a manifest of every file.

// AbilityTriage is reported in the heartbeat by agents that build triage
// packages.
const AbilityTriage = "triage"

// TriageItem is an artifact type a triage profile can include.
type TriageItem struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// TriageItems are the artifact types, in the order a package lists them.
var TriageItems = []TriageItem{
	{"prefetch", "Prefetch"},
	{"amcache", "Amcache"},
	{"registry", "System registry hives (with transaction logs)"},
	{"user_registry", "User registry hives (NTUSER.DAT, UsrClass.dat)"},
	{"tasks", "Scheduled task XML"},
	{"event_logs", "Event log files (.evtx)"},
	{"srum", "SRUM database"},
	{"browsers", "Browser history (Chrome, Edge, Firefox)"},
	{"recent", "Recent files and jump lists"},
	{"startup", "Startup folders"},
	{"powershell_history", "PowerShell console history"},
	{"wmi", "WMI repository"},
}

// ValidTriageItems accepts a non-empty list of known artifact types without
// repeats.
func ValidTriageItems(items []string) bool {
	if len(items) == 0 || len(items) > len(TriageItems) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range items {
		if seen[v] || !slices.ContainsFunc(TriageItems, func(i TriageItem) bool { return i.Name == v }) {
			return false
		}
		seen[v] = true
	}
	return true
}

// TriageQuery is how a job carries its artifact types (the job's query):
// comma-separated, in catalogue order.
func TriageQuery(items []string) string {
	out := []string{}
	for _, i := range TriageItems {
		if slices.Contains(items, i.Name) {
			out = append(out, i.Name)
		}
	}
	return strings.Join(out, ",")
}

// ParseTriageQuery reads a job's artifact types.
func ParseTriageQuery(q string) ([]string, bool) {
	items := strings.Split(q, ",")
	return items, ValidTriageItems(items) && TriageQuery(items) == q
}

// TriageFormat names the package's manifest (manifest.json in the ZIP).
const TriageFormat = "openrmm-triage"

// TriageManifest describes a package: every file with its original path,
// size, times (Unix nanoseconds), SHA-256 and how it was read, and every
// file or folder left out with the reason.
type TriageManifest struct {
	Format     string       `json:"format"`
	Version    int          `json:"version"`
	Profile    string       `json:"profile"`
	Items      []string     `json:"items"`
	DeviceTime string       `json:"device_time"`
	Volume     string       `json:"volume"`
	Snapshot   string       `json:"snapshot,omitempty"`
	SnapshotAt int64        `json:"snapshot_at,omitempty"`
	Files      []TriageFile `json:"files"`
	Skipped    []TriageSkip `json:"skipped"`
	// SkippedMore counts files left out beyond the 10,000 listed.
	SkippedMore int      `json:"skipped_more,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

type TriageFile struct {
	Path     string `json:"path"`
	Item     string `json:"item"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified,omitempty"`
	Created  int64  `json:"created,omitempty"`
	SHA256   string `json:"sha256"`
	// Method is snapshot (read from the shadow copy) or live.
	Method string `json:"method"`
	// Incomplete: reading stopped with an error; the entry holds what was
	// read (Size and SHA256 describe that).
	Incomplete bool `json:"incomplete,omitempty"`
}

type TriageSkip struct {
	Path   string `json:"path"`
	Item   string `json:"item"`
	Reason string `json:"reason"`
}
