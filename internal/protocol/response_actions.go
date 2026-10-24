package protocol

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Structured response actions. An action runs on the device from
// a case; its result is a JSON document (ActionResult) collected as case
// evidence through the evidence upload, so it is hashed, verified, stored and
// recorded like a collected file.

// ResponseAction is the action spec. Kind is processes, connections,
// services, tasks, registry (Key), kill (PID, Start, Name, Tree), script
// (Name, Script body, Parameters, Arguments, Timeout; Ref names the
// library script, empty for one typed in the case) or drop (a
// file from the tool library or the case's evidence, Source and Ref, with
// its Name, SHA256 and Size, written to Path, replacing a file only with
// Overwrite). The server fills in script bodies and file hashes, so the spec
// says exactly what runs or is written.
type ResponseAction struct {
	Kind       string            `json:"kind"`
	Key        string            `json:"key,omitempty"`
	PID        uint32            `json:"pid,omitempty"`
	Start      string            `json:"start,omitempty"`
	Name       string            `json:"name,omitempty"`
	Tree       bool              `json:"tree,omitempty"`
	Script     string            `json:"script,omitempty"`
	Parameters []ScriptParameter `json:"parameters,omitempty"`
	Arguments  map[string]string `json:"arguments,omitempty"`
	Timeout    int               `json:"timeout,omitempty"`
	Ref        string            `json:"ref,omitempty"`
	Source     string            `json:"source,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Size       int64             `json:"size,omitempty"`
	Path       string            `json:"path,omitempty"`
	Overwrite  bool              `json:"overwrite,omitempty"`
	// Events is the filter of an event log search (kind "events"): the
	// newest matching events, at most Limit.
	Events *EventFilter `json:"events,omitempty"`
	// Hunt is an indicator hunt (kind "hunt").
	Hunt *HuntSpec `json:"hunt,omitempty"`
	// Isolate is a network isolation (kind "isolate"); kind
	// "release" lifts it.
	Isolate *IsolationSpec `json:"isolate,omitempty"`
}

// MaxDrop is the largest file a case can drop (4 GiB).
const MaxDrop = 4 << 30

// ActionFormat names the result document.
const ActionFormat = "openrmm-response-action"

// Mutating reports whether the action changes the device; such an action is
// never run twice.
func (a ResponseAction) Mutating() bool {
	return a.Kind == "kill" || a.Kind == "script" || a.Kind == "drop" || a.Kind == "isolate" || a.Kind == "release"
}

// ValidDropPath accepts an absolute local Windows file path (no stream).
func ValidDropPath(p string) bool {
	if len(p) < 4 || len(p) > 1024 || !utf8.ValidString(p) || strings.TrimSpace(p) != p || !(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') || p[1] != ':' || p[2] != '\\' {
		return false
	}
	rest := p[2:]
	if strings.Contains(rest, `\\`) || strings.HasSuffix(rest, `\`) || strings.Contains(rest, ":") {
		return false
	}
	for _, r := range rest {
		if unicode.IsControl(r) || strings.ContainsRune(`/<>"|?*`, r) {
			return false
		}
	}
	return true
}

// plain reports a spec that uses none of the script and drop fields.
func (a ResponseAction) plain() bool {
	return a.Script == "" && a.Parameters == nil && a.Arguments == nil && a.Timeout == 0 && a.Ref == "" && a.Source == "" && a.SHA256 == "" && a.Size == 0 && a.Path == "" && !a.Overwrite && a.Events == nil && a.Hunt == nil && a.Isolate == nil
}

func actionText(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidRegistryKey accepts HKLM, HKU or HKCR, optionally followed by a path
// of non-empty key names separated by single backslashes.
// Key names may have leading or trailing spaces (a known way to hide a key).
func ValidRegistryKey(k string) bool {
	if k == "" || len(k) > 512 || !utf8.ValidString(k) {
		return false
	}
	for _, r := range k {
		if unicode.IsControl(r) {
			return false
		}
	}
	root, rest, _ := strings.Cut(k, `\`)
	if root != "HKLM" && root != "HKU" && root != "HKCR" {
		return false
	}
	if !strings.Contains(k, `\`) {
		return true
	}
	for _, part := range strings.Split(rest, `\`) {
		if part == "" || len(part) > 255 {
			return false
		}
	}
	return true
}

// Valid checks an action spec.
func (a ResponseAction) Valid() bool {
	switch a.Kind {
	case "processes", "connections", "services", "tasks", "persistence":
		return a.Key == "" && a.PID == 0 && a.Start == "" && a.Name == "" && !a.Tree && a.plain()
	case "registry":
		return ValidRegistryKey(a.Key) && a.PID == 0 && a.Start == "" && a.Name == "" && !a.Tree && a.plain()
	case "kill":
		v, e := strconv.ParseUint(a.Start, 10, 64)
		return a.Key == "" && a.PID > 4 && e == nil && v > 0 && strconv.FormatUint(v, 10) == a.Start && actionText(a.Name, 260) && !strings.ContainsAny(a.Name, `\/`) && a.plain()
	case "script":
		// The full definition check (scripting.ResponseJob) runs on both ends.
		return a.Key == "" && a.PID == 0 && a.Start == "" && !a.Tree && actionText(a.Name, 100) && strings.TrimSpace(a.Script) != "" && len(a.Script) <= 64<<10 && utf8.ValidString(a.Script) &&
			a.Timeout >= 5 && a.Timeout <= 300 && len(a.Parameters) <= 8 && len(a.Arguments) <= 8 && (a.Ref == "" || ValidID(a.Ref)) &&
			a.Source == "" && a.SHA256 == "" && a.Size == 0 && a.Path == "" && !a.Overwrite && a.Events == nil && a.Hunt == nil && a.Isolate == nil
	case "drop":
		return a.Key == "" && a.PID == 0 && a.Start == "" && !a.Tree && a.Script == "" && a.Parameters == nil && a.Arguments == nil && a.Timeout == 0 && a.Events == nil && a.Hunt == nil && a.Isolate == nil &&
			(a.Source == "tool" || a.Source == "evidence") && ValidID(a.Ref) && actionText(a.Name, 255) && !strings.ContainsAny(a.Name, `\/:`) && sha256Text(a.SHA256) && a.Size >= 0 && a.Size <= MaxDrop && ValidDropPath(a.Path)
	case "events":
		// The newest events from the start of the range: no page cursor.
		f := a.Events
		a.Events = nil
		return f != nil && f.Before == 0 && EventFilterValid(*f) && a.Key == "" && a.PID == 0 && a.Start == "" && a.Name == "" && !a.Tree && a.plain()
	case "hunt":
		h := a.Hunt
		a.Hunt = nil
		return h != nil && h.Valid() && a.Key == "" && a.PID == 0 && a.Start == "" && a.Name == "" && !a.Tree && a.plain()
	case "isolate":
		i := a.Isolate
		a.Isolate = nil
		return i != nil && i.Valid() && a.Key == "" && a.PID == 0 && a.Start == "" && a.Name == "" && !a.Tree && a.plain()
	case "release":
		return a.Key == "" && a.PID == 0 && a.Start == "" && a.Name == "" && !a.Tree && a.plain()
	}
	return false
}

// Text is the action's canonical JSON, stored with the job.
func (a ResponseAction) Text() string {
	b, _ := json.Marshal(a)
	return string(b)
}

// ParseAction reads a canonical action text.
func ParseAction(s string) (ResponseAction, bool) {
	var a ResponseAction
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.More() || !a.Valid() || a.Text() != s {
		return ResponseAction{}, false
	}
	return a, true
}

// Label describes the action for people.
func (a ResponseAction) Label() string {
	switch a.Kind {
	case "processes":
		return "Process list"
	case "connections":
		return "Network connections"
	case "services":
		return "Services"
	case "tasks":
		return "Scheduled tasks"
	case "persistence":
		return "Persistence report"
	case "registry":
		return "Registry " + a.Key
	case "kill":
		what := "Kill process "
		if a.Tree {
			what = "Kill process tree "
		}
		return what + a.Name + " (" + strconv.FormatUint(uint64(a.PID), 10) + ")"
	case "script":
		return "Script " + a.Name
	case "drop":
		return "Drop " + a.Name + " to " + a.Path
	case "events":
		if a.Events != nil {
			return "Log search " + a.Events.Channel
		}
	case "isolate":
		return "Isolate from the network"
	case "release":
		return "Release network isolation"
	case "hunt":
		if a.Hunt != nil {
			n := len(a.Hunt.Indicators)
			label := "Indicator hunt (" + strconv.Itoa(n) + " indicator"
			if n != 1 {
				label += "s"
			}
			return label + ")"
		}
	}
	return "Action"
}

// ActionResult is the document an action produces. Times are UTC RFC 3339
// strings; Notes carry bounded, non-fatal problems (such as a process whose
// details could not be read).
type ActionResult struct {
	Format      string            `json:"format"`
	Version     int               `json:"version"`
	Action      ResponseAction    `json:"action"`
	DeviceTime  string            `json:"device_time"`
	Processes   []ProcessDetail   `json:"processes,omitempty"`
	Connections []Connection      `json:"connections,omitempty"`
	Services    []ServiceDetail   `json:"services,omitempty"`
	Tasks       []TaskDetail      `json:"tasks,omitempty"`
	Registry    *RegistryKeyState `json:"registry,omitempty"`
	Killed      []KillResult      `json:"killed,omitempty"`
	Script      *ScriptRun        `json:"script,omitempty"`
	Drop        *DropResult       `json:"drop,omitempty"`
	// EventLog is an event log search's result.
	EventLog *EventResult `json:"event_log,omitempty"`
	// Persistence is the persistence report.
	Persistence []PersistenceEntry `json:"persistence,omitempty"`
	// Hunt is an indicator hunt's result.
	Hunt *HuntResult `json:"hunt,omitempty"`
	// Isolation is the state after an isolate or release action.
	Isolation *IsolationState `json:"isolation,omitempty"`
	Notes     []string        `json:"notes,omitempty"`
}

// ScriptRun is a response script's run: SHA256 is the hash of the
// script body that ran; Outcome and output are the script runner's.
type ScriptRun struct {
	Name      string            `json:"name"`
	SHA256    string            `json:"sha256"`
	Arguments map[string]string `json:"arguments,omitempty"`
	Outcome   string            `json:"outcome"`
	ExitCode  *int32            `json:"exit_code"`
	Stdout    string            `json:"stdout"`
	Stderr    string            `json:"stderr"`
	Truncated bool              `json:"truncated"`
	Started   string            `json:"started"`
	Finished  string            `json:"finished"`
}

// DropResult is a dropped file. Outcome is written, exists (a
// file is there and overwrite was not allowed), denied, not_found (the folder
// does not exist), hash_mismatch (the received file was not the expected
// one) or failed. Verified means the file was read back after it was written
// and had the expected hash.
type DropResult struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	Outcome        string `json:"outcome"`
	Verified       bool   `json:"verified"`
	Replaced       bool   `json:"replaced,omitempty"`
	ReplacedSHA256 string `json:"replaced_sha256,omitempty"`
}

// ProcessDetail: Start is the creation time as a Windows file time (as in
// the RMM process list, used to refuse a reused PID); SHA256 is empty with
// HashNote too_large or unreadable.
type ProcessDetail struct {
	PID         uint32 `json:"pid"`
	ParentPID   uint32 `json:"parent_pid"`
	Name        string `json:"name"`
	Start       string `json:"start,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	Image       string `json:"image,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	User        string `json:"user,omitempty"`
	UserSID     string `json:"user_sid,omitempty"`
	Session     uint32 `json:"session"`
	SHA256      string `json:"sha256,omitempty"`
	HashNote    string `json:"hash_note,omitempty"`
	CanKill     bool   `json:"can_kill"`
}

type Connection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint16 `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
	PID           uint32 `json:"pid"`
	Process       string `json:"process,omitempty"`
}

type ServiceDetail struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	StartType   string `json:"start_type"`
	Type        string `json:"type"`
	PID         uint32 `json:"pid,omitempty"`
	Account     string `json:"account,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	Image       string `json:"image,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	ServiceDLL  string `json:"service_dll,omitempty"`
	DLLSHA256   string `json:"service_dll_sha256,omitempty"`
}

type TaskDetail struct {
	Path        string       `json:"path"`
	Enabled     bool         `json:"enabled"`
	Hidden      bool         `json:"hidden,omitempty"`
	Author      string       `json:"author,omitempty"`
	Description string       `json:"description,omitempty"`
	UserID      string       `json:"user_id,omitempty"`
	RunLevel    string       `json:"run_level,omitempty"`
	Triggers    []string     `json:"triggers,omitempty"`
	Actions     []TaskAction `json:"actions,omitempty"`
	Modified    string       `json:"file_modified,omitempty"`
	SHA256      string       `json:"file_sha256"`
}

type TaskAction struct {
	Command    string `json:"command,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	WorkingDir string `json:"working_directory,omitempty"`
	ClassID    string `json:"com_class_id,omitempty"`
}

type RegistryKeyState struct {
	Key             string           `json:"key"`
	LastWrite       string           `json:"last_write,omitempty"`
	Subkeys         []RegistrySubkey `json:"subkeys"`
	SubkeysMore     bool             `json:"subkeys_more,omitempty"`
	Values          []RegistryValue  `json:"values"`
	ValuesMore      bool             `json:"values_more,omitempty"`
	BackupPrivilege bool             `json:"backup_privilege,omitempty"`
}

type RegistrySubkey struct {
	Name      string `json:"name"`
	LastWrite string `json:"last_write,omitempty"`
}

// RegistryValue: Data is text for string and number types, Strings for
// REG_MULTI_SZ, Hex (capped, Truncated) for anything else.
type RegistryValue struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Data      string   `json:"data,omitempty"`
	Strings   []string `json:"strings,omitempty"`
	Hex       string   `json:"hex,omitempty"`
	Size      int      `json:"size"`
	Truncated bool     `json:"truncated,omitempty"`
}

// KillResult: Outcome is succeeded, exited (it ended on its own before it
// was ended, such as a shell whose children were ended first), denied
// (protected or not allowed), not_found, identity_changed (the PID now
// belongs to another process) or failed.
type KillResult struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"parent_pid"`
	Name      string `json:"name"`
	Start     string `json:"start"`
	Image     string `json:"image,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Outcome   string `json:"outcome"`
}
