// Package scripting owns the versioned script contract and execution boundary.
package scripting

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var Capability = protocol.Capability{Name: "scripts", Version: 1}
var ErrInvalid = errors.New("invalid script operation")

const MaxBytes = 1024 * 1024
const MaxBody = 64 * 1024
const MaxOutput = 64 * 1024
const MaxParameters = 8

var parameterName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

func Text(s string, max int, multiline bool) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\r' || r == '\n' || r == '\t')) {
			return false
		}
	}
	return true
}
func Decode(b []byte, v any) error {
	if len(b) > MaxBytes || !utf8.Valid(b) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return ErrInvalid
	}
	return nil
}
func DefinitionValid(d protocol.ScriptDefinition) bool {
	if strings.TrimSpace(d.Name) != d.Name || d.Name == "" || !Text(d.Name, 100, false) || !Text(d.Description, 2000, true) || strings.TrimSpace(d.Body) == "" || !Text(d.Body, MaxBody, true) || d.Parameters == nil || len(d.Parameters) > MaxParameters || d.Timeout < 5 || d.Timeout > 300 || d.RunAs != "restricted" && d.RunAs != "system" {
		return false
	}
	seen := map[string]bool{}
	for _, p := range d.Parameters {
		k := strings.ToLower(p.Name)
		if !parameterName.MatchString(p.Name) || seen[k] || !Text(p.Description, 256, false) {
			return false
		}
		seen[k] = true
		switch k {
		case "debug", "verbose", "erroraction", "errorvariable", "warningaction", "warningvariable", "informationaction", "informationvariable", "outvariable", "outbuffer", "pipelinevariable", "whatif", "confirm", "progressaction":
			return false
		}
	}
	return true
}
func Digest(v protocol.ScriptVersion) string {
	b, _ := json.Marshal(struct {
		ID, ScriptID string
		Number       int
		Definition   protocol.ScriptDefinition
	}{v.ID, v.ScriptID, v.Number, v.Definition})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Hash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func VersionValid(v protocol.ScriptVersion) bool {
	return protocol.ValidID(v.ID) && protocol.ValidID(v.ScriptID) && v.Number >= 1 && v.Number <= 500 && DefinitionValid(v.Definition) && v.Hash == Digest(v)
}
func ArgumentsValid(d protocol.ScriptDefinition, args map[string]string) bool {
	if args == nil || len(args) > MaxParameters {
		return false
	}
	allowed := map[string]bool{}
	for _, p := range d.Parameters {
		allowed[p.Name] = true
		v, ok := args[p.Name]
		if p.Required && (!ok || v == "") {
			return false
		}
	}
	for k, v := range args {
		if !allowed[k] || !Text(v, 1024, true) {
			return false
		}
	}
	return true
}
func JobValid(q protocol.ScriptJob) bool {
	return protocol.ValidID(q.ID) && q.ExpiresAt > 0 && VersionValid(q.Version) && ArgumentsValid(q.Version.Definition, q.Arguments)
}
func ArgumentsHash(args map[string]string) string {
	b, _ := json.Marshal(args)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func ResultValid(r protocol.ScriptResult) bool {
	if !protocol.ValidID(r.ID) || !Text(r.Stdout, MaxOutput, true) || !Text(r.Stderr, MaxOutput, true) {
		return false
	}
	switch r.Outcome {
	case "running":
		return r.ExitCode == nil && r.Stdout == "" && r.Stderr == "" && !r.Truncated
	case "succeeded":
		return r.ExitCode != nil && *r.ExitCode == 0
	case "failed":
		return r.ExitCode != nil && *r.ExitCode != 0
	case "denied", "unsupported", "unknown", "cancelled", "timed_out", "start_failed":
		return r.ExitCode == nil
	}
	return false
}
func Failure(id, outcome string) protocol.ScriptResult {
	return protocol.ScriptResult{ID: id, Outcome: outcome}
}

// RunnerRevision identifies script execution behaviour for the fleet view.
// Scripts run inside the SYSTEM agent, so the agent reports the
// current revision itself and no separately installed runner can lag behind.
const RunnerRevision = 2

// Module reports script support. Every script runs as SYSTEM inside the agent;
// the protocol's "administrator" field stays
// "enabled" so servers keep accepting both stored run-as values.
type Module struct{}

func (Module) Capability() protocol.Capability { return Capability }
func (Module) Collect(context.Context) (json.RawMessage, error) {
	if !Supported() {
		return nil, features.ErrUnsupported
	}
	return json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "enabled", RunnerRevision: RunnerRevision})
}
func SupportValid(s protocol.ScriptSupport) bool {
	switch s.Administrator {
	case "missing", "disabled", "enabled", "denied", "unsupported":
		return true
	}
	return false
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
	if r.Capability.Version != 1 {
		r.Status = "unsupported"
		r.Data = nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) != 0 {
			return r, features.ErrReport
		}
		return r, nil
	}
	var s struct {
		Restricted     *bool   `json:"restricted"`
		Administrator  *string `json:"administrator"`
		RunnerRevision int     `json:"runner_revision"`
	}
	if Decode(r.Data, &s) != nil || s.Restricted == nil || s.Administrator == nil || s.RunnerRevision < 0 || s.RunnerRevision > 1000 {
		return r, features.ErrReport
	}
	v := protocol.ScriptSupport{Restricted: *s.Restricted, Administrator: *s.Administrator, RunnerRevision: s.RunnerRevision}
	if !SupportValid(v) {
		return r, features.ErrReport
	}
	r.Data, _ = json.Marshal(v)
	return r, nil
}

// ResponseJob builds the script job for a case response script
// from its action spec, so agent and server check the same definition. It
// always runs as SYSTEM.
func ResponseJob(id string, a protocol.ResponseAction, expires int64) (protocol.ScriptJob, bool) {
	if a.Kind != "script" || !a.Valid() {
		return protocol.ScriptJob{}, false
	}
	params, args := a.Parameters, a.Arguments
	if params == nil {
		params = []protocol.ScriptParameter{}
	}
	if args == nil {
		args = map[string]string{}
	}
	script := id
	if a.Ref != "" {
		script = a.Ref
	}
	v := protocol.ScriptVersion{ID: id, ScriptID: script, Number: 1, Definition: protocol.ScriptDefinition{Name: a.Name, Description: "Case response script", Body: a.Script, Parameters: params, Timeout: a.Timeout, RunAs: "system"}}
	v.Hash = Digest(v)
	q := protocol.ScriptJob{ID: id, Version: v, Arguments: args, ExpiresAt: expires}
	return q, JobValid(q)
}

// BodyHash is the SHA-256 of a script body (what a case records as run).
func BodyHash(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:])
}
