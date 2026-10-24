// Package filetransfer defines bounded file operations independently of transport.
package filetransfer

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
	"io/fs"
	"path"
	"strings"
	"unicode/utf8"
)

const MaxFile = 8 * 1024 * 1024
const MaxWire = 12 * 1024 * 1024
const MaxEntries = 500

var Capability = protocol.Capability{Name: "files", Version: 1}
var ErrPolicy = errors.New("file access disabled or unavailable")

func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrPolicy
	}
	return nil
}
func Text(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func RootID(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func Name(s string) bool { return name(s, true) }

// name checks one path element; protect also refuses the protected names
// (.env, .ssh, .aws, .git), which case evidence may collect. OpenRMM's own
// .openrmm-* names are always refused.
func name(s string, protect bool) bool {
	if s == "" || !Text(s, 200) || strings.TrimSpace(s) != s || strings.HasSuffix(s, ".") || strings.ContainsAny(s, `/\:<>"|?*`) {
		return false
	}
	low := strings.ToLower(s)
	if low == "." || low == ".." || strings.HasPrefix(low, ".openrmm-") || protect && (low == ".env" || strings.HasPrefix(low, ".env.")) {
		return false
	}
	reserved := []string{"con", "prn", "aux", "nul", "conin$", "conout$"}
	if protect {
		reserved = append(reserved, ".ssh", ".aws", ".git")
	}
	for _, v := range reserved {
		if strings.SplitN(low, ".", 2)[0] == v || low == v {
			return false
		}
	}
	stem := strings.SplitN(low, ".", 2)[0]
	if len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) {
		return false
	}
	return true
}
func Path(s string) bool { return validPath(s, true) }

// EvidencePath is Path for case evidence: protected names are allowed.
func EvidencePath(s string) bool { return validPath(s, false) }

func validPath(s string, protect bool) bool {
	if s == "." {
		return true
	}
	if len(s) > 1000 || !fs.ValidPath(s) || path.Clean(s) != s {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if !name(p, protect) {
			return false
		}
	}
	return true
}
func Digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func Hash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func SupportValid(s protocol.FileSupport) bool {
	if s.Roots == nil || len(s.Roots) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range s.Roots {
		if !RootID(r.ID) || seen[r.ID] || !Text(r.Name, 100) || strings.TrimSpace(r.Name) == "" || !r.Read && !r.Write {
			return false
		}
		seen[r.ID] = true
	}
	return true
}
func JobValid(q protocol.FileJob) bool {
	if !protocol.ValidID(q.ID) || !RootID(q.Root) || !Path(q.Path) || q.ExpiresAt <= 0 {
		return false
	}
	switch q.Operation {
	case "list":
		return q.Size == 0 && q.Hash == "" && len(q.Data) == 0
	case "download":
		return q.Path != "." && q.Size == 0 && q.Hash == "" && len(q.Data) == 0
	case "upload":
		return q.Path != "." && q.Size >= 0 && q.Size <= MaxFile && q.Size == int64(len(q.Data)) && Hash(q.Hash) && Digest(q.Data) == q.Hash
	}
	return false
}
func ResultValid(q protocol.FileJob, r protocol.FileResult) bool {
	if r.ID != q.ID || len(r.Entries) > MaxEntries || len(r.Data) > MaxFile {
		return false
	}
	if r.Outcome != "succeeded" {
		switch r.Outcome {
		case "denied", "not_found", "exists", "too_large", "changed", "failed", "unknown", "expired":
			return len(r.Entries) == 0 && !r.More && len(r.Data) == 0 && r.Size == 0 && r.Hash == ""
		}
		return false
	}
	switch q.Operation {
	case "list":
		if len(r.Data) != 0 || r.Hash != "" || r.Size != 0 {
			return false
		}
		seen := map[string]bool{}
		for _, e := range r.Entries {
			if !Name(e.Name) || seen[strings.ToLower(e.Name)] || e.Size < 0 || e.Modified < 0 {
				return false
			}
			seen[strings.ToLower(e.Name)] = true
		}
		return true
	case "upload":
		return len(r.Entries) == 0 && !r.More && len(r.Data) == 0 && r.Size == q.Size && r.Hash == q.Hash
	case "download":
		return len(r.Entries) == 0 && !r.More && r.Size == int64(len(r.Data)) && Hash(r.Hash) && Digest(r.Data) == r.Hash
	}
	return false
}

type Adapter interface {
	Support(context.Context) (protocol.FileSupport, error)
	Execute(context.Context, protocol.FileJob) protocol.FileResult
}
type Module struct{ Adapter Adapter }

func (Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(c context.Context) (json.RawMessage, error) {
	s, e := m.Adapter.Support(c)
	if e != nil {
		return nil, e
	}
	return json.Marshal(s)
}
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	if r.Capability != Capability {
		return r, features.ErrReport
	}
	switch r.Status {
	case "disabled", "failed", "unsupported":
		if len(r.Data) != 0 {
			return r, features.ErrReport
		}
	case "ok":
		var s protocol.FileSupport
		if Decode(r.Data, &s) != nil || !SupportValid(s) {
			return r, features.ErrReport
		}
	default:
		return r, features.ErrReport
	}
	return r, nil
}
