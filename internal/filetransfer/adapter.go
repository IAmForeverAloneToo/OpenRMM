package filetransfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type LocalRoot struct {
	protocol.FileRoot
	Path string `json:"path"`
}

// localAdapter serves every local fixed drive (the SYSTEM agent browses all
// fixed drives). The agent's own
// program, state and updater folders stay unreachable: deny is checked against
// the resolved native path of every opened directory or file, so short names,
// alternate spellings or a renamed parent cannot reach them.
type localAdapter struct {
	roots func() []LocalRoot
	deny  []string
}

func NewAdapter(deny ...string) Adapter {
	return &localAdapter{roots: fixedDrives, deny: deny}
}
func (a *localAdapter) load() ([]LocalRoot, error) {
	out := []LocalRoot{}
	s := protocol.FileSupport{Roots: []protocol.FileRoot{}}
	for _, r := range a.roots() {
		if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || filepath.VolumeName(r.Path) == "" || strings.HasPrefix(r.Path, `\\`) || !safeRoot(r.Path) {
			return nil, ErrPolicy
		}
		physical, e := canonical(r.Path)
		if e != nil || !safeNames(physical) {
			return nil, ErrPolicy
		}
		r.Path = physical
		// Opaque folder identities bind the full local definition. Absolute
		// paths stay local; the server only sees the ID and display name.
		raw, _ := json.Marshal(r)
		r.ID = Digest(append([]byte("openrmm:file-root:v1:"), raw...))[:32]
		out = append(out, r)
		s.Roots = append(s.Roots, r.FileRoot)
	}
	if !SupportValid(s) {
		return nil, ErrPolicy
	}
	return out, nil
}

// blocked reports whether a resolved native path is inside one of the agent's
// own folders. A folder that cannot be resolved for another reason than not
// existing blocks everything (fail closed).
func (a *localAdapter) blocked(physical string) bool {
	l := strings.ToLower(physical)
	for _, d := range a.deny {
		if d == "" {
			continue
		}
		c, e := canonical(d)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return true
		}
		v := strings.ToLower(strings.TrimRight(c, `\`))
		if l == v || strings.HasPrefix(l, v+`\`) {
			return true
		}
	}
	return false
}
func (a *localAdapter) Support(context.Context) (protocol.FileSupport, error) {
	if runtime.GOOS != "windows" {
		return protocol.FileSupport{}, features.ErrUnsupported
	}
	roots, e := a.load()
	s := protocol.FileSupport{Roots: []protocol.FileRoot{}}
	for _, r := range roots {
		s.Roots = append(s.Roots, r.FileRoot)
	}
	return s, e
}
func (a *localAdapter) Execute(ctx context.Context, q protocol.FileJob) protocol.FileResult {
	r := protocol.FileResult{ID: q.ID, Outcome: "denied"}
	if runtime.GOOS != "windows" {
		return r
	}
	if !JobValid(q) {
		return r
	}
	if time.Now().Unix() >= q.ExpiresAt {
		r.Outcome = "expired"
		return r
	}
	roots, e := a.load()
	if e != nil {
		return r
	}
	var selected *LocalRoot
	for _, v := range roots {
		if v.ID == q.Root {
			v := v
			selected = &v
		}
	}
	if selected == nil || q.Operation == "upload" && !selected.Write || q.Operation != "upload" && !selected.Read {
		return r
	}
	root, e := os.OpenRoot(selected.Path)
	if e != nil {
		return r
	}
	defer root.Close()
	anchor, e := root.Open(".")
	if e != nil {
		return r
	}
	actual, e := canonicalFile(anchor)
	anchor.Close()
	if e != nil || !strings.EqualFold(actual, selected.Path) {
		return r
	}
	// Lstat rejects links in the initial walk. Root methods also enforce the
	// directory boundary if a local process changes a component after this walk.
	check := q.Path
	if q.Operation == "upload" {
		check = path.Dir(check)
	}
	part := "."
	for _, v := range strings.Split(check, "/") {
		part = path.Join(part, v)
		i, e := root.Lstat(part)
		if e != nil {
			r.Outcome = outcome(e)
			return r
		}
		if i.Mode()&os.ModeSymlink != 0 || i.Mode()&os.ModeIrregular != 0 {
			return r
		}
	}
	if ctx.Err() != nil {
		return r
	}
	switch q.Operation {
	case "list":
		f, e := root.Open(q.Path)
		if e != nil {
			r.Outcome = outcome(e)
			return r
		}
		defer f.Close()
		if physical, e := canonicalFile(f); e != nil || a.blocked(physical) {
			return r
		}
		entries, e := f.ReadDir(MaxEntries + 1)
		if e != nil && e != io.EOF {
			r.Outcome = outcome(e)
			return r
		}
		r.More = len(entries) > MaxEntries
		if r.More {
			entries = entries[:MaxEntries]
		}
		r.Entries = []protocol.FileEntry{}
		for _, v := range entries {
			if !Name(v.Name()) {
				continue
			}
			i, e := v.Info()
			if e != nil || i.Mode()&os.ModeSymlink != 0 || !i.IsDir() && !i.Mode().IsRegular() {
				continue
			}
			r.Entries = append(r.Entries, protocol.FileEntry{Name: v.Name(), Directory: i.IsDir(), Size: i.Size(), Modified: max(int64(0), i.ModTime().Unix())})
		}
		sort.Slice(r.Entries, func(i, j int) bool {
			if r.Entries[i].Directory != r.Entries[j].Directory {
				return r.Entries[i].Directory
			}
			return strings.ToLower(r.Entries[i].Name) < strings.ToLower(r.Entries[j].Name)
		})
	case "download":
		f, e := root.Open(q.Path)
		if e != nil {
			r.Outcome = outcome(e)
			return r
		}
		defer f.Close()
		i, e := f.Stat()
		physical, physicalErr := canonicalFile(f)
		base, baseErr := canonical(selected.Path)
		relative, relErr := filepath.Rel(base, physical)
		if e != nil || physicalErr != nil || baseErr != nil || relErr != nil || !Path(filepath.ToSlash(relative)) || !i.Mode().IsRegular() || !singleLink(f) || a.blocked(physical) {
			return r
		}
		if i.Size() > MaxFile {
			r.Outcome = "too_large"
			return r
		}
		b, e := io.ReadAll(io.LimitReader(f, MaxFile+1))
		if e != nil {
			r.Outcome = "failed"
			return r
		}
		after, e := f.Stat()
		if e != nil || after.Size() != i.Size() || !after.ModTime().Equal(i.ModTime()) || int64(len(b)) != i.Size() {
			r.Outcome = "changed"
			return r
		}
		if len(b) > MaxFile {
			r.Outcome = "too_large"
			return r
		}
		r.Data = b
		r.Size = int64(len(b))
		r.Hash = Digest(b)
	case "upload":
		parent, e := root.OpenRoot(filepath.FromSlash(path.Dir(q.Path)))
		if e != nil {
			r.Outcome = outcome(e)
			return r
		}
		defer parent.Close()
		anchor, e := parent.Open(".")
		if e != nil {
			return r
		}
		physical, e := canonicalFile(anchor)
		anchor.Close()
		if e != nil || a.blocked(physical) {
			return r
		}
		var random [16]byte
		if _, e = rand.Read(random[:]); e != nil {
			return r
		}
		temp := ".openrmm-" + hex.EncodeToString(random[:]) + ".part"
		f, e := parent.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			r.Outcome = outcome(e)
			return r
		}
		defer parent.Remove(temp)
		n, e := f.Write(q.Data)
		if e == nil && n != len(q.Data) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			r.Outcome = "unknown"
			return r
		}
		if ctx.Err() != nil {
			r.Outcome = "unknown"
			return r
		}
		// An atomic, non-replacing directory entry commit. Never truncate/replace the
		// destination, including when another writer creates it during the transfer.
		if e = parent.Link(temp, path.Base(q.Path)); e != nil {
			r.Outcome = outcome(e)
			return r
		}
		r.Size = q.Size
		r.Hash = q.Hash
	}
	r.Outcome = "succeeded"
	return r
}
func safeNames(p string) bool {
	p = strings.TrimPrefix(p, filepath.VolumeName(p))
	p = strings.Trim(p, `/\`)
	for _, v := range strings.FieldsFunc(p, func(c rune) bool { return c == '/' || c == '\\' }) {
		if !Name(v) {
			return false
		}
	}
	return true
}
func outcome(e error) string {
	if errors.Is(e, os.ErrNotExist) {
		return "not_found"
	}
	if errors.Is(e, os.ErrExist) {
		return "exists"
	}
	if errors.Is(e, os.ErrPermission) {
		return "denied"
	}
	return "failed"
}
