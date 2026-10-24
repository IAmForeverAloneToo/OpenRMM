package filetransfer

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Triage packages: the artifact types a profile names are read
// from a Volume Shadow Copy of the system drive (live, with the backup
// privilege, when no copy can be made) into one ZIP that keeps the original
// paths, with manifest.json listing every file and everything left out.

// triageRule finds files of one artifact type: Names (case-insensitive
// patterns) in Dir and, up to Depth levels below it, its subfolders (-1: any
// depth). Dir starts with %SystemRoot% or %ProgramData%, or (User) is relative
// to each user profile folder.
type triageRule struct {
	Dir   string
	Names []string
	Depth int
	User  bool
}

// sqliteNames adds the journal and write-ahead files SQLite keeps beside a
// database (recent browser history often sits in them).
func sqliteNames(names ...string) []string {
	out := []string{}
	for _, n := range names {
		out = append(out, n, n+"-journal", n+"-wal", n+"-shm")
	}
	return out
}

func hiveNames(names ...string) []string {
	out := []string{}
	for _, n := range names {
		out = append(out, n, n+".LOG1", n+".LOG2")
	}
	return out
}

var triageRules = map[string][]triageRule{
	"prefetch":      {{Dir: `%SystemRoot%\Prefetch`, Names: []string{"*.pf"}}},
	"amcache":       {{Dir: `%SystemRoot%\AppCompat\Programs`, Names: hiveNames("Amcache.hve")}},
	"registry":      {{Dir: `%SystemRoot%\System32\config`, Names: hiveNames("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT")}},
	"user_registry": {{User: true, Names: hiveNames("NTUSER.DAT")}, {User: true, Dir: `AppData\Local\Microsoft\Windows`, Names: hiveNames("UsrClass.dat")}},
	"tasks":         {{Dir: `%SystemRoot%\System32\Tasks`, Names: []string{"*"}, Depth: -1}},
	"event_logs":    {{Dir: `%SystemRoot%\System32\winevt\Logs`, Names: []string{"*.evtx"}}},
	"srum":          {{Dir: `%SystemRoot%\System32\sru`, Names: []string{"*"}}},
	"browsers": {
		{User: true, Dir: `AppData\Local\Google\Chrome\User Data`, Names: append(sqliteNames("History", "Cookies", "Web Data", "Shortcuts", "Top Sites", "Favicons"), "Bookmarks"), Depth: 2},
		{User: true, Dir: `AppData\Local\Microsoft\Edge\User Data`, Names: append(sqliteNames("History", "Cookies", "Web Data", "Shortcuts", "Top Sites", "Favicons"), "Bookmarks"), Depth: 2},
		{User: true, Dir: `AppData\Roaming\Mozilla\Firefox\Profiles`, Names: sqliteNames("places.sqlite", "cookies.sqlite", "formhistory.sqlite", "downloads.sqlite", "favicons.sqlite"), Depth: 1},
	},
	"recent":             {{User: true, Dir: `AppData\Roaming\Microsoft\Windows\Recent`, Names: []string{"*"}, Depth: -1}},
	"startup":            {{Dir: `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`, Names: []string{"*"}}, {User: true, Dir: `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, Names: []string{"*"}}},
	"powershell_history": {{User: true, Dir: `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`, Names: []string{"*.txt"}}},
	"wmi":                {{Dir: `%SystemRoot%\System32\wbem\Repository`, Names: []string{"*"}, Depth: -1}},
}

// maxTriageFiles bounds one package's file list, maxTriageSkipped its list
// of files left out (the rest are counted).
const (
	maxTriageFiles   = 200000
	maxTriageSkipped = 10000
)

// errRedirected: a folder or file resolved somewhere other than its path
// (a junction or link above it), or into a folder that is never collected.
var errRedirected = errors.New("redirected")

// triageSource reads below Root (a shadow copy device or the live volume,
// ending in a backslash): Method is recorded per file. List lists a folder
// (by its volume-relative path) after checking it is where it claims to be;
// Check accepts an opened file the same way (nil: no checks, for tests).
type triageSource struct {
	Root   string
	Method string
	Open   func(path string) (*os.File, error)
	List   func(rel string) ([]fs.DirEntry, error)
	Check  func(f *os.File, rel string) bool
}

// skip records a file or folder left out, counting those past the limit.
func skip(m *protocol.TriageManifest, s protocol.TriageSkip) {
	if len(m.Skipped) < maxTriageSkipped {
		m.Skipped = append(m.Skipped, s)
	} else {
		m.SkippedMore++
	}
}

type triageTarget struct {
	Item, Rel string
	Size      int64
}

// triageDirs gives the volume-relative folders the placeholders stand for.
type triageDirs struct {
	SystemRoot, ProgramData string
	// Users are profile folders relative to the volume.
	Users []string
}

func matchName(patterns []string, name string) bool {
	n := strings.ToLower(name)
	for _, p := range patterns {
		if ok, _ := filepath.Match(strings.ToLower(p), n); ok {
			return true
		}
	}
	return false
}

// planTriage lists the files of the artifact types, with sizes; it stops
// at maxTriageFiles or when ctx ends.
func planTriage(ctx context.Context, src triageSource, items []string, dirs triageDirs, m *protocol.TriageManifest) []triageTarget {
	files := []triageTarget{}
	seen := map[string]bool{}
	full := false
	var walk func(item, rel string, r triageRule, depth int)
	walk = func(item, rel string, r triageRule, depth int) {
		if full || ctx.Err() != nil {
			return
		}
		entries, e := src.List(rel)
		if e != nil {
			switch {
			case errors.Is(e, errRedirected):
				skip(m, protocol.TriageSkip{Path: rel, Item: item, Reason: "redirected"})
			case !errors.Is(e, fs.ErrNotExist):
				skip(m, protocol.TriageSkip{Path: rel, Item: item, Reason: "folder_unreadable"})
			}
			return
		}
		for _, d := range entries {
			child := rel + `\` + d.Name()
			// Links and junctions are never followed or collected.
			if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
				continue
			}
			if d.IsDir() {
				if r.Depth < 0 || depth < r.Depth {
					walk(item, child, r, depth+1)
				}
				continue
			}
			if !d.Type().IsRegular() || !matchName(r.Names, d.Name()) || seen[strings.ToLower(child)] {
				continue
			}
			if len(files) >= maxTriageFiles {
				full = true
				skip(m, protocol.TriageSkip{Path: rel, Item: item, Reason: "too_many_files"})
				return
			}
			i, e := d.Info()
			if e != nil {
				skip(m, protocol.TriageSkip{Path: child, Item: item, Reason: "unreadable"})
				continue
			}
			seen[strings.ToLower(child)] = true
			files = append(files, triageTarget{Item: item, Rel: child, Size: i.Size()})
		}
	}
	for _, item := range items {
		for _, r := range triageRules[item] {
			bases := []string{}
			if r.User {
				for _, u := range dirs.Users {
					bases = append(bases, strings.TrimSuffix(u+`\`+r.Dir, `\`))
				}
			} else {
				bases = append(bases, strings.NewReplacer("%SystemRoot%", dirs.SystemRoot, "%ProgramData%", dirs.ProgramData).Replace(r.Dir))
			}
			for _, b := range bases {
				walk(item, b, r, 0)
			}
		}
	}
	return files
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, e := c.w.Write(b)
	c.n += int64(n)
	return n, e
}

// ctxReader stops a copy when its context ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(b []byte) (int, error) {
	if e := c.ctx.Err(); e != nil {
		return 0, e
	}
	return c.r.Read(b)
}

// writeTriage writes the planned files and the manifest to a new ZIP at path,
// keeping it under size bytes; files that would not fit, or come after the
// deadline, are left out. It stops with ctx.
func writeTriage(ctx context.Context, src triageSource, files []triageTarget, path, volume string, size int64, deadline time.Time, m *protocol.TriageManifest) error {
	out, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer out.Close()
	cw := &countingWriter{w: out}
	zw := zip.NewWriter(cw)
	// Room for the manifest and the ZIP directory. The ZIP writer buffers, so
	// what reached the file (cw.n) lags: used also counts every entry's size
	// plus its header.
	limit, used := size-64<<20, int64(0)
	for _, t := range files {
		if e := ctx.Err(); e != nil {
			return e
		}
		if time.Now().After(deadline) {
			skip(m, protocol.TriageSkip{Path: t.Rel, Item: t.Item, Reason: "time_limit"})
			continue
		}
		if max(cw.n, used)+t.Size+512 > limit {
			skip(m, protocol.TriageSkip{Path: t.Rel, Item: t.Item, Reason: "size_limit"})
			continue
		}
		f, e := src.Open(src.Root + t.Rel)
		if e != nil {
			skip(m, protocol.TriageSkip{Path: t.Rel, Item: t.Item, Reason: triageReason(e)})
			continue
		}
		if src.Check != nil && !src.Check(f, t.Rel) {
			f.Close()
			skip(m, protocol.TriageSkip{Path: t.Rel, Item: t.Item, Reason: "redirected"})
			continue
		}
		i, e := f.Stat()
		if e != nil || !i.Mode().IsRegular() {
			f.Close()
			skip(m, protocol.TriageSkip{Path: t.Rel, Item: t.Item, Reason: "unreadable"})
			continue
		}
		name := volume + "/" + strings.ReplaceAll(t.Rel, `\`, "/")
		w, e := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: i.ModTime().UTC()})
		if e != nil {
			f.Close()
			return e
		}
		// A file that grew since it was listed is cut at its listed size plus
		// 1 MiB and marked incomplete, so the package keeps to its limit.
		h := sha256.New()
		allowed := t.Size + 1<<20
		n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(ctxReader{ctx, f}, allowed))
		f.Close()
		if e == nil && n == allowed {
			e = errors.New("file grew while it was read")
		}
		used += n + int64(len(name)) + 512
		entry := protocol.TriageFile{Path: t.Rel, Item: t.Item, Size: n, Modified: i.ModTime().UnixNano(), Created: createdTime(i), SHA256: hex.EncodeToString(h.Sum(nil)), Method: src.Method}
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// The entry holds what was read before the error.
			entry.Incomplete = true
		}
		m.Files = append(m.Files, entry)
	}
	w, e := zw.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: time.Now().UTC()})
	if e != nil {
		return e
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	if e = enc.Encode(m); e != nil {
		return e
	}
	if e = zw.Close(); e != nil {
		return e
	}
	return out.Sync()
}

func triageReason(e error) string {
	switch {
	case errors.Is(e, fs.ErrNotExist):
		return "gone"
	case errors.Is(e, fs.ErrPermission):
		return "denied"
	case isLocked(e):
		return "locked"
	}
	return "unreadable"
}

// triageTime is how long a package is built before the remaining files are
// left out (the server waits 2 hours for the upload to start).
const triageTime = 100 * time.Minute

// OpenTriage builds a triage package of the artifact types for profile and
// opens it for collection; the ZIP (and any shadow copy) is removed on Close.
// The package stays under max bytes; building stops with ctx. Outcomes:
// denied, failed, no_space.
func OpenTriage(ctx context.Context, profile string, items []string, max int64, o EvidenceOptions) (Evidence, string) {
	if runtime.GOOS != "windows" || !protocol.ValidTriageItems(items) || o.Temp == "" || o.Ledger == "" || max <= 64<<20 {
		return Evidence{}, "denied"
	}
	return openTriage(ctx, profile, items, max, o)
}
