package response

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Indicator hunts. The matcher is platform neutral; the sources
// (processes, connections, DNS cache, persistence report, file locations)
// come from the platform files.

// huntTime bounds the search itself, so a partial result is still uploaded
// within the action's time limit.
const huntTime = 15 * time.Minute

// maxHuntFiles bounds the files one hunt looks at (a variable for tests).
var maxHuntFiles = 500000

type matcher struct {
	hashes  map[protocol.Indicator]bool
	names   []glob
	paths   []glob
	cmds    []protocol.Indicator
	lowCmds []string
	domains []protocol.Indicator
	nets    []netip.Prefix
	netOf   []protocol.Indicator
	want    hashSet
}

// glob is a name or path indicator: tail is the lower-case literal text
// after its last wildcard, checked before the pattern runs, so a hunt with a
// thousand patterns stays cheap per file; a pattern without wildcards is
// compared directly (re is nil).
type glob struct {
	ind  protocol.Indicator
	re   *regexp.Regexp
	tail string
}

func newGlob(i protocol.Indicator) glob {
	p := strings.ToLower(envVar.ReplaceAllString(strings.ReplaceAll(i.Value, "/", `\`), "*"))
	g := glob{ind: i, tail: p[strings.LastIndexAny(p, "*?")+1:]}
	if strings.ContainsAny(p, "*?") {
		g.re = globPattern(i.Value)
	}
	return g
}

func (g glob) match(lower, s string) bool {
	if !strings.HasSuffix(lower, g.tail) {
		return false
	}
	return g.re == nil && lower == g.tail || g.re != nil && g.re.MatchString(s)
}

// hashSet names the digests a hunt needs.
type hashSet struct{ sha256, sha1, md5 bool }

func (h hashSet) any() bool { return h.sha256 || h.sha1 || h.md5 }

// fileHashes are a file's digests (only those computed).
type fileHashes struct{ sha256, sha1, md5 string }

var envVar = regexp.MustCompile(`%[^%\\/]+%`)

// globPattern compiles a case-insensitive pattern where * is any text
// (folder separators included), ? one character, and %VAR% any text (as in
// indicator lists that name %APPDATA% paths). Slashes match backslashes.
func globPattern(p string) *regexp.Regexp {
	p = envVar.ReplaceAllString(strings.ReplaceAll(p, "/", `\`), "*")
	var b strings.Builder
	b.WriteString(`(?is)^`)
	for _, r := range p {
		switch r {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`$`)
	return regexp.MustCompile(b.String())
}

func newMatcher(spec protocol.HuntSpec) *matcher {
	m := &matcher{hashes: map[protocol.Indicator]bool{}}
	for _, i := range spec.Indicators {
		switch i.Type {
		case "sha256":
			m.hashes[i], m.want.sha256 = true, true
		case "sha1":
			m.hashes[i], m.want.sha1 = true, true
		case "md5":
			m.hashes[i], m.want.md5 = true, true
		case "name":
			m.names = append(m.names, newGlob(i))
		case "path":
			m.paths = append(m.paths, newGlob(i))
		case "cmd":
			m.cmds, m.lowCmds = append(m.cmds, i), append(m.lowCmds, strings.ToLower(i.Value))
		case "domain":
			m.domains = append(m.domains, i)
		case "ip":
			p, e := netip.ParsePrefix(i.Value)
			if e != nil {
				a, _ := netip.ParseAddr(i.Value)
				p = netip.PrefixFrom(a, a.BitLen())
			}
			m.nets, m.netOf = append(m.nets, p), append(m.netOf, i)
		}
	}
	return m
}

func (m *matcher) byName(name string) []protocol.Indicator {
	return byGlob(m.names, name)
}

func (m *matcher) byPath(path string) []protocol.Indicator {
	return byGlob(m.paths, path)
}

func byGlob(list []glob, s string) []protocol.Indicator {
	if s == "" || len(list) == 0 {
		return nil
	}
	s = strings.ReplaceAll(s, "/", `\`)
	lower := strings.ToLower(s)
	var out []protocol.Indicator
	for _, g := range list {
		if g.match(lower, s) {
			out = append(out, g.ind)
		}
	}
	return out
}

func (m *matcher) byHash(h fileHashes) []protocol.Indicator {
	var out []protocol.Indicator
	for _, i := range []protocol.Indicator{{Type: "sha256", Value: h.sha256}, {Type: "sha1", Value: h.sha1}, {Type: "md5", Value: h.md5}} {
		if i.Value != "" && m.hashes[i] {
			out = append(out, i)
		}
	}
	return out
}

func (m *matcher) byCommand(cmd string) []protocol.Indicator {
	var out []protocol.Indicator
	lower := strings.ToLower(cmd)
	for n, i := range m.cmds {
		if cmd != "" && strings.Contains(lower, m.lowCmds[n]) {
			out = append(out, i)
		}
	}
	return out
}

func (m *matcher) byAddress(addr string) []protocol.Indicator {
	a, e := netip.ParseAddr(addr)
	if e != nil {
		return nil
	}
	a = a.Unmap().WithZone("")
	var out []protocol.Indicator
	for n, p := range m.nets {
		if p.Contains(a) {
			out = append(out, m.netOf[n])
		}
	}
	return out
}

func (m *matcher) byDomain(name string) []protocol.Indicator {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var out []protocol.Indicator
	for _, i := range m.domains {
		if base, wild := strings.CutPrefix(i.Value, "*."); wild && (name == base || strings.HasSuffix(name, "."+base)) || !wild && name == i.Value {
			out = append(out, i)
		}
	}
	return out
}

// huntSources gather what a hunt searches; nil sources are skipped.
type huntSources struct {
	processes   func(context.Context) ([]protocol.ProcessDetail, error)
	connections func(context.Context) ([]protocol.Connection, error)
	dns         func(context.Context) ([]dnsRecord, error)
	persistence func(context.Context) ([]protocol.PersistenceEntry, error)
	// roots are the file locations: folders searched with their subfolders,
	// or only their own files (shallow).
	roots func() []huntRoot
	// hash computes the wanted digests of a file of at most
	// protocol.MaxHuntFileBytes, or returns a note (too_large, unreadable).
	hash func(ctx context.Context, path string, want hashSet) (fileHashes, string)
}

type huntRoot struct {
	dir     string
	shallow bool
}

type dnsRecord struct{ name, data string }

// hunt runs an indicator hunt over the sources.
func hunt(ctx context.Context, spec protocol.HuntSpec, src huntSources, n *notes) protocol.HuntResult {
	ctx, cancel := context.WithTimeout(ctx, huntTime)
	defer cancel()
	m := newMatcher(spec)
	r := protocol.HuntResult{Outcome: "ok", Matches: []protocol.HuntMatch{}}
	add := func(base protocol.HuntMatch, found []protocol.Indicator) bool {
		for _, i := range found {
			if len(r.Matches) == protocol.MaxHuntMatches {
				r.More = true
				return false
			}
			match := base
			match.Indicator = i
			match.Path, match.Name, match.Command = cut(match.Path, 2048), cut(match.Name, 512), cut(match.Command, 2048)
			match.User, match.Address, match.Detail = cut(match.User, 256), cut(match.Address, 256), cut(match.Detail, 1024)
			r.Matches = append(r.Matches, match)
		}
		return true
	}
	partial := func() bool {
		if ctx.Err() != nil {
			r.Outcome = "partial"
			return true
		}
		return false
	}
	objectFile := spec.Needs("name", "path", "sha256", "sha1", "md5")
	// Running processes.
	if objectFile || spec.Needs("cmd") {
		if src.processes != nil {
			list, e := src.processes(ctx)
			if e != nil {
				n.add("processes could not be listed")
			}
			r.Scanned.Processes = len(list)
			for _, p := range list {
				if partial() {
					break
				}
				found := append(append(append(m.byName(p.Name), m.byPath(p.Image)...), m.byCommand(p.CommandLine)...), m.imageHashes(ctx, src, p.Image, p.SHA256)...)
				if !add(protocol.HuntMatch{Area: "process", Path: p.Image, Name: p.Name, PID: p.PID, User: p.User, Command: p.CommandLine, SHA256: p.SHA256}, found) {
					break
				}
			}
		}
	}
	// Network connections and the DNS cache.
	if spec.Needs("ip") && src.connections != nil && !partial() {
		list, e := src.connections(ctx)
		if e != nil {
			n.add("network connections could not be listed")
		}
		r.Scanned.Connections = len(list)
		for _, c := range list {
			found := m.byAddress(c.RemoteAddress)
			detail := c.Protocol + " " + c.LocalAddress + " → " + c.RemoteAddress
			if !add(protocol.HuntMatch{Area: "connection", Address: c.RemoteAddress, PID: c.PID, Name: c.Process, Detail: detail}, found) {
				break
			}
		}
	}
	if spec.Needs("domain", "ip") && src.dns != nil && !partial() {
		list, e := src.dns(ctx)
		if e != nil {
			n.add("the DNS cache could not be read")
		}
		r.Scanned.DNS = len(list)
		for _, d := range list {
			found := append(append(m.byDomain(d.name), m.byDomain(d.data)...), m.byAddress(d.data)...)
			if !add(protocol.HuntMatch{Area: "dns", Name: d.name, Address: d.data}, found) {
				break
			}
		}
	}
	// The persistence report.
	if (objectFile || spec.Needs("cmd")) && src.persistence != nil && !partial() {
		list, e := src.persistence(ctx)
		if e != nil {
			n.add("the persistence report could not be built")
		}
		r.Scanned.Persistence = len(list)
		for _, p := range list {
			if partial() {
				break
			}
			found := append(append(append(m.byName(filepath.Base(p.Image)), m.byPath(p.Image)...), m.byCommand(p.Command)...), m.imageHashes(ctx, src, p.Image, p.SHA256)...)
			if p.Image == "" {
				found = append(m.byPath(p.Command), m.byCommand(p.Command)...)
			}
			if !add(protocol.HuntMatch{Area: "persistence", Path: p.Image, Name: p.Name, User: p.User, Command: p.Command, SHA256: p.SHA256, Detail: p.Category + ": " + p.Location}, found) {
				break
			}
		}
	}
	// Files in the common locations.
	if spec.Files && objectFile && src.roots != nil && !partial() {
		skipped, capped := m.files(ctx, src, &r, add)
		r.Skipped += skipped
		if capped {
			r.Outcome = "partial"
			n.add("more than 500,000 files in the searched locations; the rest were not searched")
		}
		partial()
	}
	return r
}

// cut shortens text to at most n bytes of valid UTF-8.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// imageHashes matches a program's hashes: the SHA-256 already known, others
// computed when the hunt has such indicators.
func (m *matcher) imageHashes(ctx context.Context, src huntSources, image, known string) []protocol.Indicator {
	if !m.want.any() || image == "" {
		return nil
	}
	h := fileHashes{sha256: known}
	if (m.want.sha1 || m.want.md5 || m.want.sha256 && known == "") && src.hash != nil {
		if computed, note := src.hash(ctx, image, m.want); note == "" {
			h = computed
		}
	}
	return m.byHash(h)
}

// hashWorkers hash files in parallel: opening a file waits on the
// antivirus scan as much as on the disk.
const hashWorkers = 4

// files walks the roots without following links or junctions, matching
// names and paths, and hashing files up to MaxHuntFileBytes (in parallel)
// when the hunt has hash indicators. It returns the count of skipped files
// and folders, and whether the file limit stopped it. A file open or folder
// read can block beyond cancellation (an oplock, a filter driver): shortly
// after the time limit the walk is abandoned, and its late results ignored.
func (m *matcher) files(ctx context.Context, src huntSources, r *protocol.HuntResult, add func(protocol.HuntMatch, []protocol.Indicator) bool) (int, bool) {
	var (
		mu                     sync.Mutex
		closed, capped         bool
		files, hashed, skipped int
		full                   atomic.Bool
		wg                     sync.WaitGroup
	)
	// locked runs f unless the walk was abandoned.
	locked := func(f func()) {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			f()
		}
	}
	report := func(path string, d fs.DirEntry, h fileHashes, found []protocol.Indicator) {
		if len(found) == 0 {
			return
		}
		match := protocol.HuntMatch{Area: "file", Path: path, Name: d.Name(), SHA256: h.sha256}
		if info, _ := d.Info(); info != nil {
			match.Size, match.Modified = info.Size(), stamp(info.ModTime())
		}
		locked(func() {
			if !add(match, found) {
				full.Store(true)
			}
		})
	}
	type job struct {
		path  string
		d     fs.DirEntry
		found []protocol.Indicator
	}
	hashing := m.want.any() && src.hash != nil
	jobs := make(chan job, 256)
	if hashing {
		for range hashWorkers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					if ctx.Err() != nil || full.Load() {
						continue
					}
					h, note := src.hash(ctx, j.path, m.want)
					locked(func() {
						if note == "" {
							hashed++
						} else if ctx.Err() == nil {
							skipped++
						}
					})
					found := j.found
					if note == "" {
						found = append(found, m.byHash(h)...)
					}
					report(j.path, j.d, h, found)
				}
			}()
		}
	}
	walk := func() {
		defer func() {
			close(jobs)
			wg.Wait()
		}()
		seen := map[string]bool{}
		stop := errors.New("stop")
		for _, root := range src.roots() {
			key := strings.ToLower(filepath.Clean(root.dir))
			if seen[key] {
				continue
			}
			seen[key] = true
			e := filepath.WalkDir(root.dir, func(path string, d fs.DirEntry, err error) error {
				if ctx.Err() != nil || full.Load() {
					return stop
				}
				if err != nil {
					if path != root.dir {
						locked(func() { skipped++ })
					}
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if d.IsDir() {
					if path == root.dir {
						return nil
					}
					if root.shallow {
						return fs.SkipDir
					}
					// A folder reached through another root is searched once.
					if seen[strings.ToLower(path)] {
						return fs.SkipDir
					}
					return nil
				}
				if !d.Type().IsRegular() {
					return nil
				}
				counted := false
				locked(func() {
					if files == maxHuntFiles {
						capped = true
						return
					}
					files++
					counted = true
				})
				if !counted {
					return stop
				}
				found := append(m.byName(d.Name()), m.byPath(path)...)
				if hashing {
					select {
					case jobs <- job{path, d, found}:
					case <-ctx.Done():
						return stop
					}
					return nil
				}
				report(path, d, fileHashes{}, found)
				return nil
			})
			if e == stop {
				break
			}
		}
	}
	done := make(chan struct{})
	go func() {
		walk()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		select {
		case <-done:
		case <-time.After(abandonAfter):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	closed = true
	r.Scanned.Files, r.Scanned.Hashed = files, hashed
	return skipped, capped
}

// abandonAfter is how long a walk may overrun the time limit (a variable
// for tests).
var abandonAfter = 10 * time.Second

// hashFile computes the wanted digests of a file of at most
// protocol.MaxHuntFileBytes; a SHA-256 alone comes from the hash cache.
func hashFile(ctx context.Context, cache *HashCache, path string, want hashSet) (fileHashes, string) {
	if networkPath(path) {
		return fileHashes{}, "network_path"
	}
	i, e := os.Stat(path)
	if e != nil || !i.Mode().IsRegular() {
		return fileHashes{}, "unreadable"
	}
	if i.Size() > protocol.MaxHuntFileBytes {
		return fileHashes{}, "too_large"
	}
	if !want.sha1 && !want.md5 {
		sum, note := cache.Hash(ctx, path)
		return fileHashes{sha256: sum}, note
	}
	f, e := os.Open(path)
	if e != nil {
		return fileHashes{}, "unreadable"
	}
	defer f.Close()
	var writers []io.Writer
	var s256, s1, s5 hash.Hash
	if want.sha256 {
		s256 = sha256.New()
		writers = append(writers, s256)
	}
	if want.sha1 {
		s1 = sha1.New()
		writers = append(writers, s1)
	}
	if want.md5 {
		s5 = md5.New()
		writers = append(writers, s5)
	}
	w := io.MultiWriter(writers...)
	buf := hashBuffers.Get().(*[hashBuffer]byte)
	defer hashBuffers.Put(buf)
	var total int64
	for {
		if ctx.Err() != nil {
			return fileHashes{}, "unreadable"
		}
		k, e := f.Read(buf[:])
		total += int64(k)
		if total > protocol.MaxHuntFileBytes {
			return fileHashes{}, "too_large"
		}
		w.Write(buf[:k])
		if e == io.EOF {
			break
		}
		if e != nil {
			return fileHashes{}, "unreadable"
		}
	}
	var h fileHashes
	if s256 != nil {
		h.sha256 = hex.EncodeToString(s256.Sum(nil))
	}
	if s1 != nil {
		h.sha1 = hex.EncodeToString(s1.Sum(nil))
	}
	if s5 != nil {
		h.md5 = hex.EncodeToString(s5.Sum(nil))
	}
	return h, ""
}
