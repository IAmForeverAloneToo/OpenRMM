package serverupdate

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Backups copies the server's data and secrets folders (not the evidence
// volume, which is exported separately) into the backup volume. Update and
// restore backups are taken while the server is stopped; nightly and manual
// backups while it runs, with a consistent copy of the live database.
type Backups struct {
	Dir     string            // backup volume
	Sources map[string]string // name → folder, such as "data" → /data
	// CheckDB verifies the copied database (SQLite integrity check).
	CheckDB func(path string) error
	// DB is the database's path inside the "data" source.
	DB string
	// Keep overrides how many update backups are kept (default 3).
	Keep int
	// Snapshot copies the live database consistently (SQLite VACUUM INTO);
	// required for backups taken while the server runs.
	Snapshot func(src, dst string) error
	// Inspect reads a database copy's installation ID and schema version for
	// the backup's description; optional.
	Inspect func(path string) (instance string, schema int, err error)
}

const (
	sumsFile = "SHA256SUMS"
	metaFile = "backup.json"
	// partPrefix marks a backup still being written or imported; it is
	// never listed, restored or counted.
	partPrefix = ".part-"
)

// Backup kinds and how many of each are kept.
var keepKinds = map[string]int{"update": 3, "nightly": 7, "manual": 5, "pre-restore": 3}

var anyBackupName = regexp.MustCompile(`^(update|nightly|manual|pre-restore)-([0-9]{8}-[0-9]{6})(-[0-9]{1,5})?$`)

// ValidBackupName reports whether a name is one the updater creates.
func ValidBackupName(name string) bool { return anyBackupName.MatchString(name) }

// NewBackupName names a backup of a kind taken at a time.
func NewBackupName(kind string, at time.Time) string {
	return kind + "-" + at.UTC().Format("20060102-150405")
}

// BackupInfo describes a backup for listings.
type BackupInfo struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	CreatedAt     int64  `json:"created_at"`
	Live          bool   `json:"live"`
	Size          int64  `json:"size"`
	InstanceID    string `json:"instance_id,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
}

func kindOf(name string) string {
	m := anyBackupName.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1]
}

func timeOf(name string) int64 {
	m := anyBackupName.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	t, e := time.Parse("20060102-150405", m[2])
	if e != nil {
		return 0
	}
	return t.Unix()
}

func hashFile(path string) (string, error) {
	f, e := openRegular(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, e := openRegular(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if e != nil {
		return e
	}
	_, e1 := io.Copy(out, in)
	e2 := out.Sync()
	e3 := out.Close()
	return errors.Join(e1, e2, e3)
}

// Create copies every source into Dir/name while the server is stopped and
// verifies the copy: each file's hash is compared with the original and the
// database copy must pass the integrity check.
func (b Backups) Create(name string) error { return b.create(name, false) }

// CreateLive takes a backup while the server runs: the database is copied
// with Snapshot, every other file as with Create.
func (b Backups) CreateLive(name string) error {
	if b.Snapshot == nil {
		return errors.New("live backups are not available")
	}
	return b.create(name, true)
}

func (b Backups) create(name string, live bool) error {
	if !ValidBackupName(name) {
		return errors.New("invalid backup name")
	}
	if _, e := os.Lstat(filepath.Join(b.Dir, name)); e == nil {
		return errors.New("a backup with this name already exists")
	}
	part := filepath.Join(b.Dir, partPrefix+name)
	if e := os.Mkdir(part, 0700); e != nil {
		return e
	}
	if e := b.fill(part, live); e != nil {
		_ = os.RemoveAll(part)
		return e
	}
	return os.Rename(part, filepath.Join(b.Dir, name))
}

// isDatabaseFile reports whether a path inside the data source belongs to
// the live database (copied with Snapshot instead).
func (b Backups) isDatabaseFile(rel string) bool {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if filepath.ToSlash(rel) == filepath.ToSlash(b.DB)+suffix {
			return true
		}
	}
	return false
}

func (b Backups) fill(root string, live bool) error {
	var sums []string
	var size int64
	names := make([]string, 0, len(b.Sources))
	for n := range b.Sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		src := b.Sources[n]
		e := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(src, path)
			dst := filepath.Join(root, n, rel)
			info, e := d.Info()
			if e != nil {
				return e
			}
			switch {
			case d.IsDir():
				return os.MkdirAll(dst, 0700)
			case live && n == "data" && b.isDatabaseFile(rel):
				return nil
			case !info.Mode().IsRegular():
				return fmt.Errorf("unexpected file type in %s", n)
			}
			want, e := hashFile(path)
			if e != nil {
				return e
			}
			if e = copyFile(path, dst, info.Mode()); e != nil {
				return e
			}
			got, e := hashFile(dst)
			if e != nil {
				return e
			}
			if got != want {
				return errors.New("a backup copy does not match its original")
			}
			sums = append(sums, want+"  "+filepath.ToSlash(filepath.Join(n, rel)))
			size += info.Size()
			return nil
		})
		if e != nil {
			return e
		}
	}
	if live {
		dst := filepath.Join(root, "data", filepath.FromSlash(b.DB))
		if e := os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
			return e
		}
		if e := b.Snapshot(filepath.Join(b.Sources["data"], filepath.FromSlash(b.DB)), dst); e != nil {
			return e
		}
		if e := os.Chmod(dst, 0600); e != nil {
			return e
		}
		sum, e := hashFile(dst)
		if e != nil {
			return e
		}
		info, e := os.Stat(dst)
		if e != nil {
			return e
		}
		sums = append(sums, sum+"  "+path.Join("data", filepath.ToSlash(b.DB)))
		size += info.Size()
	}
	if b.CheckDB != nil {
		if e := b.checkDB(filepath.Join(root, "data")); e != nil {
			return fmt.Errorf("the database copy failed its integrity check: %w", e)
		}
	}
	name := strings.TrimPrefix(filepath.Base(root), partPrefix)
	meta := BackupInfo{Name: name, Kind: kindOf(name), CreatedAt: timeOf(name), Live: live, Size: size}
	if b.Inspect != nil {
		if id, schema, e := b.Inspect(filepath.Join(root, "data", filepath.FromSlash(b.DB))); e == nil {
			meta.InstanceID, meta.SchemaVersion = id, schema
		}
	}
	if e := writeJSON(filepath.Join(root, metaFile), meta); e != nil {
		return e
	}
	slices.Sort(sums)
	return os.WriteFile(filepath.Join(root, sumsFile), []byte(strings.Join(sums, "\n")+"\n"), 0600)
}

// checkDB runs the integrity check on a scratch copy: SQLite may create or
// rewrite its -wal and -shm files even on a read-only connection, which must
// not change the hashed backup.
func (b Backups) checkDB(data string) error {
	scratch, e := os.MkdirTemp(b.Dir, ".check-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(scratch)
	for _, suffix := range []string{"", "-wal"} {
		src := filepath.Join(data, b.DB+suffix)
		info, e := os.Stat(src)
		if errors.Is(e, fs.ErrNotExist) && suffix != "" {
			continue
		}
		if e != nil {
			return e
		}
		if e = copyFile(src, filepath.Join(scratch, filepath.Base(b.DB)+suffix), info.Mode()); e != nil {
			return e
		}
	}
	return b.CheckDB(filepath.Join(scratch, filepath.Base(b.DB)))
}

// Verify re-checks a backup against its recorded hashes before a restore
// and returns the listed files.
func (b Backups) Verify(name string) ([]string, error) {
	if !ValidBackupName(name) {
		return nil, errors.New("invalid backup name")
	}
	return b.verifyDir(filepath.Join(b.Dir, name))
}

func (b Backups) verifyDir(root string) ([]string, error) {
	raw, e := os.ReadFile(filepath.Join(root, sumsFile))
	if e != nil {
		return nil, errors.New("the backup is incomplete")
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		sum, rel, ok := strings.Cut(line, "  ")
		first, _, _ := strings.Cut(rel, "/")
		if _, known := b.Sources[first]; !ok || !known || !filepath.IsLocal(filepath.FromSlash(rel)) {
			return nil, errors.New("the backup list is malformed")
		}
		got, e := hashFile(filepath.Join(root, filepath.FromSlash(rel)))
		if e != nil || got != sum {
			return nil, errors.New("a backup file is missing or changed")
		}
		files = append(files, rel)
	}
	return files, nil
}

// Restore puts a verified backup back: each source folder ends up with
// exactly the files listed in the backup.
func (b Backups) Restore(name string) error {
	files, e := b.Verify(name)
	if e != nil {
		return e
	}
	root := filepath.Join(b.Dir, name)
	names := make([]string, 0, len(b.Sources))
	for n := range b.Sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		entries, e := os.ReadDir(b.Sources[n])
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if e := os.RemoveAll(filepath.Join(b.Sources[n], entry.Name())); e != nil {
				return e
			}
		}
	}
	for _, rel := range files {
		first, rest, _ := strings.Cut(rel, "/")
		src := filepath.Join(root, filepath.FromSlash(rel))
		target := filepath.Join(b.Sources[first], filepath.FromSlash(rest))
		info, e := os.Stat(src)
		if e != nil {
			return e
		}
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		if e = copyFile(src, target, info.Mode()); e != nil {
			return e
		}
	}
	return nil
}

// Prune keeps the newest backups of each kind (names sort by time) and
// removes incomplete ones.
func (b Backups) Prune() error {
	entries, e := os.ReadDir(b.Dir)
	if e != nil {
		return e
	}
	byKind := map[string][]string{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			continue
		}
		// A backup interrupted while being written; one still being written
		// by another process is younger than a day.
		if strings.HasPrefix(name, partPrefix) {
			if info, e := entry.Info(); e == nil && time.Since(info.ModTime()) > 24*time.Hour {
				if e = os.RemoveAll(filepath.Join(b.Dir, name)); e != nil {
					return e
				}
			}
			continue
		}
		if !ValidBackupName(name) {
			continue
		}
		// An incomplete backup (no hash list) is never counted or kept.
		if _, e := os.Stat(filepath.Join(b.Dir, name, sumsFile)); e != nil {
			if e = os.RemoveAll(filepath.Join(b.Dir, name)); e != nil {
				return e
			}
			continue
		}
		byKind[kindOf(name)] = append(byKind[kindOf(name)], name)
	}
	for kind, names := range byKind {
		slices.Sort(names)
		keep := keepKinds[kind]
		if kind == "update" && b.Keep > 0 {
			keep = b.Keep
		}
		for len(names) > max(keep, 1) {
			if e := os.RemoveAll(filepath.Join(b.Dir, names[0])); e != nil {
				return e
			}
			names = names[1:]
		}
	}
	return nil
}

// List returns the complete backups, newest first.
func (b Backups) List() ([]BackupInfo, error) {
	entries, e := os.ReadDir(b.Dir)
	if e != nil {
		return nil, e
	}
	out := []BackupInfo{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !ValidBackupName(name) {
			continue
		}
		if _, e := os.Stat(filepath.Join(b.Dir, name, sumsFile)); e != nil {
			continue
		}
		var meta BackupInfo
		if readJSON(filepath.Join(b.Dir, name, metaFile), &meta, 4096) != nil || meta.Name != name {
			meta = BackupInfo{Name: name}
		}
		meta.Kind, meta.CreatedAt = kindOf(name), timeOf(name)
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].Name > out[j].Name
	})
	return out, nil
}

// Export writes a verified backup as a gzip-compressed tar stream (for a
// copy outside the machine).
func (b Backups) Export(name string, w io.Writer) error {
	files, e := b.Verify(name)
	if e != nil {
		return e
	}
	root := filepath.Join(b.Dir, name)
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, rel := range append([]string{sumsFile, metaFile}, files...) {
		src := filepath.Join(root, filepath.FromSlash(rel))
		info, e := os.Stat(src)
		if errors.Is(e, fs.ErrNotExist) && rel == metaFile {
			continue
		}
		if e != nil {
			return e
		}
		if e = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name + "/" + rel, Mode: 0600, Size: info.Size(), ModTime: info.ModTime()}); e != nil {
			return e
		}
		f, e := os.Open(src)
		if e != nil {
			return e
		}
		_, e = io.Copy(tw, f)
		f.Close()
		if e != nil {
			return e
		}
	}
	return errors.Join(tw.Close(), gz.Close())
}

// Import reads a backup written by Export into the backup volume and
// verifies it. It returns the backup's name; an existing backup of that
// name is never replaced.
func (b Backups) Import(r io.Reader) (string, error) {
	gz, e := gzip.NewReader(r)
	if e != nil {
		return "", errors.New("the file is not an OpenRMM backup")
	}
	tr := tar.NewReader(gz)
	name, part := "", ""
	fail := func(err error) (string, error) {
		if part != "" {
			_ = os.RemoveAll(part)
		}
		return "", err
	}
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return fail(errors.New("the backup file is damaged"))
		}
		first, rel, _ := strings.Cut(h.Name, "/")
		if name == "" {
			if !ValidBackupName(first) {
				return fail(errors.New("the file is not an OpenRMM backup"))
			}
			if _, e := os.Lstat(filepath.Join(b.Dir, first)); e == nil {
				return fail(fmt.Errorf("a backup named %s already exists; restore it by name", first))
			}
			name, part = first, filepath.Join(b.Dir, partPrefix+first)
			if e := os.Mkdir(part, 0700); e != nil {
				part = ""
				return fail(errors.New("the backup is already being imported"))
			}
		}
		if first != name || h.Typeflag != tar.TypeReg || rel == "" || !filepath.IsLocal(filepath.FromSlash(rel)) {
			return fail(errors.New("the backup file contains unexpected entries"))
		}
		dst := filepath.Join(part, filepath.FromSlash(rel))
		if e := os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
			return fail(e)
		}
		f, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return fail(errors.New("the backup file contains unexpected entries"))
		}
		_, e1 := io.Copy(f, tr)
		e2 := f.Close()
		if e = errors.Join(e1, e2); e != nil {
			return fail(errors.New("the backup file is damaged"))
		}
	}
	if name == "" {
		return fail(errors.New("the file is not an OpenRMM backup"))
	}
	if _, e := b.verifyDir(part); e != nil {
		return fail(e)
	}
	if e := os.Rename(part, filepath.Join(b.Dir, name)); e != nil {
		return fail(e)
	}
	return name, nil
}
