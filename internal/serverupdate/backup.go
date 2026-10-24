package serverupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Backups copies the server's data and secrets folders (not the evidence
// volume, which updates do not touch) while the server is stopped.
type Backups struct {
	Dir     string            // backup volume
	Sources map[string]string // name → folder, such as "data" → /data
	// CheckDB verifies the copied database (SQLite integrity check).
	CheckDB func(path string) error
	// DB is the database's path inside the "data" source.
	DB   string
	Keep int
}

const sumsFile = "SHA256SUMS"

func hashFile(path string) (string, error) {
	f, e := os.Open(path)
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
	in, e := os.Open(src)
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

// Create copies every source into Dir/name and verifies the copy: each
// file's hash is compared with the original and the database copy must
// pass the integrity check.
func (b Backups) Create(name string) error {
	root := filepath.Join(b.Dir, name)
	if e := os.Mkdir(root, 0700); e != nil {
		return e
	}
	var sums []string
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
			return nil
		})
		if e != nil {
			return e
		}
	}
	if b.CheckDB != nil {
		if e := b.checkDB(filepath.Join(root, "data")); e != nil {
			return fmt.Errorf("the database copy failed its integrity check: %w", e)
		}
	}
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
	if !backupName.MatchString(name) {
		return nil, errors.New("invalid backup name")
	}
	root := filepath.Join(b.Dir, name)
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

// Prune keeps the newest Keep backups (names sort by time).
func (b Backups) Prune() error {
	entries, e := os.ReadDir(b.Dir)
	if e != nil {
		return e
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() || !backupName.MatchString(entry.Name()) {
			continue
		}
		// An incomplete backup (no hash list) is never counted or kept.
		if _, e := os.Stat(filepath.Join(b.Dir, entry.Name(), sumsFile)); e != nil {
			if e = os.RemoveAll(filepath.Join(b.Dir, entry.Name())); e != nil {
				return e
			}
			continue
		}
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	keep := max(b.Keep, 1)
	for len(names) > keep {
		if e := os.RemoveAll(filepath.Join(b.Dir, names[0])); e != nil {
			return e
		}
		names = names[1:]
	}
	return nil
}
