package serverupdate

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Evidence is backed up separately from the server state and only on
// request: it can be far larger. Stored evidence is content-addressed
// (sha256/<first two hex digits>/<hash>) and never changes, so an export can
// be incremental by file and an import can check every file by its name.

var evidenceName = regexp.MustCompile(`^sha256/([0-9a-f]{2})/([0-9a-f]{64})$`)

// ExportEvidence writes the stored evidence files changed at or after since
// (Unix time; 0 for all) as a tar stream. Unfinished uploads are skipped.
func ExportEvidence(dir string, since int64, w io.Writer) (int, error) {
	tw := tar.NewWriter(w)
	count := 0
	e := filepath.WalkDir(filepath.Join(dir, "sha256"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == filepath.Join(dir, "sha256") {
				return fs.SkipDir
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		info, e := d.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || !evidenceName.MatchString(rel) || info.ModTime().Unix() < since {
			return nil
		}
		if e = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Mode: 0400, Size: info.Size(), ModTime: info.ModTime()}); e != nil {
			return e
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		if _, e = io.Copy(tw, f); e != nil {
			return e
		}
		count++
		return nil
	})
	if e != nil {
		return count, e
	}
	return count, tw.Close()
}

// ImportEvidence adds evidence files from an export, skipping files already
// present. Each file must match the hash in its name.
func ImportEvidence(dir string, r io.Reader) (added, skipped int, err error) {
	tr := tar.NewReader(r)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			return added, skipped, nil
		}
		if e != nil {
			return added, skipped, errors.New("the evidence file is damaged")
		}
		m := evidenceName.FindStringSubmatch(h.Name)
		if h.Typeflag != tar.TypeReg || m == nil || !strings.HasPrefix(m[2], m[1]) {
			return added, skipped, errors.New("the evidence file contains unexpected entries")
		}
		target := filepath.Join(dir, filepath.FromSlash(h.Name))
		if _, e := os.Stat(target); e == nil {
			skipped++
			continue
		}
		if e := os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return added, skipped, e
		}
		part := target + ".import"
		f, e := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if e != nil {
			return added, skipped, e
		}
		hash := sha256.New()
		_, e1 := io.Copy(io.MultiWriter(f, hash), tr)
		e2 := f.Sync()
		e3 := f.Close()
		if e = errors.Join(e1, e2, e3); e == nil && hex.EncodeToString(hash.Sum(nil)) != m[2] {
			e = errors.New("an evidence file does not match its hash")
		}
		if e == nil {
			e = os.Chmod(part, 0400)
		}
		if e == nil {
			e = os.Rename(part, target)
		}
		if e != nil {
			_ = os.Remove(part)
			return added, skipped, e
		}
		added++
	}
}
