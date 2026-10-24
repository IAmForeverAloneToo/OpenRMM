package filetransfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// DropFile writes a file a case sends to the device at full, a
// local fixed-drive path whose folder exists and is outside OpenRMM's
// folders (deny). The content is written by write into a temporary file in
// that folder, checked against size and hash, then committed: create-only
// (refused as exists when a file is there), or replacing the existing file
// with overwrite (its hash is recorded first). The written file is read back
// and verified.
func DropFile(full string, overwrite bool, deny []string, size int64, hash string, write func(io.Writer) error) protocol.DropResult {
	r := protocol.DropResult{Path: full, SHA256: hash, Size: size, Outcome: "denied"}
	if runtime.GOOS != "windows" || !protocol.ValidDropPath(full) {
		return r
	}
	a := &localAdapter{roots: fixedDrives, deny: deny}
	roots, e := a.load()
	if e != nil {
		return r
	}
	volume := filepath.VolumeName(full)
	var selected *LocalRoot
	for _, v := range roots {
		if strings.EqualFold(strings.TrimRight(v.Path, `\`), volume) && v.Write {
			v := v
			selected = &v
		}
	}
	relative := filepath.ToSlash(strings.TrimLeft(full[len(volume):], `\`))
	dir, name := path.Dir(relative), path.Base(relative)
	if selected == nil || !EvidencePath(relative) {
		return r
	}
	root, e := os.OpenRoot(selected.Path)
	if e != nil {
		return r
	}
	defer root.Close()
	// Every folder on the way must be a real folder (no links).
	if dir != "." {
		part := "."
		for _, v := range strings.Split(dir, "/") {
			part = path.Join(part, v)
			i, e := root.Lstat(part)
			if e != nil {
				r.Outcome = outcome(e)
				return r
			}
			if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode()&os.ModeIrregular != 0 {
				return r
			}
		}
	}
	parent, e := root.OpenRoot(filepath.FromSlash(dir))
	if e != nil {
		r.Outcome = outcome(e)
		return r
	}
	defer parent.Close()
	anchor, e := parent.Open(".")
	if e != nil {
		return r
	}
	folder, e := canonicalFile(anchor)
	anchor.Close()
	if e != nil || a.blocked(folder) {
		return r
	}
	r.Path = filepath.Join(folder, name)
	if i, e := parent.Lstat(name); e == nil {
		if !overwrite {
			r.Outcome = "exists"
			return r
		}
		if !i.Mode().IsRegular() {
			return r
		}
		existing, e := parent.Open(name)
		if e != nil {
			r.Outcome = outcome(e)
			return r
		}
		_, physical, ok := a.evidenceCheck(existing, selected.Path, r.Path, false)
		if ok {
			r.ReplacedSHA256 = digestFile(existing)
		}
		existing.Close()
		if !ok || physical == "" {
			return r
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		r.Outcome = outcome(e)
		return r
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		r.Outcome = "failed"
		return r
	}
	temp := ".openrmm-" + hex.EncodeToString(random[:]) + ".part"
	f, e := parent.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		r.Outcome = outcome(e)
		return r
	}
	defer parent.Remove(temp)
	h := sha256.New()
	counter := &countWriter{}
	e = write(io.MultiWriter(f, h, counter))
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		r.Outcome = "failed"
		return r
	}
	if counter.n != size || hex.EncodeToString(h.Sum(nil)) != hash {
		r.Outcome = "hash_mismatch"
		return r
	}
	if overwrite && r.ReplacedSHA256 != "" {
		e = parent.Rename(temp, name)
		r.Replaced = e == nil
	} else {
		// A non-replacing commit: refused if a file appeared meanwhile.
		e = parent.Link(temp, name)
	}
	if e != nil {
		r.Outcome = outcome(e)
		return r
	}
	// Read the written file back.
	written, e := parent.Open(name)
	if e != nil {
		r.Outcome = "failed"
		return r
	}
	defer written.Close()
	_, physical, ok := a.evidenceCheck(written, selected.Path, r.Path, false)
	if ok {
		r.Path = physical
	}
	r.Verified = ok && digestFile(written) == hash
	r.Outcome = "written"
	return r
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func digestFile(f *os.File) string {
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return ""
	}
	h := sha256.New()
	if _, e := io.Copy(h, f); e != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
