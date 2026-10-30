package filetransfer

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/ntfs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// ntfsTime is how long an NTFS package is built before it is given up.
const ntfsTime = 100 * time.Minute

// OpenNTFS builds an NTFS artifact package (protocol.NTFSManifest) for the
// system drive, the named drives or (all) every fixed NTFS drive, up to max
// bytes. On failure it returns an outcome: denied, no_space or failed.
func OpenNTFS(ctx context.Context, volumes []string, all bool, max int64, o EvidenceOptions) (Evidence, string) {
	if runtime.GOOS != "windows" {
		return Evidence{}, "denied"
	}
	return openNTFS(ctx, volumes, all, max, o)
}

// ntfsExcluded reports whether a timeline path is one of OpenRMM's own
// files: under a denied folder, or named .openrmm-*.
func ntfsExcluded(path string, deny []string) bool {
	for _, d := range deny {
		d = strings.TrimRight(d, `\`)
		if d != "" && len(path) >= len(d) && strings.EqualFold(path[:len(d)], d) && (len(path) == len(d) || path[len(d)] == '\\') {
			return true
		}
	}
	i := strings.LastIndexByte(path, '\\')
	return strings.HasPrefix(strings.ToLower(path[i+1:]), ".openrmm-")
}

// journalRecord reports whether a record is the change journal,
// $Extend\$UsnJrnl.
func journalRecord(r ntfs.Record) bool {
	if !r.InUse || r.Base.Record != 0 {
		return false
	}
	for _, n := range r.Names {
		if n.Name == "$UsnJrnl" && n.Parent.Record == 11 {
			return true
		}
	}
	return false
}

// writeNTFSVolume adds one volume's folder to the package from a raw
// volume: the raw $MFT, $LogFile and $J, then mft.csv and usn.csv.
// Timeline rows of OpenRMM's own files (deny) are left out.
func writeNTFSVolume(ctx context.Context, zw *zip.Writer, letter string, raw io.ReaderAt, deny []string, mv *protocol.NTFSVolume) error {
	v, e := ntfs.Open(raw)
	if e != nil {
		return errors.New("cannot read the volume's NTFS structures")
	}
	mv.Serial, mv.ClusterSize, mv.RecordSize = fmt.Sprintf("%016X", v.Serial), v.ClusterSize, v.RecordSize
	folder := letter[:1] + "/"
	// The raw $MFT; its records also build the path index.
	x := ntfs.NewIndex()
	journal := uint64(0)
	mft := v.MFT()
	f, e := copyEntry(ctx, zw, folder+"$MFT", io.NewSectionReader(mft, 0, mft.Size()), func(chunk []byte, off int64) {
		for i := 0; i+v.RecordSize <= len(chunk); i += v.RecordSize {
			n := uint64(off+int64(i)) / uint64(v.RecordSize)
			if r, err := ntfs.ParseRecord(chunk[i:i+v.RecordSize], v.SectorSize, n); err == nil {
				x.Add(r)
				if journalRecord(r) {
					journal = n
				}
			}
		}
	})
	if e != nil {
		return e
	}
	mv.Files = append(mv.Files, f)
	if rec, err := v.Record(2); err == nil {
		if lf, err := v.OpenStream(rec, ""); err == nil {
			if f, e = copyEntry(ctx, zw, folder+"$LogFile", io.NewSectionReader(lf, 0, lf.Size()), nil); e != nil {
				return e
			}
			mv.Files = append(mv.Files, f)
		}
	}
	var j *ntfs.Reader
	if journal != 0 {
		if rec, err := v.Record(journal); err == nil {
			j, _ = v.OpenStream(rec, "$J")
		}
	}
	if j != nil {
		mv.JournalOffset = j.Allocated()
		if f, e = copyEntry(ctx, zw, folder+"$J", io.NewSectionReader(j, mv.JournalOffset, j.Size()-mv.JournalOffset), nil); e != nil {
			return e
		}
		mv.Files = append(mv.Files, f)
	}
	// The timelines.
	w, h, e := csvEntry(zw, folder+"mft.csv")
	if e != nil {
		return e
	}
	c, e := ntfs.NewCSV(w, ntfs.MFTColumns)
	if e != nil {
		return e
	}
	e = ntfs.ScanMFT(io.NewSectionReader(mft, 0, mft.Size()), v.Boot, func(r ntfs.Record, err error) error {
		if err != nil {
			mv.Damaged++
			return nil
		}
		row, path, ok := ntfs.MFTRow(x, r, letter)
		if !ok {
			return nil
		}
		if ntfsExcluded(path, deny) {
			mv.Excluded++
			return nil
		}
		mv.MFTRows++
		if mv.MFTRows%50000 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		return c.Write(row)
	})
	if f, e = h.finish(c, e, folder+"mft.csv"); e != nil {
		return e
	}
	mv.Files = append(mv.Files, f)
	if j == nil {
		return nil
	}
	if w, h, e = csvEntry(zw, folder+"usn.csv"); e != nil {
		return e
	}
	if c, e = ntfs.NewCSV(w, ntfs.USNColumns); e != nil {
		return e
	}
	e = ntfs.ScanUSN(io.NewSectionReader(j, mv.JournalOffset, j.Size()-mv.JournalOffset), mv.JournalOffset, func(u ntfs.USNRecord) error {
		row, path := ntfs.USNRow(x, u, letter)
		if ntfsExcluded(path, deny) {
			mv.Excluded++
			return nil
		}
		mv.USNRows++
		if mv.USNRows%50000 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		return c.Write(row)
	})
	if f, e = h.finish(c, e, folder+"usn.csv"); e != nil {
		return e
	}
	mv.Files = append(mv.Files, f)
	return nil
}

// copyEntry copies r into a new package entry in 1 MiB chunks, hashing it;
// each (if set) sees every chunk and its offset.
func copyEntry(ctx context.Context, zw *zip.Writer, name string, r io.Reader, each func([]byte, int64)) (protocol.NTFSFile, error) {
	w, e := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
	if e != nil {
		return protocol.NTFSFile{}, e
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var off int64
	for {
		if ctx.Err() != nil {
			return protocol.NTFSFile{}, ctx.Err()
		}
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			if each != nil {
				each(buf[:n], off)
			}
			h.Write(buf[:n])
			if _, e := w.Write(buf[:n]); e != nil {
				return protocol.NTFSFile{}, e
			}
			off += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return protocol.NTFSFile{}, errors.New("cannot read " + filepath.Base(name) + " from the volume")
		}
	}
	return protocol.NTFSFile{Name: name, Size: off, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// hashedEntry counts and hashes what is written to a package entry.
type hashedEntry struct {
	w    io.Writer
	h    io.Writer
	sum  func() []byte
	size int64
}

func (e *hashedEntry) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	e.h.Write(p[:n])
	e.size += int64(n)
	return n, err
}

func csvEntry(zw *zip.Writer, name string) (io.Writer, *hashedEntry, error) {
	w, e := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
	if e != nil {
		return nil, nil, e
	}
	h := sha256.New()
	he := &hashedEntry{w: w, h: h, sum: func() []byte { return h.Sum(nil) }}
	return he, he, nil
}

// finish flushes a timeline and describes its entry.
func (e *hashedEntry) finish(c interface {
	Flush()
	Error() error
}, scanErr error, name string) (protocol.NTFSFile, error) {
	c.Flush()
	if scanErr == nil {
		scanErr = c.Error()
	}
	if scanErr != nil {
		return protocol.NTFSFile{}, scanErr
	}
	return protocol.NTFSFile{Name: name, Size: e.size, SHA256: hex.EncodeToString(e.sum())}, nil
}

// NTFSEntry is a file found in an NTFS volume's MFT.
type NTFSEntry struct {
	Path, Name string
	Size       int64
	Modified   time.Time
}

// mftFiles calls fn for every file in use in a volume's MFT (directories
// and extension records left out); fn returns false to stop.
func mftFiles(ctx context.Context, letter string, raw io.ReaderAt, fn func(NTFSEntry) bool) error {
	v, e := ntfs.Open(raw)
	if e != nil {
		return e
	}
	mft := v.MFT()
	x := ntfs.NewIndex()
	n := 0
	scan := func(each func(ntfs.Record) bool) error {
		return ntfs.ScanMFT(io.NewSectionReader(mft, 0, mft.Size()), v.Boot, func(r ntfs.Record, err error) error {
			if n++; n%20000 == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil && !each(r) {
				return errStop
			}
			return nil
		})
	}
	if e = scan(func(r ntfs.Record) bool { x.Add(r); return true }); e != nil {
		return e
	}
	e = scan(func(r ntfs.Record) bool {
		if !r.InUse || r.Directory || r.Base.Record != 0 {
			return true
		}
		name, ok := r.Name()
		dir := x.Dir(name.Parent)
		if !ok || dir == "" {
			return true
		}
		f := NTFSEntry{Path: letter + ntfs.Join(dir, name.Name), Name: name.Name, Modified: r.SI.Modified}
		for _, s := range r.Streams {
			if s.Name == "" && s.StartVCN == 0 {
				f.Size = s.Size
			}
		}
		return fn(f)
	})
	if errors.Is(e, errStop) {
		return nil
	}
	return e
}

var errStop = errors.New("stopped")
