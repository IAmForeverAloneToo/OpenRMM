package filetransfer

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// rawVolume reads a volume device. Devices accept only sector-aligned
// reads; 4 KiB is a multiple of every sector size, so other reads go
// through a block-aligned buffer.
type rawVolume struct{ f *os.File }

func openRawVolume(device string) (*rawVolume, error) {
	p, e := windows.UTF16PtrFromString(device)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		return nil, e
	}
	return &rawVolume{os.NewFile(uintptr(h), device)}, nil
}

func (r *rawVolume) ReadAt(p []byte, off int64) (int, error) {
	const block = 4096
	start := off &^ (block - 1)
	end := (off + int64(len(p)) + block - 1) &^ (block - 1)
	if start == off && end == off+int64(len(p)) {
		return r.f.ReadAt(p, off)
	}
	buf := make([]byte, end-start)
	n, err := r.f.ReadAt(buf, start)
	k := int(off - start)
	c := 0
	if n > k {
		c = copy(p, buf[k:n])
	}
	if c < len(p) {
		if err == nil {
			err = io.EOF
		}
		return c, err
	}
	return c, nil
}

// fixedNTFS reports whether a drive letter (C:) is a fixed NTFS volume.
func fixedNTFS(letter string) bool {
	root, e := windows.UTF16PtrFromString(letter + `\`)
	if e != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return false
	}
	fs := make([]uint16, 32)
	if windows.GetVolumeInformation(root, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))) != nil {
		return false
	}
	return windows.UTF16ToString(fs) == "NTFS"
}

func fixedNTFSVolumes() []string {
	mask, e := windows.GetLogicalDrives()
	if e != nil {
		return nil
	}
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<i) != 0 {
			if l := string(rune('A'+i)) + ":"; fixedNTFS(l) {
				out = append(out, l)
			}
		}
	}
	return out
}

// errTooLarge stops a package that would pass its size limit.
var errTooLarge = errors.New("the package reached its size limit")

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, errTooLarge
	}
	n, e := l.w.Write(p)
	l.left -= int64(n)
	return n, e
}

func openNTFS(ctx context.Context, volumes []string, all bool, max int64, o EvidenceOptions) (Evidence, string) {
	start := time.Now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(ntfsTime))
	defer cancel()
	switch {
	case all:
		volumes = fixedNTFSVolumes()
	case len(volumes) == 0:
		system := filepath.VolumeName(os.Getenv("SystemRoot"))
		if !driveLetter.MatchString(system) {
			return Evidence{}, "failed"
		}
		volumes = []string{system}
	}
	if e := os.MkdirAll(o.Temp, 0700); e != nil {
		return Evidence{}, "failed"
	}
	// The package must fit on the drive of the agent's state folder, keeping
	// 1 GiB free.
	var free uint64
	dir, e := windows.UTF16PtrFromString(o.Temp)
	if e != nil || windows.GetDiskFreeSpaceEx(dir, &free, nil, nil) != nil {
		return Evidence{}, "failed"
	}
	if free < 1<<30+128<<20 {
		return Evidence{}, "no_space"
	}
	max = min(max, int64(free-1<<30))
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return Evidence{}, "failed"
	}
	target := filepath.Join(o.Temp, "ntfs-"+hex.EncodeToString(random)+".zip")
	out, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return Evidence{}, "failed"
	}
	remove := func() { _ = os.Remove(target) }
	zw := zip.NewWriter(&limitWriter{w: out, left: max})
	m := protocol.NTFSManifest{Format: protocol.NTFSFormat, Version: 1, DeviceTime: start.UTC().Format(time.RFC3339Nano), Volumes: []protocol.NTFSVolume{}, Notes: []string{}}
	for _, letter := range volumes {
		mv := protocol.NTFSVolume{Volume: letter, Files: []protocol.NTFSFile{}}
		if !fixedNTFS(letter) {
			mv.Error = "not a fixed NTFS volume"
		} else if e := ntfsVolume(ctx, zw, letter, o, &mv); e != nil {
			if errors.Is(e, errTooLarge) {
				out.Close()
				remove()
				return Evidence{}, "too_large"
			}
			if ctx.Err() != nil {
				out.Close()
				remove()
				return Evidence{}, "failed"
			}
			mv.Error = e.Error()
		}
		m.Volumes = append(m.Volumes, mv)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	w, e := zw.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Deflate, Modified: time.Now()})
	if e == nil {
		_, e = w.Write(b)
	}
	if e == nil {
		e = zw.Close()
	}
	if c := out.Close(); e == nil {
		e = c
	}
	if e != nil {
		remove()
		if errors.Is(e, errTooLarge) {
			return Evidence{}, "too_large"
		}
		return Evidence{}, "failed"
	}
	f, e := os.Open(target)
	if e != nil {
		remove()
		return Evidence{}, "failed"
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		remove()
		return Evidence{}, "failed"
	}
	return Evidence{File: f, Info: i, Resolved: "ntfs:" + protocol.NTFSQuery(all, volumes), Meta: protocol.EvidenceMeta{Method: "ntfs"}, cleanup: []func(){remove}}, ""
}

// ntfsVolume reads one volume, from a shadow copy when one can be made
// (which keeps the raw copies and the timeline consistent), else live.
func ntfsVolume(ctx context.Context, zw *zip.Writer, letter string, o EvidenceOptions, mv *protocol.NTFSVolume) error {
	device := `\\.\` + letter
	if snap, e := createShadow(letter, o.Ledger); e == nil {
		device = snap.Device
		mv.Method, mv.Snapshot, mv.SnapshotAt = "snapshot", snap.ID, snap.At.UnixNano()
		defer func() { _ = deleteShadow(snap.ID, o.Ledger) }()
	} else {
		mv.Method = "live"
	}
	raw, e := openRawVolume(device)
	if e != nil {
		return errors.New("cannot open the volume")
	}
	defer raw.f.Close()
	return writeNTFSVolume(ctx, zw, letter, raw, o.Deny, mv)
}
