package filetransfer

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Evidence is a file opened for collection as case evidence. The
// same root, path, link and deny-list rules apply as for downloads, without
// the download size limit, and protected names are allowed; the
// caller streams and hashes the file and then calls Close.
type Evidence struct {
	File     *os.File
	Info     os.FileInfo
	Resolved string
	Meta     protocol.EvidenceMeta
	cleanup  []func()
}

// Close closes the file and removes what reading it needed: a temporary
// shadow copy or a saved hive.
func (e *Evidence) Close() {
	if e.File != nil {
		e.File.Close()
	}
	for i := len(e.cleanup) - 1; i >= 0; i-- {
		e.cleanup[i]()
	}
	e.cleanup = nil
}

// EvidenceOptions: Deny lists OpenRMM's own folders; Ledger is a private
// file recording shadow copies in use, so ones left by a crash are deleted
// later (CleanupShadows); Temp is a private folder for saved hives.
type EvidenceOptions struct {
	Deny   []string
	Ledger string
	Temp   string
}

// OpenEvidence opens an absolute path on a local fixed drive, such as
// C:\Users\x\file.txt, or one of its alternate data streams
// (C:\x\file.txt:Zone.Identifier). A file the agent may not read is read with
// the backup privilege; a file locked by another program is read from a
// temporary Volume Shadow Copy. On failure it returns an outcome:
// denied, not_found or failed.
func OpenEvidence(full string, o EvidenceOptions) (Evidence, string) {
	if runtime.GOOS != "windows" || len(full) > 4096 || !filepath.IsAbs(full) || strings.HasPrefix(full, `\\`) {
		return Evidence{}, "denied"
	}
	volume := filepath.VolumeName(full)
	file, stream, ok := protocol.SplitStream(full[len(volume):])
	if !ok {
		return Evidence{}, "denied"
	}
	full = volume + file
	a := &localAdapter{roots: fixedDrives, deny: o.Deny}
	roots, e := a.load()
	if e != nil {
		return Evidence{}, "denied"
	}
	var selected *LocalRoot
	for _, r := range roots {
		if strings.EqualFold(strings.TrimRight(r.Path, `\`), volume) && r.Read {
			r := r
			selected = &r
		}
	}
	relative := filepath.ToSlash(strings.TrimLeft(file, `\`))
	if selected == nil || !EvidencePath(relative) || relative == "." {
		return Evidence{}, "denied"
	}
	ev, source, result := a.openLive(selected.Path, full, relative)
	if result == "locked" {
		ev, source, result = a.openShadow(selected.Path, full, relative, o.Ledger)
	}
	if result != "" {
		return Evidence{}, result
	}
	if stream != "" {
		// The stream replaces the file's content; its metadata stays. It is
		// opened by path, so it must belong to the file already checked.
		f, privileged, e := openStream(source + ":" + stream)
		if e != nil {
			ev.Close()
			return Evidence{}, outcome(e)
		}
		i, e := f.Stat()
		if e != nil || !sameFile(f, ev.File) {
			f.Close()
			ev.Close()
			return Evidence{}, "denied"
		}
		if privileged && ev.Meta.Method == "read" {
			ev.Meta.Method = "backup"
		}
		ev.File.Close()
		ev.File, ev.Info, ev.Resolved = f, i, ev.Resolved+":"+stream
		return ev, ""
	}
	ev.Meta.Streams, ev.Meta.StreamsMore = listStreams(ev.File, source)
	return ev, ""
}

// openLive opens the file in place: normally, or with the backup privilege
// when access is denied. It returns the path its streams are read from, or
// the outcome "locked" when another program holds the file exclusively.
func (a *localAdapter) openLive(base, full, relative string) (Evidence, string, string) {
	root, e := os.OpenRoot(base)
	if e != nil {
		return Evidence{}, "", "denied"
	}
	defer root.Close()
	// Lstat rejects links in the walk; the root keeps later opens inside it.
	walked := true
	part := "."
	for _, v := range strings.Split(relative, "/") {
		part = path.Join(part, v)
		i, e := root.Lstat(part)
		if isLocked(e) {
			return Evidence{}, "", "locked" // checked again through the attribute handle
		}
		if errors.Is(e, os.ErrPermission) {
			walked = false // checked by the exact final path below
			break
		}
		if e != nil {
			return Evidence{}, "", outcome(e)
		}
		if i.Mode()&os.ModeSymlink != 0 || i.Mode()&os.ModeIrregular != 0 {
			return Evidence{}, "", "denied"
		}
	}
	method := "read"
	var f *os.File
	if walked {
		f, e = root.Open(relative)
	}
	if !walked || errors.Is(e, os.ErrPermission) {
		method = "backup"
		f, e = openBackup(full)
	}
	if isLocked(e) {
		return Evidence{}, "", "locked"
	}
	if e != nil {
		return Evidence{}, "", outcome(e)
	}
	i, physical, ok := a.evidenceCheck(f, base, full, method != "read")
	if !ok {
		f.Close()
		return Evidence{}, "", "denied"
	}
	meta := fileMeta(f)
	meta.Method = method
	return Evidence{File: f, Info: i, Resolved: physical, Meta: meta}, longPath(physical), ""
}

// openShadow checks and describes the live file through a handle that only
// reads attributes (allowed even while the file is locked), then reads its
// content from a temporary shadow copy of the volume, deleted on Close.
func (a *localAdapter) openShadow(base, full, relative, ledger string) (Evidence, string, string) {
	attr, e := openAttributes(full)
	if e != nil {
		return Evidence{}, "", outcome(e)
	}
	_, physical, ok := a.evidenceCheck(attr, base, full, true)
	meta := fileMeta(attr)
	index := fileIndex(attr)
	attr.Close()
	if !ok {
		return Evidence{}, "", "denied"
	}
	snapshot, err := createShadow(filepath.VolumeName(full), ledger)
	if err != nil {
		return Evidence{}, "", "failed"
	}
	ev := Evidence{Resolved: physical, cleanup: []func(){func() { _ = deleteShadow(snapshot.ID, ledger) }}}
	inner := snapshot.Device + `\` + filepath.FromSlash(relative)
	f, e := openSnapshotFile(inner)
	if e != nil {
		ev.Close()
		return Evidence{}, "", outcome(e)
	}
	ev.File = f
	// The copy is opened by path: it must be the checked file (same file
	// number) at the same place inside the snapshot, not something a junction
	// swapped in while the snapshot was made.
	if !inSnapshot(f, snapshot.Device, relative) || fileIndex(f) != index || index == 0 {
		ev.Close()
		return Evidence{}, "", "denied"
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() {
		ev.Close()
		return Evidence{}, "", "failed"
	}
	ev.Info = i
	meta.Method, meta.Snapshot, meta.SnapshotAt = "shadow_copy", snapshot.ID, snapshot.At.UnixNano()
	ev.Meta = meta
	return ev, inner, ""
}

// evidenceCheck applies the download rules to an opened file: a regular,
// non-reparse file under the drive, outside OpenRMM's folders through every
// hard link. With exact set (opened by full path rather than through the
// checked walk) its final path must be the requested one.
func (a *localAdapter) evidenceCheck(f *os.File, base, full string, exact bool) (os.FileInfo, string, bool) {
	i, e := f.Stat()
	physical, physicalErr := canonicalFile(f)
	b, baseErr := canonical(base)
	rel, relErr := filepath.Rel(b, physical)
	if e != nil || physicalErr != nil || baseErr != nil || relErr != nil || !EvidencePath(filepath.ToSlash(rel)) || !i.Mode().IsRegular() || a.blocked(physical) || !linksAllowed(f, physical, a.blocked) {
		return nil, "", false
	}
	if exact && !strings.EqualFold(physical, full) {
		return nil, "", false
	}
	return i, physical, true
}

func longPath(p string) string { return `\\?\` + p }

// OpenHive opens a registry hive for collection: a loaded hive is
// saved to a private temporary file with the backup privilege (removed on
// Close); a user hive that is not loaded is collected as its file, under the
// rules of OpenEvidence.
func OpenHive(name string, o EvidenceOptions) (Evidence, string) {
	if runtime.GOOS != "windows" || !protocol.ValidHive(name) || o.Temp == "" {
		return Evidence{}, "denied"
	}
	return openHive(name, o)
}

// OpenEventLog exports an event log channel to a private temporary .evtx file
// (removed on Close) for collection: the whole channel, or the
// events matching query (eventlogs.ExportQuery).
func OpenEventLog(channel, query string, o EvidenceOptions) (Evidence, string) {
	if runtime.GOOS != "windows" || !eventlogs.ValidChannel(channel) || !eventlogs.ValidExportQuery(query) || o.Temp == "" {
		return Evidence{}, "denied"
	}
	return openEventLog(channel, query, o)
}
