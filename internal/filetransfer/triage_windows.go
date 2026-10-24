package filetransfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func createdTime(i os.FileInfo) int64 {
	if d, ok := i.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.CreationTime.Nanoseconds()
	}
	return 0
}

// userSID matches local, domain and Microsoft Entra accounts' profiles.
var userSID = regexp.MustCompile(`^S-1-(5-21|12-1)-[0-9-]+$`)

// userProfiles lists the user profile folders on the volume, relative to it.
func userProfiles(volume string) []string {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if e != nil {
		return nil
	}
	defer k.Close()
	names, e := k.ReadSubKeyNames(-1)
	if e != nil {
		return nil
	}
	out := []string{}
	for _, sid := range names {
		if !userSID.MatchString(sid) {
			continue
		}
		p, e := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if e != nil {
			continue
		}
		image, _, e := p.GetStringValue("ProfileImagePath")
		p.Close()
		if e != nil {
			continue
		}
		if image, e = registry.ExpandString(image); e != nil || !strings.EqualFold(filepath.VolumeName(image), volume) {
			continue
		}
		if rel := strings.Trim(image[len(volume):], `\`); rel != "" && !strings.Contains(rel, "..") {
			out = append(out, rel)
		}
	}
	return out
}

// triageDeny resolves the folders never collected (OpenRMM's own) to their
// final paths, lowercased.
func triageDeny(deny []string) []string {
	out := []string{}
	for _, d := range deny {
		if d == "" {
			continue
		}
		c, e := canonical(d)
		if e != nil {
			c = d
		}
		out = append(out, strings.ToLower(strings.TrimRight(c, `\`)))
	}
	return out
}

func notReparse(f *os.File) bool {
	var i windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i) == nil && i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

// triageSourceFor reads the volume through a shadow copy device, or live
// with the backup privilege when device is "". Every folder and file must be
// where its path says: a junction or link above it (which would lead
// elsewhere, even out of the shadow copy) and the deny folders (OpenRMM's
// own) are refused, also through hard links.
func triageSourceFor(volume, device string, denyList []string) triageSource {
	deny := triageDeny(denyList)
	denied := func(p string) bool {
		l := strings.ToLower(p)
		for _, d := range deny {
			if l == d || strings.HasPrefix(l, d+`\`) {
				return true
			}
		}
		return false
	}
	live := func(rel string) string { return volume + `\` + rel }
	src := triageSource{Root: device + `\`, Method: "snapshot", Open: openSnapshotFile}
	at := func(f *os.File, rel string) bool { return inSnapshot(f, device, rel) }
	if device == "" {
		src.Root, src.Method = longPath(volume+`\`), "live"
		src.Open = func(p string) (*os.File, error) { return privileged(p, windows.GENERIC_READ) }
		at = func(f *os.File, rel string) bool {
			p, e := canonicalFile(f)
			return e == nil && strings.EqualFold(p, live(rel))
		}
	}
	src.List = func(rel string) ([]fs.DirEntry, error) {
		d, e := privileged(src.Root+rel, windows.FILE_READ_ATTRIBUTES)
		if e != nil {
			return nil, e
		}
		ok := notReparse(d) && at(d, rel) && !denied(live(rel))
		d.Close()
		if !ok {
			return nil, errRedirected
		}
		return os.ReadDir(src.Root + rel)
	}
	src.Check = func(f *os.File, rel string) bool { return at(f, rel) && linksAllowed(f, live(rel), denied) }
	return src
}

func openTriage(ctx context.Context, profile string, items []string, max int64, o EvidenceOptions) (Evidence, string) {
	start := time.Now()
	system := os.Getenv("SystemRoot")
	volume := filepath.VolumeName(system)
	if !driveLetter.MatchString(volume) {
		return Evidence{}, "failed"
	}
	programData := os.Getenv("ProgramData")
	if !strings.EqualFold(filepath.VolumeName(programData), volume) {
		programData = volume + `\ProgramData`
	}
	dirs := triageDirs{SystemRoot: strings.Trim(system[len(volume):], `\`), ProgramData: strings.Trim(programData[len(volume):], `\`), Users: userProfiles(volume)}
	if e := os.MkdirAll(o.Temp, 0700); e != nil {
		return Evidence{}, "failed"
	}
	m := protocol.TriageManifest{Format: protocol.TriageFormat, Version: 1, Profile: profile, Items: items, DeviceTime: start.UTC().Format(time.RFC3339Nano), Volume: volume, Files: []protocol.TriageFile{}, Skipped: []protocol.TriageSkip{}}
	// One shadow copy gives a consistent, lock-free view of the whole drive.
	var src triageSource
	snapshot, e := createShadow(volume, o.Ledger)
	if e == nil {
		src = triageSourceFor(volume, snapshot.Device, o.Deny)
		m.Snapshot, m.SnapshotAt = snapshot.ID, snapshot.At.UnixNano()
		defer func() { _ = deleteShadow(snapshot.ID, o.Ledger) }()
	} else {
		src = triageSourceFor(volume, "", o.Deny)
		m.Notes = append(m.Notes, "No shadow copy could be made: files were read live, and files locked by other programs were left out.")
	}
	files := planTriage(ctx, src, items, dirs, &m)
	if ctx.Err() != nil {
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
	if room := int64(free - 1<<30); room < max {
		max = room
		m.Notes = append(m.Notes, "The package was limited by free disk space on the device.")
	}
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return Evidence{}, "failed"
	}
	target := filepath.Join(o.Temp, "triage-"+hex.EncodeToString(random)+".zip")
	if e = writeTriage(ctx, src, files, target, volume[:1], max, start.Add(triageTime), &m); e != nil {
		_ = os.Remove(target)
		return Evidence{}, "failed"
	}
	f, e := os.Open(target)
	if e != nil {
		_ = os.Remove(target)
		return Evidence{}, "failed"
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		_ = os.Remove(target)
		return Evidence{}, "failed"
	}
	return Evidence{File: f, Info: i, Resolved: "triage:" + profile, Meta: protocol.EvidenceMeta{Method: "triage"}, cleanup: []func(){func() { _ = os.Remove(target) }}}, ""
}
