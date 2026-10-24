package filetransfer

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Artifact types map to files under the system folders and every
// user profile; the package keeps the original paths, hashes every file in
// its manifest and leaves out what does not fit.
func TestTriagePlanAndPackage(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("Windows/Prefetch/CMD.EXE-1234.pf", "prefetch")
	write("Windows/Prefetch/notes.txt", "not prefetch")
	write("Windows/System32/config/SYSTEM", "hive")
	write("Windows/System32/config/SYSTEM.LOG1", "log")
	write("Windows/System32/config/BBI", "other hive")
	write("Users/alice/NTUSER.DAT", "user hive")
	write("Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt", "whoami")
	write("Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", "chrome")
	write("Users/alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies", "cookies")
	write("Users/alice/AppData/Local/Google/Chrome/User Data/Default/Cache/deep/History", "too deep")
	write("Windows/System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag", "<Task/>")
	write("Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite-wal", "recent history")
	sep := string(os.PathSeparator)
	src := triageSource{Root: root + sep, Method: "snapshot", Open: os.Open, List: func(rel string) ([]os.DirEntry, error) { return os.ReadDir(root + sep + rel) }}
	if os.PathSeparator == '/' {
		t.Skip("triage paths are Windows paths")
	}
	dirs := triageDirs{SystemRoot: "Windows", ProgramData: "ProgramData", Users: []string{`Users\alice`, `Users\bob`}}
	items := []string{"prefetch", "registry", "user_registry", "powershell_history", "browsers", "tasks"}
	m := protocol.TriageManifest{Format: protocol.TriageFormat, Version: 1, Profile: "Test", Items: items, Files: []protocol.TriageFile{}, Skipped: []protocol.TriageSkip{}}
	ctx := context.Background()
	files := planTriage(ctx, src, items, dirs, &m)
	got := map[string]bool{}
	for _, f := range files {
		got[f.Rel] = true
	}
	for _, want := range []string{`Windows\Prefetch\CMD.EXE-1234.pf`, `Windows\System32\config\SYSTEM`, `Windows\System32\config\SYSTEM.LOG1`, `Users\alice\NTUSER.DAT`, `Users\alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, `Users\alice\AppData\Local\Google\Chrome\User Data\Default\History`, `Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`, `Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag`, `Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\places.sqlite-wal`} {
		if !got[want] {
			t.Fatal("missing", want, files)
		}
	}
	for _, not := range []string{`Windows\Prefetch\notes.txt`, `Windows\System32\config\BBI`, `Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cache\deep\History`} {
		if got[not] {
			t.Fatal("collected", not)
		}
	}
	if len(m.Skipped) != 0 {
		t.Fatal("missing folders reported", m.Skipped)
	}
	zipPath := filepath.Join(t.TempDir(), "t.zip")
	if e := writeTriage(ctx, src, files, zipPath, "C", 1<<30, time.Now().Add(time.Hour), &m); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(zipPath)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	names := map[string]*zip.File{}
	for _, f := range z.File {
		names[f.Name] = f
	}
	mf, ok := names["manifest.json"]
	if !ok || names["C/Windows/Prefetch/CMD.EXE-1234.pf"] == nil {
		t.Fatal("package entries", names)
	}
	r, _ := mf.Open()
	var back protocol.TriageManifest
	if e = json.NewDecoder(r).Decode(&back); e != nil || len(back.Files) != len(files) {
		t.Fatal("manifest", e, back)
	}
	for _, f := range back.Files {
		entry := names["C/"+strings.ReplaceAll(f.Path, `\`, "/")]
		rc, _ := entry.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 || int64(len(b)) != f.Size || f.Method != "snapshot" || f.Modified == 0 {
			t.Fatal("entry", f)
		}
	}
	// Files that do not fit are listed as left out.
	m = protocol.TriageManifest{Files: []protocol.TriageFile{}, Skipped: []protocol.TriageSkip{}}
	if e = writeTriage(ctx, src, files, filepath.Join(t.TempDir(), "small.zip"), "C", 64<<20+20, time.Now().Add(time.Hour), &m); e != nil {
		t.Fatal(e)
	}
	if len(m.Files)+len(m.Skipped) != len(files) || len(m.Skipped) == 0 || m.Skipped[0].Reason != "size_limit" {
		t.Fatal("size limit", m.Files, m.Skipped)
	}
	// A file that is not where its path says (Check) and every
	// file after the deadline are left out; the left-out list is capped.
	src.Check = func(_ *os.File, rel string) bool { return !strings.Contains(rel, "NTUSER") }
	m = protocol.TriageManifest{Files: []protocol.TriageFile{}, Skipped: []protocol.TriageSkip{}}
	if e = writeTriage(ctx, src, files, filepath.Join(t.TempDir(), "check.zip"), "C", 1<<30, time.Now().Add(time.Hour), &m); e != nil {
		t.Fatal(e)
	}
	if len(m.Skipped) != 1 || m.Skipped[0].Reason != "redirected" {
		t.Fatal("redirected file", m.Skipped)
	}
	m = protocol.TriageManifest{Files: []protocol.TriageFile{}, Skipped: []protocol.TriageSkip{}}
	if e = writeTriage(ctx, src, files, filepath.Join(t.TempDir(), "late.zip"), "C", 1<<30, time.Now().Add(-time.Second), &m); e != nil || len(m.Files) != 0 || m.Skipped[0].Reason != "time_limit" {
		t.Fatal("deadline", e, m.Skipped)
	}
	m = protocol.TriageManifest{}
	for range maxTriageSkipped + 5 {
		skip(&m, protocol.TriageSkip{Reason: "x"})
	}
	if len(m.Skipped) != maxTriageSkipped || m.SkippedMore != 5 {
		t.Fatal("skip cap", len(m.Skipped), m.SkippedMore)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if e = writeTriage(cancelled, src, files, filepath.Join(t.TempDir(), "stopped.zip"), "C", 1<<30, time.Now().Add(time.Hour), &m); e == nil {
		t.Fatal("cancelled build finished")
	}
}
