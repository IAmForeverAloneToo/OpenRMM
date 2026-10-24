package filetransfer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func read(t *testing.T, ev Evidence) []byte {
	t.Helper()
	b, e := io.ReadAll(ev.File)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func elevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (administrator) test run, like the SYSTEM agent")
	}
}

// System files with several hard links (System32 and WinSxS) can be
// collected, but a hard link to a file in a protected folder cannot.
func TestOpenEvidenceHardLinks(t *testing.T) {
	system := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	ev, outcome := OpenEvidence(system, EvidenceOptions{})
	if outcome != "" {
		t.Fatal("multi-link system file refused:", outcome)
	}
	ev.Close()

	protected := t.TempDir()
	secret := filepath.Join(protected, "secret.json")
	if err := os.WriteFile(secret, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "innocent.json")
	if err := os.Link(secret, link); err != nil {
		t.Skip("cannot create a hard link here:", err)
	}
	if _, outcome := OpenEvidence(link, EvidenceOptions{Deny: []string{protected}}); outcome != "denied" {
		t.Fatal("hard link into a protected folder collected:", outcome)
	}
	if ev, outcome := OpenEvidence(link, EvidenceOptions{}); outcome != "" {
		t.Fatal("hard link refused without a protected folder:", outcome)
	} else {
		ev.Close()
	}
}

// Protected names can be collected (OpenRMM's folders still
// cannot); the times, attributes and owner are recorded; alternate data
// streams are listed with their hashes and can be collected by path.
func TestOpenEvidenceProtectedNamesMetadataAndStreams(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".ssh")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "id_ed25519")
	if e := os.WriteFile(file, []byte("test key material"), 0600); e != nil {
		t.Fatal(e)
	}
	zone := "[ZoneTransfer]\r\nZoneId=3\r\n"
	if e := os.WriteFile(file+":Zone.Identifier", []byte(zone), 0600); e != nil {
		t.Skip("no alternate data streams here:", e)
	}
	// A large stream is listed with its size but not hashed.
	if e := os.WriteFile(file+":big", bytes.Repeat([]byte("x"), 2<<20), 0600); e != nil {
		t.Fatal(e)
	}
	ev, outcome := OpenEvidence(file, EvidenceOptions{})
	if outcome != "" {
		t.Fatal("protected name refused:", outcome)
	}
	b := read(t, ev)
	ev.Close()
	m := ev.Meta
	if string(b) != "test key material" || m.Method != "read" || m.Accessed == 0 || m.Changed == 0 || m.Attributes == 0 || !strings.HasPrefix(m.OwnerSID, "S-1-") || m.Owner == "" {
		t.Fatalf("content or metadata %q %+v", b, m)
	}
	streams := map[string]protocol.EvidenceStream{}
	for _, s := range m.Streams {
		streams[s.Name] = s
	}
	if len(m.Streams) != 2 || streams["Zone.Identifier"].Size != int64(len(zone)) || streams["Zone.Identifier"].SHA256 != Digest([]byte(zone)) || streams["big"].Size != 2<<20 || streams["big"].SHA256 != "" || !m.Valid() {
		t.Fatalf("streams %+v", m.Streams)
	}
	ev, outcome = OpenEvidence(file+":Zone.Identifier", EvidenceOptions{})
	if outcome != "" {
		t.Fatal("stream refused:", outcome)
	}
	b = read(t, ev)
	ev.Close()
	if string(b) != zone || ev.Info.Size() != int64(len(zone)) || !strings.HasSuffix(ev.Resolved, ":Zone.Identifier") || len(ev.Meta.Streams) != 0 {
		t.Fatalf("stream content %q size %d resolved %s", b, ev.Info.Size(), ev.Resolved)
	}
	if _, outcome = OpenEvidence(file, EvidenceOptions{Deny: []string{dir}}); outcome != "denied" {
		t.Fatal("OpenRMM folder collected:", outcome)
	}
	for _, bad := range []string{file + ":a:b", file + ":", file + "::$DATA"} {
		if _, outcome = OpenEvidence(bad, EvidenceOptions{}); outcome != "denied" {
			t.Fatal("bad stream path accepted:", bad, outcome)
		}
	}
}

// A file whose permissions deny every account is read with the backup
// privilege.
func TestOpenEvidenceBackupPrivilege(t *testing.T) {
	elevated(t)
	file := filepath.Join(t.TempDir(), "denied.txt")
	if e := os.WriteFile(file, []byte("restricted"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(file+":note", []byte("hidden"), 0600); e != nil {
		t.Fatal(e)
	}
	sd, e := windows.SecurityDescriptorFromString("D:P") // a protected, empty DACL
	if e != nil {
		t.Fatal(e)
	}
	empty, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, empty, nil); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil)
	})
	if _, e = os.ReadFile(file); e == nil {
		t.Skip("the deny-all permissions did not apply")
	}
	ev, outcome := OpenEvidence(file, EvidenceOptions{})
	if outcome != "" {
		t.Fatal("backup read refused:", outcome)
	}
	b := read(t, ev)
	ev.Close()
	if string(b) != "restricted" || ev.Meta.Method != "backup" || len(ev.Meta.Streams) != 1 || ev.Meta.Streams[0].SHA256 != Digest([]byte("hidden")) {
		t.Fatalf("backup read %q %+v", b, ev.Meta)
	}
	// Its stream, read by path, also needs the privilege and says so.
	ev, outcome = OpenEvidence(file+":note", EvidenceOptions{})
	if outcome != "" {
		t.Fatal("backup stream refused:", outcome)
	}
	b = read(t, ev)
	ev.Close()
	if string(b) != "hidden" || ev.Meta.Method != "backup" {
		t.Fatalf("backup stream %q %+v", b, ev.Meta)
	}
}

// A file another program holds exclusively is read from a temporary shadow
// copy, which is deleted afterwards.
func TestOpenEvidenceShadowCopy(t *testing.T) {
	elevated(t)
	if testing.Short() {
		t.Skip("creates a Volume Shadow Copy")
	}
	file := filepath.Join(t.TempDir(), "locked.db")
	content := bytes.Repeat([]byte("locked evidence "), 4096)
	if e := os.WriteFile(file, content, 0600); e != nil {
		t.Fatal(e)
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(file), windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	if _, e = os.ReadFile(file); e == nil {
		t.Fatal("the file is not locked")
	}
	ledger := filepath.Join(t.TempDir(), "shadows.json")
	ev, outcome := OpenEvidence(file, EvidenceOptions{Ledger: ledger})
	if outcome != "" {
		t.Fatal("locked file refused:", outcome)
	}
	b := read(t, ev)
	ev.Close()
	if !bytes.Equal(b, content) || ev.Meta.Method != "shadow_copy" || ev.Meta.Snapshot == "" || ev.Meta.SnapshotAt == 0 || !strings.EqualFold(ev.Resolved, file) || !ev.Meta.Valid() {
		t.Fatalf("shadow read %d bytes %+v %s", len(b), ev.Meta, ev.Resolved)
	}
	if left, _ := os.ReadFile(ledger); string(left) != "[]" {
		t.Fatal("shadow copy not deleted:", string(left))
	}
}

// Loaded hives are saved with RegSaveKeyEx into the temporary folder, which
// is emptied on Close.
func TestOpenHive(t *testing.T) {
	elevated(t)
	temp := t.TempDir()
	for _, name := range []string{"SYSTEM", "SAM", "DEFAULT"} {
		ev, outcome := OpenHive(name, EvidenceOptions{Temp: temp})
		if outcome != "" {
			t.Fatal(name, outcome)
		}
		header := make([]byte, 4)
		_, e := io.ReadFull(ev.File, header)
		ev.Close()
		if e != nil || string(header) != "regf" || ev.Meta.Method != "registry_save" || ev.Info.Size() < 4096 || !strings.HasPrefix(ev.Resolved, "HK") {
			t.Fatalf("%s: header %q %+v %s", name, header, ev.Meta, ev.Resolved)
		}
	}
	if left, _ := os.ReadDir(temp); len(left) != 0 {
		t.Fatal("saved hive left behind")
	}
	if _, outcome := OpenHive("NTUSER:no-such-profile-openrmm", EvidenceOptions{Temp: temp}); outcome != "not_found" {
		t.Fatal("unknown profile", outcome)
	}
	if _, outcome := OpenHive("HARDWARE", EvidenceOptions{Temp: temp}); outcome != "denied" {
		t.Fatal("unlisted hive", outcome)
	}
}

// An event log channel is exported to a private .evtx file, whole
// or filtered, and removed on Close.
func TestOpenEventLog(t *testing.T) {
	temp := t.TempDir()
	now := time.Now()
	filtered, e := eventlogs.ExportQuery(protocol.EventFilter{Channel: "Application", From: now.Add(-24 * time.Hour).Unix(), To: now.Unix(), Level: -1, EventID: -1, Limit: 1})
	if e != nil {
		t.Fatal(e)
	}
	for _, query := range []string{"", filtered} {
		ev, outcome := OpenEventLog("Application", query, EvidenceOptions{Temp: temp})
		if outcome != "" {
			t.Fatal(query, outcome)
		}
		header := make([]byte, 8)
		_, e := io.ReadFull(ev.File, header)
		name := ev.File.Name()
		ev.Close()
		if e != nil || string(header) != "ElfFile\x00" || ev.Meta.Method != "export" || ev.Resolved != "Application" {
			t.Fatalf("header %q %+v %s", header, ev.Meta, ev.Resolved)
		}
		if _, e := os.Stat(name); !os.IsNotExist(e) {
			t.Fatal("export kept after Close")
		}
	}
	if size, ok := logFileSize(windows.StringToUTF16Ptr("Application")); !ok || size == 0 {
		t.Fatal("log file size unavailable", size)
	}
	if _, outcome := OpenEventLog("OpenRMM-No-Such-Channel/Operational", "", EvidenceOptions{Temp: temp}); outcome == "" {
		t.Fatal("unknown channel exported")
	}
	for _, c := range []string{`C:\Windows\System32\winevt\Logs\System.evtx`, "../System"} {
		if _, outcome := OpenEventLog(c, "", EvidenceOptions{Temp: temp}); outcome != "denied" {
			t.Fatal("path accepted as a channel", c, outcome)
		}
	}
}

// A triage package is read from a shadow copy of the system drive
// and removed on Close; the shadow copy is gone afterwards.
func TestOpenTriage(t *testing.T) {
	elevated(t)
	temp := t.TempDir()
	ledger := filepath.Join(t.TempDir(), "shadows.json")
	ev, outcome := OpenTriage(context.Background(), "Test", []string{"prefetch", "startup", "powershell_history"}, 1<<30, EvidenceOptions{Temp: temp, Ledger: ledger, Deny: []string{os.Getenv("ProgramData") + `\Microsoft\Windows\Start Menu\Programs\StartUp`}})
	if outcome != "" {
		t.Fatal(outcome)
	}
	name := ev.File.Name()
	z, e := zip.NewReader(ev.File, ev.Info.Size())
	if e != nil {
		t.Fatal(e)
	}
	var m protocol.TriageManifest
	for _, f := range z.File {
		if f.Name == "manifest.json" {
			r, _ := f.Open()
			_ = json.NewDecoder(r).Decode(&m)
			r.Close()
		}
	}
	ev.Close()
	if m.Format != protocol.TriageFormat || m.Snapshot == "" || len(m.Files) == 0 || m.Files[0].Method != "snapshot" || ev.Meta.Method != "triage" {
		t.Fatalf("manifest %+v", m)
	}
	// A denied folder (here the all-users Startup folder) is left out.
	for _, f := range m.Files {
		if strings.Contains(strings.ToLower(f.Path), `programdata\microsoft\windows\start menu`) {
			t.Fatal("denied folder collected", f.Path)
		}
	}
	if _, e := os.Stat(name); !os.IsNotExist(e) {
		t.Fatal("package kept after Close")
	}
	if b, _ := os.ReadFile(ledger); strings.Contains(string(b), "{") {
		t.Fatal("shadow copy left", string(b))
	}
}

// A junction in a folder the triage walks is refused,
// so is a file reached through one, and a denied folder.
func TestTriageRefusesJunctions(t *testing.T) {
	dir := t.TempDir()
	volume := filepath.VolumeName(dir)
	real := filepath.Join(dir, "real")
	if e := os.MkdirAll(real, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(real, "f.txt"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	junction := filepath.Join(dir, "junction")
	if out, e := exec.Command("cmd", "/c", "mklink", "/J", junction, real).CombinedOutput(); e != nil {
		t.Skip("cannot create a junction", string(out))
	}
	rel := func(p string) string { return strings.TrimPrefix(p, volume+`\`) }
	src := triageSourceFor(volume, "", nil)
	if _, e := src.List(rel(junction)); !errors.Is(e, errRedirected) {
		t.Fatal("junction listed", e)
	}
	if _, e := src.List(rel(real)); e != nil {
		t.Fatal("real folder", e)
	}
	through, e := src.Open(src.Root + rel(junction) + `\f.txt`)
	if e != nil {
		t.Fatal(e)
	}
	defer through.Close()
	if src.Check(through, rel(junction)+`\f.txt`) {
		t.Fatal("file through a junction accepted")
	}
	direct, e := src.Open(src.Root + rel(real) + `\f.txt`)
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	if !src.Check(direct, rel(real)+`\f.txt`) {
		t.Fatal("file at its path refused")
	}
	if _, e := triageSourceFor(volume, "", []string{real}).List(rel(real)); !errors.Is(e, errRedirected) {
		t.Fatal("denied folder listed", e)
	}
}
