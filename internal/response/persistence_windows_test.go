package response

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The report finds a Run value added for the test (harmless:
// notepad), services and scheduled tasks, resolves their programs and checks
// signatures.
func TestPersistenceReport(t *testing.T) {
	k, _, e := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if e != nil {
		t.Fatal(e)
	}
	marker := "OpenRMMPersistenceTest"
	notepad := filepath.Join(os.Getenv("SystemRoot"), `System32\notepad.exe`)
	if e = k.SetStringValue(marker, `"`+notepad+`" /p nothing.txt`); e != nil {
		t.Fatal(e)
	}
	// A file on another computer is never opened (192.0.2.1 is a
	// documentation address), and per-user variables use the user's profile.
	remote, local := marker+"Remote", marker+"Local"
	if e = k.SetStringValue(remote, `\\192.0.2.1\share\tool.exe -x`); e != nil {
		t.Fatal(e)
	}
	if e = k.SetExpandStringValue(local, `%LOCALAPPDATA%\OpenRMMNoSuchFolder\app.exe`); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = k.DeleteValue(marker); _ = k.DeleteValue(remote); _ = k.DeleteValue(local); k.Close() }()
	start := time.Now()
	r, e := Run(context.Background(), protocol.ResponseAction{Kind: "persistence"}, &HashCache{})
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("%d entries in %s, notes %v", len(r.Persistence), time.Since(start), r.Notes)
	counts := map[string]int{}
	var found *protocol.PersistenceEntry
	for i, p := range r.Persistence {
		counts[p.Category]++
		if p.Name == marker {
			found = &r.Persistence[i]
		}
	}
	t.Log(counts)
	unresolved := 0
	for _, p := range r.Persistence {
		if (p.Image == "" || p.HashNote == "not_found") && p.Category != "wmi" {
			unresolved++
			if unresolved <= 25 {
				t.Logf("unresolved %s %s: %q -> %q (%s)", p.Category, p.Name, p.Command, p.Image, p.HashNote)
			}
		}
	}
	t.Log("unresolved", unresolved)
	if found == nil {
		t.Fatal("test Run value not reported")
	}
	for _, p := range r.Persistence {
		switch p.Name {
		case remote:
			if p.HashNote != "network_path" || p.Signature != nil || p.SHA256 != "" || !p.Arguments {
				t.Fatalf("network entry %+v", p)
			}
		case local:
			if !strings.Contains(strings.ToLower(p.Image), `\appdata\local\openrmmnosuchfolder`) || strings.Contains(strings.ToLower(p.Image), "systemprofile") || p.HashNote != "not_found" {
				t.Fatalf("per-user entry %+v", p)
			}
		}
	}
	if !strings.EqualFold(found.Image, notepad) || found.SHA256 == "" || found.Signature == nil || found.Signature.Status != "valid" || found.User == "" || !strings.HasPrefix(found.Location, `HKU\`) || !found.Arguments {
		t.Fatalf("test entry %+v %+v", found, found.Signature)
	}
	for _, c := range []string{"service", "driver", "task", "lsa", "boot_execute"} {
		// Scheduled tasks are readable only by administrators.
		if counts[c] == 0 && (c != "task" || elevated()) {
			t.Fatal("no entries of", c)
		}
	}
	for _, p := range r.Persistence {
		if p.Category == "boot_execute" && !strings.HasSuffix(strings.ToLower(p.Image), `autochk.exe`) {
			t.Fatalf("boot execute %+v", p)
		}
	}
}

// Network paths, Winlogon lists, arguments and per-user
// variables.
func TestPersistenceHelpers(t *testing.T) {
	for p, want := range map[string]bool{`\\server\share\x.exe`: true, `//server/share/x.exe`: true, `\\?\UNC\server\x.exe`: true, `\??\UNC\server\x.exe`: true, `\Device\Mup\server\x`: true, `\\server@80\x.exe`: true, `C:\Windows\notepad.exe`: false, `\\?\C:\Windows\notepad.exe`: false, `relative.exe`: false} {
		if networkPath(p) != want {
			t.Fatal("network path", p, want)
		}
	}
	if got := split(`C:\Windows\system32\userinit.exe,C:\evil.exe`, "comma"); len(got) != 2 || got[1] != `C:\evil.exe` {
		t.Fatal("winlogon split", got)
	}
	notepad := filepath.Join(os.Getenv("SystemRoot"), `System32\notepad.exe`)
	for cmd, want := range map[string]bool{`"` + notepad + `"`: false, `"` + notepad + `" x.txt`: true, notepad: false, notepad + ` /p`: true} {
		if hasArguments(cmd, notepad, "") != want {
			t.Fatal("arguments", cmd, want)
		}
	}
	if got := expandFor(`%APPDATA%\x.exe`, `C:\Users\alice`); got != `C:\Users\alice\AppData\Roaming\x.exe` {
		t.Fatal("user variables", got)
	}
	if got := resolveImage(`relative\dir\x.dll`, "appinit", true, ""); got != "" {
		t.Fatal("relative DLL resolved", got)
	}
	if s := Signature(`\\192.0.2.1\share\x.exe`); s.Status != "error" {
		t.Fatal("network signature", s)
	}
}
