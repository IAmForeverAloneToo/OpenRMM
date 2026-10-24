package response

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func digest(b []byte) (string, string) {
	s, m := sha256.Sum256(b), md5.Sum(b)
	return hex.EncodeToString(s[:]), hex.EncodeToString(m[:])
}

// Indicators match processes, connections, DNS records,
// persistence entries and files; links are not followed; matches are capped.
func TestHuntMatching(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("openrmm hunt test payload")
	sum, md := digest(payload)
	sub := filepath.Join(dir, "Users", "alice", "AppData", "Local", "Temp")
	if e := os.MkdirAll(sub, 0700); e != nil {
		t.Fatal(e)
	}
	for name, body := range map[string][]byte{"dropper.EXE": payload, "notes.txt": []byte("x"), "renamed.bin": payload} {
		if e := os.WriteFile(filepath.Join(sub, name), body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "root.exe"), []byte("y"), 0600); e != nil {
		t.Fatal(e)
	}
	spec := protocol.HuntSpec{Files: true, Indicators: []protocol.Indicator{
		{Type: "name", Value: "dropper*.exe"},
		{Type: "md5", Value: md},
		{Type: "path", Value: `%LOCALAPPDATA%\Temp\notes.txt`},
		{Type: "cmd", Value: "-enc"},
		{Type: "ip", Value: "203.0.113.0/24"},
		{Type: "domain", Value: "*.example.org"},
		{Type: "sha256", Value: sum},
		{Type: "name", Value: "root.exe"},
	}}
	cache := &HashCache{}
	src := huntSources{
		processes: func(context.Context) ([]protocol.ProcessDetail, error) {
			return []protocol.ProcessDetail{{PID: 10, Name: "powershell.exe", CommandLine: "powershell -ENC abc"}, {PID: 11, Name: "dropper.exe", Image: filepath.Join(sub, "dropper.EXE")}}, nil
		},
		connections: func(context.Context) ([]protocol.Connection, error) {
			return []protocol.Connection{{Protocol: "tcp", RemoteAddress: "203.0.113.9"}, {Protocol: "tcp", RemoteAddress: "198.51.100.1"}}, nil
		},
		dns: func(context.Context) ([]dnsRecord, error) {
			return []dnsRecord{{"c2.example.org", "203.0.113.5"}, {"example.org.", ""}, {"notexample.org", ""}}, nil
		},
		persistence: func(context.Context) ([]protocol.PersistenceEntry, error) {
			return []protocol.PersistenceEntry{{Category: "run_key", Name: "Updater", Command: filepath.Join(sub, "renamed.bin"), Image: filepath.Join(sub, "renamed.bin")}}, nil
		},
		roots: func() []huntRoot { return []huntRoot{{dir: dir, shallow: true}, {dir: filepath.Join(dir, "Users")}} },
		hash: func(ctx context.Context, path string, want hashSet) (fileHashes, string) {
			return hashFile(ctx, cache, path, want)
		},
	}
	r := hunt(context.Background(), spec, src, &notes{})
	count := map[string]int{}
	for _, m := range r.Matches {
		count[m.Area+" "+m.Indicator.Type]++
	}
	want := map[string]int{
		"process cmd": 1, "process name": 1, "process md5": 1, "process sha256": 1,
		"connection ip": 1, "dns domain": 2, "dns ip": 1,
		"persistence md5": 1, "persistence sha256": 1,
		"file name": 2, "file md5": 2, "file sha256": 2, "file path": 1,
	}
	for k, v := range want {
		if count[k] != v {
			t.Fatalf("%s: %d want %d (all %v)", k, count[k], v, count)
		}
	}
	if len(count) != len(want) || r.Outcome != "ok" || r.More || r.Scanned.Files != 4 || r.Scanned.Hashed != 4 || r.Scanned.Processes != 2 || r.Scanned.DNS != 3 {
		t.Fatalf("result %+v %v", r.Scanned, count)
	}
	// Shallow roots: a file below the root is not searched there (only once
	// through the deeper root), and files are not searched without Files.
	spec.Files = false
	r = hunt(context.Background(), spec, src, &notes{})
	if r.Scanned.Files != 0 {
		t.Fatal("files searched without Files")
	}
	// The match cap.
	many := protocol.HuntSpec{Indicators: []protocol.Indicator{{Type: "cmd", Value: "abc"}}}
	src.processes = func(context.Context) ([]protocol.ProcessDetail, error) {
		list := make([]protocol.ProcessDetail, protocol.MaxHuntMatches+5)
		for i := range list {
			list[i] = protocol.ProcessDetail{PID: uint32(i + 5), CommandLine: "abc"}
		}
		return list, nil
	}
	if r = hunt(context.Background(), many, src, &notes{}); len(r.Matches) != protocol.MaxHuntMatches || !r.More {
		t.Fatal("cap", len(r.Matches), r.More)
	}
	// A file over the size limit is skipped, not hashed.
	big := filepath.Join(sub, "big.dat")
	f, _ := os.Create(big)
	f.Truncate(protocol.MaxHuntFileBytes + 1)
	f.Close()
	if _, note := hashFile(context.Background(), cache, big, hashSet{sha256: true}); note != "too_large" {
		t.Fatal("large file", note)
	}
}

func TestGlobPattern(t *testing.T) {
	for _, c := range []struct {
		pattern, s string
		ok         bool
	}{
		{"evil?.exe", "EVIL1.exe", true},
		{"evil?.exe", "evil12.exe", false},
		{`C:/Users/*/x.exe`, `c:\users\bob\appdata\x.exe`, true},
		{`%APPDATA%\x.exe`, `C:\Users\bob\AppData\Roaming\x.exe`, true},
		{"a.b", "aXb", false},
		{"(x)+", "(x)+", true},
	} {
		if globPattern(c.pattern).MatchString(c.s) != c.ok {
			t.Fatal(c)
		}
	}
}

// Exact and wildcard globs with the suffix prefilter, a blocked
// hash abandoned after the time limit, and the file limit reported as
// partial.
func TestHuntLimits(t *testing.T) {
	m := newMatcher(protocol.HuntSpec{Indicators: []protocol.Indicator{
		{Type: "name", Value: "Evil.EXE"},
		{Type: "name", Value: "*.hta"},
		{Type: "path", Value: `%APPDATA%\Microsoft\*\upd.exe`},
	}})
	if len(m.byName("evil.exe")) != 1 || len(m.byName("xevil.exe")) != 0 || len(m.byName("a.HTA")) != 1 || len(m.byName("a.htm")) != 0 {
		t.Fatal("names")
	}
	if len(m.byPath(`C:\Users\a\AppData\Roaming\Microsoft\x\UPD.exe`)) != 1 || len(m.byPath(`C:/Users/a/AppData/Roaming/Microsoft/x/upd.exe`)) != 1 || len(m.byPath(`C:\upd.exe`)) != 0 {
		t.Fatal("paths")
	}

	dir := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		if e := os.WriteFile(filepath.Join(dir, n), []byte(n), 0600); e != nil {
			t.Fatal(e)
		}
	}
	block := make(chan struct{})
	defer close(block)
	old := abandonAfter
	abandonAfter = 100 * time.Millisecond
	defer func() { abandonAfter = old }()
	src := huntSources{
		roots: func() []huntRoot { return []huntRoot{{dir: dir}} },
		hash: func(context.Context, string, hashSet) (fileHashes, string) {
			<-block // an open that cannot be cancelled
			return fileHashes{}, "unreadable"
		},
	}
	spec := protocol.HuntSpec{Files: true, Indicators: []protocol.Indicator{{Type: "sha256", Value: strings.Repeat("a", 64)}}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := hunt(ctx, spec, src, &notes{})
	if took := time.Since(start); took > 5*time.Second || r.Outcome != "partial" {
		t.Fatal("blocked walk", took, r.Outcome)
	}

	oldMax := maxHuntFiles
	maxHuntFiles = 2
	defer func() { maxHuntFiles = oldMax }()
	n := &notes{}
	r = hunt(context.Background(), protocol.HuntSpec{Files: true, Indicators: []protocol.Indicator{{Type: "name", Value: "a.txt"}}}, huntSources{roots: src.roots}, n)
	if r.Outcome != "partial" || r.Scanned.Files != 2 || len(n.list) != 1 {
		t.Fatal("file limit", r.Outcome, r.Scanned.Files, n.list)
	}
}
