package response

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/yara"
)

// Invented indicators: no real malware strings in tests.
const huntRules = `
rule example_dumper : hacktool {
  strings: $a = "dumpcreds::allsessions" ascii wide
  condition: $a
}
rule example_beacon {
  strings: $b = { 4D 5A ?? 00 [0-4] 45 58 41 4D }
  condition: $b
}`

// YARA rules run over the files searched and process memory, skipping
// LSASS, security products and the agent itself; matches name the rule.
func TestYaraHunt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tool.exe"), []byte("....dumpcreds::allsessions...."), 0600)
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here"), 0600)
	os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	os.WriteFile(filepath.Join(dir, "sub", "loader.bin"), []byte("MZ\x90\x00\x01EXAM"), 0600)
	read := map[uint32]bool{}
	src := huntSources{
		roots: func() []huntRoot { return []huntRoot{{dir: dir}} },
		processes: func(context.Context) ([]protocol.ProcessDetail, error) {
			return []protocol.ProcessDetail{
				{PID: 100, Name: "notepad.exe", Image: `C:\Windows\notepad.exe`},
				{PID: 200, Name: "LSASS.EXE", Image: `C:\Windows\System32\lsass.exe`},
				{PID: 300, Name: "MsMpEng.exe"},
				{PID: uint32(os.Getpid()), Name: "openrmm-agent.exe"},
				{PID: 400, Name: "victim.exe", Image: `C:\Users\a\victim.exe`},
			}, nil
		},
		memory: func(_ context.Context, pid uint32, fn func([]yara.Block) error) error {
			read[pid] = true
			if pid == 400 {
				// The string is in the second of two batches.
				if e := fn([]yara.Block{{Base: 0x10000, Data: []byte("plain")}}); e != nil {
					return e
				}
				return fn([]yara.Block{{Base: 0x7FF00000, Data: []byte("d\x00u\x00m\x00p\x00c\x00r\x00e\x00d\x00s\x00:\x00:\x00a\x00l\x00l\x00s\x00e\x00s\x00s\x00i\x00o\x00n\x00s\x00")}})
			}
			return fn([]yara.Block{{Data: []byte("nothing")}})
		},
	}
	spec := protocol.HuntSpec{Files: true, Yara: &protocol.YaraSpec{Name: "test", SHA256: strings.Repeat("a", 64), Rules: huntRules, Memory: true}}
	if !spec.Valid() {
		t.Fatal("spec")
	}
	n := &notes{}
	r := hunt(context.Background(), spec, src, n)
	got := map[string]protocol.HuntMatch{}
	for _, m := range r.Matches {
		// Process paths are Windows paths, also when the test runs elsewhere.
		got[m.Area+" "+m.Indicator.Value+" "+m.Path[strings.LastIndexAny(m.Path, `\/`)+1:]] = m
	}
	if len(r.Matches) != 3 || r.Scanned.YaraFiles != 3 || r.Scanned.YaraProcesses != 2 {
		t.Fatalf("%+v %v", r, n.list)
	}
	f, ok := got["file example_dumper tool.exe"]
	if !ok || f.Indicator.Type != "yara" || !strings.Contains(f.Detail, "rule example_dumper [hacktool]: $a at 0x4") {
		t.Fatalf("%+v", got)
	}
	if _, ok := got["file example_beacon loader.bin"]; !ok {
		t.Fatalf("%+v", got)
	}
	p, ok := got["process example_dumper victim.exe"]
	if !ok || p.PID != 400 || !strings.Contains(p.Detail, "memory: rule example_dumper") || !strings.Contains(p.Detail, "0x7ff00000") {
		t.Fatalf("%+v", got)
	}
	if read[200] || read[300] || read[uint32(os.Getpid())] || !read[100] {
		t.Fatal("skipped processes were read", read)
	}
	if len(n.list) != 1 || !strings.Contains(n.list[0], "memory of 3 processes was not scanned") {
		t.Fatal(n.list)
	}

	// A narrowed scan: one folder, one process, no common locations.
	read = map[uint32]bool{}
	spec.Files, spec.Yara.Memory, spec.Yara.Path, spec.Yara.PID = false, false, filepath.Join(dir, "sub"), 100
	r = hunt(context.Background(), spec, src, &notes{})
	if len(r.Matches) != 1 || r.Matches[0].Indicator.Value != "example_beacon" || r.Scanned.YaraFiles != 1 || len(read) != 1 || !read[100] {
		t.Fatalf("%+v %v", r, read)
	}

	// Rules that do not compile are reported, and the rest of the hunt runs.
	n = &notes{}
	spec = protocol.HuntSpec{Files: true, Indicators: []protocol.Indicator{{Type: "name", Value: "clean.txt"}}, Yara: &protocol.YaraSpec{Name: "x", SHA256: strings.Repeat("a", 64), Rules: "rule broken {"}}
	r = hunt(context.Background(), spec, huntSources{roots: src.roots}, n)
	if len(r.Matches) != 1 || len(n.list) != 1 || !strings.Contains(n.list[0], "could not be compiled") {
		t.Fatal(r.Matches, n.list)
	}
}
