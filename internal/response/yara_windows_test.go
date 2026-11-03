package response

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A native YARA scan through the agent's action: rules with a random marker
// find a test file holding it and a harmless cmd.exe whose command line
// holds it (Windows keeps the command line in the process's memory as
// UTF-16), while reading the memory of every process the scan may read. It
// needs administrator or SYSTEM rights, so it runs only when asked:
// OPENRMM_NATIVE_YARA=1.
func TestNativeYara(t *testing.T) {
	if os.Getenv("OPENRMM_NATIVE_YARA") != "1" {
		t.Skip("set OPENRMM_NATIVE_YARA=1 in an administrator shell to scan this machine's processes")
	}
	raw := make([]byte, 12)
	rand.Read(raw)
	marker := "openrmm-yara-check-" + hex.EncodeToString(raw)
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "sample.txt"), []byte("before "+marker+" after"), 0600); e != nil {
		t.Fatal(e)
	}
	child := exec.Command("cmd.exe", "/c", "ping -n 900 127.0.0.1 >nul & rem "+marker)
	if e := child.Start(); e != nil {
		t.Fatal(e)
	}
	defer child.Process.Kill()
	time.Sleep(2 * time.Second)
	rules := "rule native_file { strings: $a = \"" + marker + "\" condition: $a }\n" +
		"rule native_memory { strings: $w = \"" + marker + "\" wide condition: $w }"
	// The child by its PID: its memory holds the marker (cmd.exe keeps its
	// command line as ANSI and UTF-16 text, so either rule may match).
	one := protocol.HuntSpec{Yara: &protocol.YaraSpec{Name: "native check", SHA256: strings.Repeat("a", 64), Rules: rules, PID: uint32(child.Process.Pid)}}
	r, e := Run(context.Background(), protocol.ResponseAction{Kind: "hunt", Hunt: &one}, &HashCache{})
	if e != nil || r.Hunt == nil || len(r.Hunt.Matches) == 0 || r.Hunt.Matches[0].PID != uint32(child.Process.Pid) {
		t.Fatalf("child by PID: %+v %v %v", r.Hunt, r.Notes, e)
	}
	t.Logf("child by PID: %s", r.Hunt.Matches[0].Detail)
	// Then everything: the folder and every process's memory.
	spec := protocol.HuntSpec{Yara: &protocol.YaraSpec{Name: "native check", SHA256: strings.Repeat("a", 64), Rules: rules, Path: dir, Memory: true}}
	start := time.Now()
	r, e = Run(context.Background(), protocol.ResponseAction{Kind: "hunt", Hunt: &spec}, &HashCache{})
	if e != nil || r.Hunt == nil {
		t.Fatal(e)
	}
	h := r.Hunt
	t.Logf("%s: outcome %s, scanned %+v, skipped %d, %d matches, notes %v", time.Since(start).Round(time.Second), h.Outcome, h.Scanned, h.Skipped, len(h.Matches), r.Notes)
	file, memory := false, false
	for _, m := range h.Matches {
		t.Logf("match: %s %s pid %d %s: %s", m.Area, m.Indicator.Value, m.PID, filepath.Base(m.Path), m.Detail)
		file = file || m.Area == "file" && m.Indicator.Value == "native_file"
		memory = memory || m.Area == "process" && m.PID == uint32(child.Process.Pid)
	}
	if !file || !memory {
		t.Fatalf("file found %v, child process found %v", file, memory)
	}
	if h.Scanned.YaraProcesses < 10 || r.Action.Hunt.Yara.Rules != "" {
		t.Fatalf("scanned %+v, rules echoed %v", h.Scanned, r.Action.Hunt.Yara.Rules != "")
	}
}
