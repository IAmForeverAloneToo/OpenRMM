package agentservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogRetentionAndRestart(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.limit = 20
	for i := 0; i < 9; i++ {
		if _, err := l.Write([]byte(strings.Repeat(string(rune('a'+i)), 10))); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for i, want := range map[string]string{"agent.log": strings.Repeat("i", 10), "agent.log.1": strings.Repeat("g", 10) + strings.Repeat("h", 10), "agent.log.2": strings.Repeat("e", 10) + strings.Repeat("f", 10)} {
		got, err := os.ReadFile(filepath.Join(dir, i))
		if err != nil || string(got) != want {
			t.Fatalf("bad retained log %s: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != LogFiles {
		t.Fatal("retention exceeded")
	}
	l, err = OpenLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.size != 10 {
		t.Fatal("restart lost current file size")
	}
	if _, err := l.Write(make([]byte, LogLimit+1)); err == nil {
		t.Fatal("unbounded record accepted")
	}
}
