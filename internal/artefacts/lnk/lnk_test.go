package lnk

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/lnk/lnktest"
)

var when = lnktest.When

func TestShortcut(t *testing.T) {
	l, err := Parse(lnktest.Shortcut())
	if err != nil {
		t.Fatal(err)
	}
	if l.TargetPath != `C:\Tools\evil.exe` || l.Arguments != "--quiet --steal" || l.WorkingDir != `C:\Tools` || l.Size != 4096 || !l.Accessed.Equal(when) ||
		l.DriveType != "Fixed" || l.VolumeSerial != "DEADBEEF" || l.VolumeLabel != "DATA" || l.MachineID != "WS-SOURCE" || l.MAC != "00:15:5d:01:02:03" {
		t.Fatalf("%+v", l)
	}
}

func TestJumpLists(t *testing.T) {
	entries, err := Automatic(lnktest.CFB(map[string][]byte{"1": lnktest.Shortcut(), "DestList": lnktest.DestList()}))
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	e := entries[0]
	if e.Err != nil || e.Stream != "1" || e.TargetPath != `C:\Tools\evil.exe` || e.Path != `C:\Tools\evil.exe` || !e.LastAccess.Equal(when) || !e.Pinned || e.AccessCount != 12 || e.Hostname != "WS-SOURCE" {
		t.Fatalf("%+v", e)
	}
	custom := append(append([]byte("header junk"), lnktest.Shortcut()...), lnktest.Shortcut()...)
	if c := Custom(custom); len(c) != 2 || c[1].Arguments != "--quiet --steal" {
		t.Fatal(c)
	}
}

// Damaged input never panics.
func TestDamaged(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 10))
	link := lnktest.Shortcut()
	jl := lnktest.CFB(map[string][]byte{"1": link, "DestList": lnktest.DestList()})
	for range 3000 {
		for _, good := range [][]byte{link, jl} {
			b := append([]byte(nil), good...)
			for range 1 + r.IntN(20) {
				b[r.IntN(len(b))] = byte(r.Uint32())
			}
			if r.IntN(4) == 0 {
				b = b[:r.IntN(len(b))]
			}
			_, _ = Parse(b)
			_, _ = Automatic(b)
			_ = Custom(b)
		}
	}
}

// Real shortcuts and jump lists of this account: set OPENRMM_TEST_RECENT
// to a Recent folder (%APPDATA%\Microsoft\Windows\Recent). They name
// personal files, so none is kept with the source.
func TestRealRecent(t *testing.T) {
	dir := os.Getenv("OPENRMM_TEST_RECENT")
	if dir == "" {
		t.Skip("set OPENRMM_TEST_RECENT to a Recent folder")
	}
	var links, linkErr, auto, autoEntries, autoErr, custom, customEntries int
	files, _ := filepath.Glob(filepath.Join(dir, "*.lnk"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		links++
		if l, err := Parse(b); err != nil || l.TargetPath == "" && l.NetworkPath == "" {
			linkErr++
		}
	}
	files, _ = filepath.Glob(filepath.Join(dir, "AutomaticDestinations", "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		auto++
		entries, err := Automatic(b)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
		for _, e := range entries {
			autoEntries++
			if e.Err != nil && !strings.HasPrefix(e.Stream, "") {
				autoErr++
			}
			if e.Err != nil {
				autoErr++
			}
		}
	}
	files, _ = filepath.Glob(filepath.Join(dir, "CustomDestinations", "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		custom++
		customEntries += len(Custom(b))
	}
	t.Logf("shortcuts %d (%d without a target), automatic jump lists %d with %d entries (%d unreadable), custom %d with %d entries", links, linkErr, auto, autoEntries, autoErr, custom, customEntries)
	if links > 0 && linkErr > links/10 || autoEntries > 0 && autoErr > autoEntries/10 {
		t.Fatal("too many unreadable")
	}
}
