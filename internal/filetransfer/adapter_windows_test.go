package filetransfer

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeContainedFilesAndCreateOnlyCommit(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "shared")
	protected := filepath.Join(root, "agent-state")
	if e := os.MkdirAll(protected, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(protected, "credentials.json"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	a := &localAdapter{roots: func() []LocalRoot {
		return []LocalRoot{{FileRoot: protocol.FileRoot{Name: "Support", Read: true, Write: true}, Path: root}}
	}, deny: []string{protected}}
	support, e := a.Support(context.Background())
	if e != nil || len(support.Roots) != 1 {
		t.Fatal("roots", e)
	}
	job := func(op, name string, data []byte) protocol.FileJob {
		q := protocol.FileJob{ID: strings.Repeat("a", 32), Operation: op, Root: support.Roots[0].ID, Path: name, ExpiresAt: time.Now().Add(time.Minute).Unix()}
		if op == "upload" {
			q.Data = data
			q.Size = int64(len(data))
			q.Hash = Digest(data)
		}
		return q
	}
	run := func(q protocol.FileJob, expected string) protocol.FileResult {
		t.Helper()
		r := a.Execute(context.Background(), q)
		if r.Outcome != expected || !ResultValid(q, r) {
			t.Fatalf("%s %s: %+v", q.Operation, q.Path, r)
		}
		return r
	}
	bytes := []byte("literal file 日本語\x00\xff")
	run(job("upload", "file.bin", bytes), "succeeded")
	run(job("upload", "file.bin", []byte("replace")), "exists")
	got := run(job("download", "file.bin", nil), "succeeded")
	if string(got.Data) != string(bytes) {
		t.Fatal("bytes changed")
	}
	run(job("list", ".", nil), "succeeded")
	os.WriteFile(filepath.Join(root, ".env"), []byte("never read"), 0600)
	listing := run(job("list", ".", nil), "succeeded")
	if len(listing.Entries) != 2 {
		t.Fatal("protected name listed or staging leaked", listing.Entries)
	}
	run(job("download", ".env", nil), "denied")
	// The agent's own folders are unreachable for every operation.
	run(job("list", "agent-state", nil), "denied")
	run(job("download", "agent-state/credentials.json", nil), "denied")
	run(job("upload", "agent-state/planted.json", []byte("x")), "denied")
	if _, e := os.Stat(filepath.Join(protected, "planted.json")); !os.IsNotExist(e) {
		t.Fatal("upload reached a protected folder")
	}
	// A native short-name alias must not bypass the exclusion.
	long, _ := windows.UTF16PtrFromString(protected)
	short := make([]uint16, 32768)
	if n, e := windows.GetShortPathName(long, &short[0], uint32(len(short))); e == nil && n > 0 && n < uint32(len(short)) {
		alias := filepath.Base(windows.UTF16ToString(short[:n]))
		if alias != filepath.Base(protected) {
			run(job("list", alias, nil), "denied")
		}
	}
	outside := filepath.Join(base, "outside.bin")
	os.WriteFile(outside, []byte("outside"), 0600)
	if e = os.Link(outside, filepath.Join(root, "hardlink")); e != nil {
		t.Fatal(e)
	}
	run(job("download", "hardlink", nil), "denied")
	// Junctions are available without developer-mode symlink privileges.
	// The ordinary symlink test runs where Windows permits it.
	if e = os.Symlink(outside, filepath.Join(root, "escape")); e == nil {
		run(job("download", "escape", nil), "denied")
	}
	outsideDir := filepath.Join(base, "outside-directory")
	if e = os.Mkdir(outsideDir, 0700); e != nil {
		t.Fatal(e)
	}
	if output, e := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(root, "junction"), outsideDir).CombinedOutput(); e != nil {
		t.Fatalf("junction fixture: %v %s", e, output)
	}
	run(job("list", "junction", nil), "denied")
}

func TestFixedDrivesAreOffered(t *testing.T) {
	roots := fixedDrives()
	if len(roots) == 0 {
		t.Fatal("no fixed drive found")
	}
	support, e := NewAdapter().Support(context.Background())
	if e != nil || len(support.Roots) != len(roots) {
		t.Fatal("drive roots", e, len(support.Roots), len(roots))
	}
	for _, r := range support.Roots {
		if !r.Read || !r.Write || len(r.Name) != 2 || r.Name[1] != ':' {
			t.Fatal("drive root shape", r)
		}
	}
}
