package filetransfer

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func feed(b []byte) func(io.Writer) error {
	return func(w io.Writer) error { _, e := w.Write(b); return e }
}

// A dropped file is written create-only and verified; an existing
// file is replaced only with overwrite (its hash recorded); a wrong file,
// a missing folder, OpenRMM's folders and a junction are refused.
func TestDropFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("tool content")
	sum := Digest(content)
	target := filepath.Join(dir, "autoruns.exe")
	r := DropFile(target, false, nil, int64(len(content)), sum, feed(content))
	got, _ := os.ReadFile(target)
	if r.Outcome != "written" || !r.Verified || r.Replaced || !bytes.Equal(got, content) {
		t.Fatalf("create %+v", r)
	}
	if r = DropFile(target, false, nil, int64(len(content)), sum, feed(content)); r.Outcome != "exists" {
		t.Fatalf("create-only %+v", r)
	}
	next := []byte("newer tool")
	r = DropFile(target, true, nil, int64(len(next)), Digest(next), feed(next))
	got, _ = os.ReadFile(target)
	if r.Outcome != "written" || !r.Verified || !r.Replaced || r.ReplacedSHA256 != sum || !bytes.Equal(got, next) {
		t.Fatalf("overwrite %+v", r)
	}
	if r = DropFile(filepath.Join(dir, "x.bin"), false, nil, 3, Digest([]byte("abc")), feed([]byte("abd"))); r.Outcome != "hash_mismatch" {
		t.Fatalf("wrong content %+v", r)
	}
	if _, e := os.Stat(filepath.Join(dir, "x.bin")); !os.IsNotExist(e) {
		t.Fatal("a refused file was left")
	}
	if r = DropFile(filepath.Join(dir, "missing", "x.bin"), false, nil, 3, Digest([]byte("abc")), feed([]byte("abc"))); r.Outcome != "not_found" {
		t.Fatalf("missing folder %+v", r)
	}
	if r = DropFile(filepath.Join(dir, "y.bin"), false, []string{dir}, 3, Digest([]byte("abc")), feed([]byte("abc"))); r.Outcome != "denied" {
		t.Fatalf("OpenRMM folder %+v", r)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".part" {
			t.Fatal("temporary file left:", e.Name())
		}
	}
	// A junction on the way to the folder is refused.
	inside := filepath.Join(dir, "real")
	if e := os.Mkdir(inside, 0700); e != nil {
		t.Fatal(e)
	}
	junction := filepath.Join(dir, "link")
	if out, e := exec.Command(os.Getenv("ComSpec"), "/c", "mklink", "/J", junction, inside).CombinedOutput(); e != nil {
		t.Skip("cannot create a junction:", string(out))
	}
	if r = DropFile(filepath.Join(junction, "z.bin"), false, nil, 3, Digest([]byte("abc")), feed([]byte("abc"))); r.Outcome != "denied" {
		t.Fatalf("junction %+v", r)
	}
}
