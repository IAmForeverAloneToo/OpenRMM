package filetransfer

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Reads the system drive's raw volume (read-only): the MFT lists
// cmd.exe, and a package's timelines decode. It needs administrator or
// SYSTEM rights, so it runs only when asked: OPENRMM_NATIVE_NTFS=1.
func TestNativeNTFS(t *testing.T) {
	if os.Getenv("OPENRMM_NATIVE_NTFS") != "1" {
		t.Skip("set OPENRMM_NATIVE_NTFS=1 in an administrator shell to read this machine's system drive")
	}
	system := filepath.VolumeName(os.Getenv("SystemRoot"))
	raw, e := openRawVolume(`\\.\` + system)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.f.Close()
	cmd := strings.ToLower(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	found, files := false, 0
	if e := mftFiles(context.Background(), system, raw, func(f NTFSEntry) bool {
		files++
		found = found || strings.ToLower(f.Path) == cmd
		return true
	}); e != nil {
		t.Fatal(e)
	}
	t.Logf("%d files in use on %s", files, system)
	if !found || files < 10000 {
		t.Fatal("cmd.exe not found in the MFT")
	}
	// A package of the live volume (no shadow copy, to keep the test quick).
	out, e := os.Create(filepath.Join(t.TempDir(), "ntfs.zip"))
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	mv := protocol.NTFSVolume{Volume: system}
	if e := writeNTFSVolume(context.Background(), zw, system, raw, nil, &mv); e != nil {
		t.Fatal(e)
	}
	zw.Close()
	t.Logf("%+v", mv)
	if mv.MFTRows < 10000 || mv.USNRows == 0 || mv.Damaged > mv.MFTRows/1000 {
		t.Fatalf("counts %+v", mv)
	}
	i, _ := out.Stat()
	zr, _ := zip.NewReader(out, i.Size())
	f, e := zr.Open(system[:1] + "/usn.csv")
	if e != nil {
		t.Fatal(e)
	}
	r := csv.NewReader(f)
	n := 0
	for ; n < 1000; n++ {
		if _, e := r.Read(); e == io.EOF {
			break
		} else if e != nil {
			t.Fatal(e)
		}
	}
	if n < 2 {
		t.Fatal("empty journal timeline")
	}
}
