package response

import (
	"os"
	"path/filepath"
	"testing"
)

// Windows' own files verify (most through a catalog), a plain file
// is unsigned, and a changed copy of a signed file is invalid.
func TestSignature(t *testing.T) {
	system := filepath.Join(os.Getenv("SystemRoot"), "System32")
	for _, name := range []string{"kernel32.dll", "svchost.exe", "notepad.exe"} {
		s := Signature(filepath.Join(system, name))
		if s.Status != "valid" || s.Signer == "" {
			t.Fatalf("%s: %+v", name, s)
		}
		t.Logf("%s: %+v", name, s)
	}
	plain := filepath.Join(t.TempDir(), "plain.exe")
	if e := os.WriteFile(plain, []byte("MZ not signed"), 0600); e != nil {
		t.Fatal(e)
	}
	if s := Signature(plain); s.Status != "unsigned" {
		t.Fatalf("plain file: %+v", s)
	}
	// A signed file with a byte changed in its body no longer verifies.
	b, e := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"))
	if e != nil {
		t.Skip(e)
	}
	if s := Signature(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe")); s.Status != "valid" {
		t.Skip("explorer.exe not signed here", s)
	}
	b[len(b)/2]++
	changed := filepath.Join(t.TempDir(), "explorer.exe")
	if e = os.WriteFile(changed, b, 0600); e != nil {
		t.Fatal(e)
	}
	if s := Signature(changed); s.Status == "valid" {
		t.Fatalf("changed file verified: %+v", s)
	}
}
