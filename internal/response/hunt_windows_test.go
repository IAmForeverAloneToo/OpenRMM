package response

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A native hunt on the local machine finds this test process by its image
// hash and reads connections, the DNS cache and the persistence report. With
// OPENRMM_NATIVE_HUNT_FILES=1 it also searches and hashes the common file
// locations (minutes) and must find a harmless file the test creates in the
// user's Temp folder by name and SHA-256.
func TestNativeHunt(t *testing.T) {
	files := os.Getenv("OPENRMM_NATIVE_HUNT_FILES") == "1"
	marker := make([]byte, 16)
	rand.Read(marker)
	name := "openrmm-hunt-" + hex.EncodeToString(marker[:6]) + ".txt"
	path := filepath.Join(os.TempDir(), name)
	if e := os.WriteFile(path, marker, 0600); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	sum, _ := digest(marker)
	self, _ := os.Executable()
	cache := &HashCache{}
	selfHash, note := cache.Hash(context.Background(), self)
	if note != "" {
		t.Fatal(note)
	}
	spec := protocol.HuntSpec{Files: files, Indicators: []protocol.Indicator{
		{Type: "name", Value: name},
		{Type: "sha256", Value: sum},
		{Type: "sha256", Value: selfHash},
		{Type: "ip", Value: "127.0.0.0/8"},
		{Type: "domain", Value: "*.openrmm-hunt.invalid"},
	}}
	start := time.Now()
	r, e := Run(context.Background(), protocol.ResponseAction{Kind: "hunt", Hunt: &spec}, cache)
	if e != nil || r.Hunt == nil {
		t.Fatal(e)
	}
	h := r.Hunt
	t.Logf("%s: outcome %s, scanned %+v, skipped %d, %d matches, notes %v", time.Since(start), h.Outcome, h.Scanned, h.Skipped, len(h.Matches), r.Notes)
	found := map[string]bool{}
	for _, m := range h.Matches {
		if m.Area == "file" && strings.EqualFold(m.Path, path) {
			found["file "+m.Indicator.Type] = true
		}
		if m.Area == "process" && m.Indicator.Value == selfHash {
			found["process"] = true
		}
	}
	if files && h.Outcome == "ok" && (!found["file name"] || !found["file sha256"]) {
		t.Fatal("test file not found", found)
	}
	if !found["process"] {
		t.Fatal("test process not found by its image hash")
	}
	if h.Scanned.Processes == 0 || h.Scanned.Persistence == 0 || files && h.Scanned.Files == 0 || !files && h.Scanned.Files != 0 {
		t.Fatalf("scanned: %+v", h.Scanned)
	}
}
