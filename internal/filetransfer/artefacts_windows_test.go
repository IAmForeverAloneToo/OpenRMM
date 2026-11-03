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
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts"
)

// Builds a triage package of this machine as the agent does and parses it
// as the server does, reporting what each table holds. It needs
// administrator or SYSTEM rights (a shadow copy and other users' files),
// so it runs only when asked: OPENRMM_NATIVE_ARTEFACTS=1.
func TestNativeArtefacts(t *testing.T) {
	if os.Getenv("OPENRMM_NATIVE_ARTEFACTS") != "1" {
		t.Skip("set OPENRMM_NATIVE_ARTEFACTS=1 in an administrator shell to parse this machine's artefacts")
	}
	temp := t.TempDir()
	start := time.Now()
	ev, outcome := OpenTriage(context.Background(), "Native", []string{"prefetch", "amcache", "registry", "user_registry", "event_logs", "recent", "startup"}, 8<<30, EvidenceOptions{Temp: temp, Ledger: filepath.Join(temp, "shadows.json")})
	if outcome != "" {
		t.Fatal(outcome)
	}
	defer ev.Close()
	t.Logf("package %d MB in %s", ev.Info.Size()>>20, time.Since(start).Round(time.Second))
	start = time.Now()
	out := t.TempDir()
	req := artefacts.Request{Input: ev.File.Name(), Source: "triage", Output: filepath.Join(out, "parsed.zip"), Temp: out, MaxOutput: 4 << 30}
	m, err := artefacts.Parse(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(req.Output)
	t.Logf("parsed into %d MB in %s", info.Size()>>20, time.Since(start).Round(time.Second))
	rows := map[string]int64{}
	for _, tb := range m.Tables {
		rows[tb.Name] = tb.Rows
		t.Logf("%-18s %9d rows from %d files", tb.Name, tb.Rows, tb.Sources)
	}
	for i, e := range m.Errors {
		if i < 25 {
			t.Logf("not parsed: %s (%s): %s", e.Path, e.Table, e.Error)
		}
	}
	t.Logf("%d files not parsed", len(m.Errors)+m.ErrorsMore)
	// The hives: whether they were dirty and how many log entries applied.
	if zr, err := zip.OpenReader(req.Output); err == nil {
		if f, err := zr.Open("tables/registry_hives.csv"); err == nil {
			rows, _ := csv.NewReader(f).ReadAll()
			for _, r := range rows {
				t.Logf("hive %s dirty=%s replayed=%s keys=%s", r[1], r[4], r[5], r[6])
			}
		}
		zr.Close()
	}
	// The start of files that did not parse.
	if zr, err := zip.NewReader(ev.File, ev.Info.Size()); err == nil {
		for _, e := range m.Errors {
			for _, z := range zr.File {
				if p, ok := strings.CutPrefix(e.Path, "C:\\"); ok && z.Name == "C/"+strings.ReplaceAll(p, "\\", "/") {
					r, _ := z.Open()
					head := make([]byte, 16)
					n, _ := io.ReadFull(r, head)
					r.Close()
					t.Logf("%s: %d bytes, starts % x", z.Name, z.UncompressedSize64, head[:n])
				}
			}
		}
	}
	for _, want := range []string{"timeline", "prefetch", "registry_hives", "registry_keys", "services", "event_logs", "amcache_files"} {
		if rows[want] == 0 {
			t.Errorf("no %s rows", want)
		}
	}
}
