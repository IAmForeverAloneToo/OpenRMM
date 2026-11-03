package artefacts

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/evtx/evtxtest"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/lnk/lnktest"
)

// Events of every artefact are merged oldest first, also when they pass
// through several sorted runs on disk.
func TestTimeline(t *testing.T) {
	defer func(n int) { runSize = n }(runSize)
	runSize = 3
	older := pf("OLD.EXE", 1)
	binary.LittleEndian.PutUint64(older[120:], uint64(when.Add(-48*time.Hour).UnixNano()/100)+116444736000000000)
	in := pkg(t, map[string][]byte{
		"C/Windows/Prefetch/CMD.EXE-0BD30981.pf":                              pf("CMD.EXE", 7),
		"C/Windows/Prefetch/OLD.EXE-00000001.pf":                              older,
		"C/Windows/System32/winevt/Logs/Security.evtx":                        evtxtest.Log("alice", "bob"),
		"C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/evil.exe.lnk": lnktest.Shortcut(),
		"C/Windows/System32/config/SYSTEM":                                    systemHive(),
	})
	req := request(t, in)
	m, err := Parse(context.Background(), req)
	if err != nil || m.Tables[0].Name != "timeline" {
		t.Fatal(m, err)
	}
	lines := strings.Split(strings.TrimSpace(string(readTable(t, req.Output, "timeline"))), "\n")
	if lines[0] != "Time,Artefact,Event,Path,Details,SourceFile" || int64(len(lines)-1) != m.Tables[0].Rows {
		t.Fatal(lines[0], len(lines), m.Tables[0].Rows)
	}
	last := ""
	for _, l := range lines[1:] {
		at, _, _ := strings.Cut(l, ",")
		if at < last {
			t.Fatalf("out of order: %q after %q", at, last)
		}
		last = at
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"2026-11-01 09:30:00.0000000,Prefetch,Program ran,,Executable=OLD.EXE; RunCount=1",
		"2026-11-03 09:30:00.0000000,Event logs,Event 4672 (Security),Microsoft-Windows-Security-Auditing,Level=Information; UserID=S-1-5-21-1-2-3-1001; Data=TargetUserName=alice | LogonType=2",
		`2026-11-03 09:30:00.0000000,ShimCache (AppCompatCache),File modified (ShimCache entry),C:\Tools\evil.exe,Position=1`,
		`2026-11-03 09:30:00.0000000,BAM / DAM,Program ran (bam),\Device\HarddiskVolume3\Tools\evil.exe,Sid=S-1-5-21-1-2-3-1001`,
		`2026-11-03 08:30:00.0000000,Shortcuts (LNK),Target created (shortcut),C:\Tools\evil.exe,`,
		`2026-11-03 08:30:00.0000000,USB devices,USB device installed,Disk&Ven_Kingston&Prod_DT&Rev_1.00,Serial=AA00BB11&0; FriendlyName=Kingston DataTraveler USB Device`,
		`Registry key written,ControlSet001\Services\EvilSvc,Hive=SYSTEM`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("timeline lacks %q", want)
		}
	}
	if !strings.HasPrefix(lines[1], "2026-11-01") {
		t.Fatal("oldest first", lines[1])
	}
}
