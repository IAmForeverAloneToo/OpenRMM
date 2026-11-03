package artefacts

import (
	"context"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/lnk/lnktest"
)

// Shortcuts and jump lists in a triage package become two tables.
func TestParseShortcuts(t *testing.T) {
	auto := lnktest.CFB(map[string][]byte{"1": lnktest.Shortcut(), "DestList": lnktest.DestList()})
	in := pkg(t, map[string][]byte{
		"C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/evil.exe.lnk":                                                    lnktest.Shortcut(),
		"C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms": auto,
		"C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/9b9cdc69c1c24e2b.customDestinations-ms":       append([]byte("junk"), lnktest.Shortcut()...),
	})
	req := request(t, in)
	m, err := Parse(context.Background(), req)
	if err != nil || len(m.Errors) != 0 || len(m.Tables) != 3 {
		t.Fatal(m, err)
	}
	links := string(readTable(t, req.Output, "lnk_files"))
	if !strings.Contains(links, `\Recent\evil.exe.lnk,,C:\Tools\evil.exe,--quiet --steal,C:\Tools,,2026-11-03 08:30:00.0000000,2026-11-03 09:00:00.0000000,2026-11-03 09:30:00.0000000,4096,Fixed,DEADBEEF,DATA,,WS-SOURCE,00:15:5d:01:02:03`) {
		t.Fatal(links)
	}
	jumps := string(readTable(t, req.Output, "jump_lists"))
	if !strings.Contains(jumps, `f01b4d95cf55d32a,automatic,1,C:\Tools\evil.exe,2026-11-03 09:30:00.0000000,true,12,WS-SOURCE,C:\Tools\evil.exe,--quiet --steal,`) ||
		!strings.Contains(jumps, `9b9cdc69c1c24e2b,custom,1,,,,,,C:\Tools\evil.exe,`) {
		t.Fatal(jumps)
	}
}
