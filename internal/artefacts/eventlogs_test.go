package artefacts

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/evtx/evtxtest"
)

// Event logs in a triage package and single exported logs become rows of
// one table, which the viewer filters by column.
func TestParseEventLogs(t *testing.T) {
	in := pkg(t, map[string][]byte{"C/Windows/System32/winevt/Logs/Security.evtx": evtxtest.Log("alice", "bob")})
	req := request(t, in)
	m, err := Parse(context.Background(), req)
	if err != nil || len(m.Errors) != 0 || len(m.Tables) != 1 || m.Tables[0].Rows != 2 {
		t.Fatal(m, err)
	}
	table := readTable(t, req.Output, "event_logs")
	if !strings.Contains(string(table), `2026-11-03 09:30:00.0000000,Security,4672,Information,Microsoft-Windows-Security-Auditing,2,PC-1,S-1-5-21-1-2-3-1001,,,,,,TargetUserName=bob | LogonType=10,C:\Windows\System32\winevt\Logs\Security.evtx`) {
		t.Fatal(string(table))
	}
	p, err := Query(bytes.NewReader(table), eventsTable.Times, Filter{Column: "EventRecordID", Equals: "1"}, 0, 10)
	if err != nil || len(p.Rows) != 1 || !strings.Contains(p.Rows[0][13], "alice") {
		t.Fatal(p, err)
	}
	if _, err := Query(bytes.NewReader(table), nil, Filter{Column: "Nope", Equals: "1"}, 0, 10); err != ErrNoColumn {
		t.Fatal(err)
	}
	// An event log collection (one exported channel).
	single := request(t, "")
	single.Source, single.Name = "evtx", "Security"
	single.Input = single.Temp + "/log.evtx"
	if err := writeFile(single.Input, evtxtest.Log("carol")); err != nil {
		t.Fatal(err)
	}
	if m, err := Parse(context.Background(), single); err != nil || m.Tables[0].Rows != 1 {
		t.Fatal(m, err)
	}
}
