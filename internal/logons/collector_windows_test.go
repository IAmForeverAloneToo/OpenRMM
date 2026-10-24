package logons

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The Security log query is accepted by Windows and the local machine's
// logons parse; a second collection after the cursor repeats none of them.
// Reading the Security log needs an elevated test run; otherwise skipped.
func TestNativeLogons(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	m := &Module{Reader: NewReader()}
	start := time.Now()
	raw, e := m.Collect(ctx)
	if e != nil {
		t.Skip("Security log not readable here:", e)
	}
	var v protocol.Logons
	if json.Unmarshal(raw, &v) != nil || !Valid(v) {
		t.Fatal("invalid report")
	}
	t.Logf("%s: %d logons, more %v", time.Since(start), len(v.Logons), v.More)
	for i, l := range v.Logons {
		if i < 3 || i == len(v.Logons)-1 {
			t.Logf("%s %s %s\\%s from %q %s", time.Unix(l.Time, 0).UTC().Format(time.RFC3339), l.Type, l.Domain, l.User, l.SourceIP, l.AuthPackage)
		}
	}
	m.Settled(true)
	if m.cursor.Record == 0 && len(v.Logons) > 0 {
		t.Fatal("cursor not advanced")
	}
	raw, e = m.Collect(ctx)
	var again protocol.Logons
	if e != nil || json.Unmarshal(raw, &again) != nil {
		t.Fatal(e)
	}
	for _, l := range again.Logons {
		for _, old := range v.Logons {
			if l.RecordID == old.RecordID && l.Time == old.Time {
				t.Fatal("logon sent twice", l.RecordID)
			}
		}
	}
	t.Log("after cursor:", len(again.Logons))
}
