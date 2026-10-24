package patching

import (
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"testing"
	"time"
)

func TestUTCRecurrenceAndExplicitCompleteApproval(t *testing.T) {
	d := Definition{Name: "Security ring", Ring: "canary", Devices: []string{strings.Repeat("a", 32)}, Weekday: 1, Minute: 120, Duration: 120, Install: true, KB: []string{"12345"}, DeferHours: 24}
	if !Valid(d) {
		t.Fatal("definition")
	}
	now := time.Date(2026, 10, 19, 1, 59, 0, 0, time.UTC)
	if Next(d, now).Sub(now) != time.Minute {
		t.Fatal("weekly UTC")
	}
	now = now.Add(time.Minute)
	if Next(d, now).Sub(now) != 7*24*time.Hour {
		t.Fatal("catch-up")
	}
	p := protocol.UpdateProgress{Phase: "finished", Outcome: "ok", RebootKnown: true, Catalog: []protocol.WindowsUpdate{{UpdateIdentity: protocol.UpdateIdentity{ID: "x", Revision: 1}, KB: []string{"12345"}}}}
	if selected, e := Selection(d, p); e != nil || len(selected) != 1 {
		t.Fatal("approved", e)
	}
	p.Catalog[0].KB = append(p.Catalog[0].KB, "99999")
	if _, e := Selection(d, p); e == nil {
		t.Fatal("partially approved bundle reported compliant")
	}
	p.Truncated = true
	if _, e := Selection(d, p); e == nil {
		t.Fatal("truncated scan compliant")
	}
	p.Truncated = false
	p.Skipped = 1
	if _, e := Selection(d, p); e == nil {
		t.Fatal("scan with skipped updates compliant")
	}
	p.Skipped = 0
	p.RebootKnown = false
	if _, e := Selection(d, p); e == nil {
		t.Fatal("unknown restart state")
	}
	for _, edit := range []func(*Definition){func(d *Definition) { d.Duration = 29 }, func(d *Definition) { d.Duration = 241 }, func(d *Definition) { d.KB = []string{"KB12345"} }, func(d *Definition) { d.DeferHours = 0 }, func(d *Definition) { d.Devices = append(d.Devices, d.Devices[0]) }} {
		bad := d
		edit(&bad)
		if Valid(bad) {
			t.Fatal("invalid definition accepted")
		}
	}
}
