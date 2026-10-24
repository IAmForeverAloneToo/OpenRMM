package isolation

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The plan keeps the server, DNS resolvers, DHCP, loopback and the
// allow list reachable, and refuses to isolate without a server address.
func TestPlan(t *testing.T) {
	spec := protocol.IsolationSpec{Allow: []string{"203.0.113.0/24", "2001:db8::7"}, CodeHash: HashCode("abcd-efgh-jkmn")}
	if !spec.Valid() {
		t.Fatal("spec")
	}
	l := Local{ServerIPs: []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("::ffff:192.0.2.10"), netip.MustParseAddr("2001:db8::10")}, ServerPort: 8444, DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	rules, e := Plan(spec, l)
	if e != nil {
		t.Fatal(e)
	}
	count := map[string]int{}
	for _, r := range rules {
		count[r.Purpose]++
		if r.Purpose == "server" && (r.Port != 8444 || r.Protocol != "tcp" || r.Direction != "out") {
			t.Fatal("server rule", r)
		}
	}
	// The mapped and plain IPv4 server address are one rule.
	if count["server"] != 2 || count["dns"] != 2 || count["dhcp"] != 3 || count["loopback"] != 2 || count["allow"] != 2 {
		t.Fatal(count)
	}
	if !(protocol.IsolationState{Isolated: true, Mode: "dry_run", Rules: rules}).Valid() {
		t.Fatal("state")
	}
	if _, e = Plan(spec, Local{ServerPort: 8444}); e != ErrNoServer {
		t.Fatal("no server address", e)
	}
	if _, e = Plan(spec, Local{ServerIPs: l.ServerIPs}); e != ErrNoServer {
		t.Fatal("no server port", e)
	}
	bad := spec
	bad.Allow = []string{"0.0.0.0/0"}
	if bad.Valid() {
		t.Fatal("allow everything accepted")
	}
	bad.Allow = []string{"10.0.0.1/8"}
	if bad.Valid() {
		t.Fatal("unmasked network accepted")
	}
	bad = spec
	bad.Allow = nil
	if bad.Valid() {
		t.Fatal("missing allow list accepted")
	}
	if !CodeMatches(" ABCD efgh-JKMN ", spec.CodeHash) || CodeMatches("abcd-efgh-jkmm", spec.CodeHash) {
		t.Fatal("release code")
	}
	if Enforce {
		t.Fatal("enforcement must stay off until verified on a VM")
	}
	if strings.Contains((&DryRun{}).Mode(), "enforced") {
		t.Fatal("dry run mode")
	}
}
