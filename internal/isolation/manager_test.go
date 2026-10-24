package isolation

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type recorder struct {
	DryRun
	applied, removed int
	fail             bool
}

func (r *recorder) Apply(rules []protocol.IsolationRule) error {
	if r.fail {
		return errors.New("refused")
	}
	r.applied++
	return r.DryRun.Apply(rules)
}
func (r *recorder) Remove() error { r.removed++; return r.DryRun.Remove() }

// Isolation state lives in the isolation folder shared with the
// break-glass command; release by the server, a timed release and the local
// release code all lift it; a failed plan changes nothing; the rules are
// worked out again when the network changes.
func TestManager(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	enf := &recorder{}
	m := &Manager{Dir: dir, Enforcer: enf, Now: func() time.Time { return now }}
	l := Local{ServerIPs: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, ServerPort: 8444}
	spec := protocol.IsolationSpec{Allow: []string{}, CodeHash: HashCode("AAAA-BBBB-CCCC"), ReleaseAfter: 3600}
	if s := m.State(); s.Isolated || s.Error != "" {
		t.Fatal("isolated at start", s)
	}
	if _, e := m.Isolate("0123456789abcdef0123456789abcdef", spec, Local{ServerPort: 8444}); !errors.Is(e, ErrNoServer) || m.State().Isolated || enf.applied != 0 {
		t.Fatal("isolated without a server address", e)
	}
	if _, e := m.Isolate("0123456789abcdef0123456789abcdef", spec, Local{ServerIPs: l.ServerIPs, ServerPort: 8444, ServerByName: true}); !errors.Is(e, ErrNoDNS) {
		t.Fatal("isolated without DNS for a named server", e)
	}
	s, e := m.Isolate("0123456789abcdef0123456789abcdef", spec, l)
	if e != nil || !s.Isolated || s.Mode != "dry_run" || s.ReleaseAt != "2026-10-23T13:00:00Z" || len(s.Rules) == 0 || s.Rules[0].Purpose != "server" {
		t.Fatalf("isolate %+v %v", s, e)
	}
	// The network changed: a new server address is added to the rules.
	l2 := l
	l2.ServerIPs = append(l2.ServerIPs, netip.MustParseAddr("192.0.2.11"))
	before := enf.applied
	if e = m.Refresh(l2); e != nil || enf.applied != before+1 || len(m.State().Rules) != len(s.Rules)+1 {
		t.Fatal("refresh", e)
	}
	if e = m.Refresh(l2); e != nil || enf.applied != before+1 {
		t.Fatal("refresh without a change applied again", e)
	}
	// The break-glass command is another process: a new manager on the folder.
	other := &Manager{Dir: dir, Enforcer: &recorder{}, Now: m.Now}
	if e = other.BreakGlass("AAAA-BBBB-CCCD"); !errors.Is(e, ErrCode) || !m.State().Isolated {
		t.Fatal("wrong code released", e)
	}
	// A lock left by a process that died is taken over.
	stale := filepath.Join(dir, lockFile)
	if e = os.WriteFile(stale, nil, 0600); e != nil {
		t.Fatal(e)
	}
	old := time.Now().Add(-2 * time.Minute)
	os.Chtimes(stale, old, old)
	if e = other.BreakGlass("aaaa bbbb cccc"); e != nil {
		t.Fatal(e)
	}
	if s = m.State(); s.Isolated || s.Released != "break_glass" || s.ReleasedAt == "" {
		t.Fatalf("after break glass %+v", s)
	}
	if e = other.BreakGlass("AAAA-BBBB-CCCC"); !errors.Is(e, ErrNotIsolated) {
		t.Fatal("released twice", e)
	}
	// A timed release happens when the state is next read.
	if _, e = m.Isolate("0123456789abcdef0123456789abcdee", spec, l); e != nil {
		t.Fatal(e)
	}
	now = now.Add(2 * time.Hour)
	if s = m.State(); s.Isolated || s.Released != "timed" {
		t.Fatalf("timed %+v", s)
	}
	// Released by the server; restored after an agent restart.
	spec.ReleaseAfter = 0
	if _, e = m.Isolate("0123456789abcdef0123456789abcded", spec, l); e != nil {
		t.Fatal(e)
	}
	before = enf.applied
	if e = m.Restore(); e != nil || enf.applied != before+1 {
		t.Fatal("restore", e)
	}
	if s, e = m.Release(); e != nil || s.Isolated || s.Released != "server" || s.Job != "0123456789abcdef0123456789abcded" {
		t.Fatalf("release %+v %v", s, e)
	}
	// Filters that cannot be applied leave the device as it was.
	enf.fail = true
	if _, e = m.Isolate("0123456789abcdef0123456789abcdec", spec, l); e == nil || m.State().Isolated {
		t.Fatal("isolated although the filters failed")
	}
	// A damaged state is reported, never read as "not isolated".
	if e = os.WriteFile(filepath.Join(dir, StateFile), []byte("{"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = other.BreakGlass("AAAA-BBBB-CCCC"); e == nil || errors.Is(e, ErrNotIsolated) {
		t.Fatal("damaged state", e)
	}
	if s = m.State(); s.Error == "" {
		t.Fatal("damaged state not reported")
	}
}

func TestDHCPRules(t *testing.T) {
	spec := protocol.IsolationSpec{Allow: []string{}, CodeHash: HashCode("x")}
	rules, e := Plan(spec, Local{ServerIPs: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, ServerPort: 8444, DHCPServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}})
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range rules {
		if r.Purpose != "dhcp" {
			continue
		}
		if r.LocalPort != 68 && r.LocalPort != 546 || r.Remote == "0.0.0.0/0" || r.Remote == "::/0" {
			t.Fatal("open DHCP rule", r)
		}
	}
	state := filepath.Join("ProgramData", "OpenRMM Agent", "state")
	if Dir(state) != filepath.Join("ProgramData", "OpenRMM Agent", "isolation") {
		t.Fatal(Dir(state))
	}
}
