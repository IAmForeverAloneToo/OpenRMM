// Package isolation works out and applies network isolation on the agent
// Plan turns an isolate action and what the agent knows about its
// network (the server's addresses and port, the DNS resolvers in use) into
// the traffic that stays allowed; an Enforcer applies or removes it.
//
// Until isolation is verified on a disposable VM, Enforce is false and
// agents use the dry-run enforcer — the rules are reported, nothing is
// blocked.
package isolation

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Enforce switches real filtering on. It stays false until the Windows
// Filtering Platform enforcer is verified on a disposable VM.
const Enforce = false

// Local is what the agent knows about its network when it isolates.
// ServerIPs are the server's addresses (resolved, and the address of the
// connection in use); DNS the resolvers the device uses.
type Local struct {
	ServerIPs  []netip.Addr
	ServerPort int
	DNS        []netip.Addr
	// DHCPServers are the servers that leased the adapters' addresses.
	DHCPServers []netip.Addr
	// ServerByName: the server is reached by host name, so DNS is required.
	ServerByName bool
}

// ErrNoServer: the server's address is unknown, so isolating would cut the
// device off from OpenRMM (the pre-flight check fails).
var ErrNoServer = errors.New("the server's address is unknown; isolating would cut the device off")

// ErrNoDNS: the server is reached by name but no DNS resolver is known, so
// isolating would cut the device off.
var ErrNoDNS = errors.New("no DNS resolver is known and the server is reached by name; isolating would cut the device off")

func host(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()).String()
}

// Plan works out the allowed traffic: TCP to the server's addresses on its
// port, DNS (UDP and TCP 53) to the device's resolvers, DHCP and DHCPv6,
// loopback, and anything to or from the allow list.
func Plan(spec protocol.IsolationSpec, l Local) ([]protocol.IsolationRule, error) {
	if !spec.Valid() {
		return nil, errors.New("invalid isolation spec")
	}
	if l.ServerPort <= 0 || l.ServerPort > 65535 {
		return nil, ErrNoServer
	}
	var rules []protocol.IsolationRule
	seen := map[protocol.IsolationRule]bool{}
	add := func(r protocol.IsolationRule) {
		if !seen[r] {
			seen[r] = true
			rules = append(rules, r)
		}
	}
	servers := 0
	for _, a := range l.ServerIPs {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		add(protocol.IsolationRule{Purpose: "server", Direction: "out", Protocol: "tcp", Remote: host(a), Port: l.ServerPort})
		servers++
	}
	if servers == 0 {
		return nil, ErrNoServer
	}
	resolvers := 0
	for _, a := range l.DNS {
		if !a.IsValid() || a.IsUnspecified() {
			continue
		}
		add(protocol.IsolationRule{Purpose: "dns", Direction: "out", Protocol: "udp", Remote: host(a), Port: 53})
		add(protocol.IsolationRule{Purpose: "dns", Direction: "out", Protocol: "tcp", Remote: host(a), Port: 53})
		resolvers++
	}
	if l.ServerByName && resolvers == 0 {
		return nil, ErrNoDNS
	}
	// DHCP between the client ports and the server ports only: requests to
	// the broadcast address (and DHCPv6 to its multicast group), both ways
	// with the servers that leased the addresses (offers and renewals), and
	// DHCPv6 replies from link-local servers.
	add(protocol.IsolationRule{Purpose: "dhcp", Direction: "out", Protocol: "udp", Remote: "255.255.255.255/32", Port: 67, LocalPort: 68})
	for _, a := range l.DHCPServers {
		if a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() {
			port, local := 67, 68
			if !a.Unmap().Is4() {
				port, local = 547, 546
			}
			add(protocol.IsolationRule{Purpose: "dhcp", Direction: "both", Protocol: "udp", Remote: host(a), Port: port, LocalPort: local})
		}
	}
	add(protocol.IsolationRule{Purpose: "dhcp", Direction: "out", Protocol: "udp", Remote: "ff02::1:2/128", Port: 547, LocalPort: 546})
	add(protocol.IsolationRule{Purpose: "dhcp", Direction: "both", Protocol: "udp", Remote: "fe80::/10", Port: 547, LocalPort: 546})
	add(protocol.IsolationRule{Purpose: "loopback", Direction: "both", Protocol: "any", Remote: "127.0.0.0/8"})
	add(protocol.IsolationRule{Purpose: "loopback", Direction: "both", Protocol: "any", Remote: "::1/128"})
	for _, s := range spec.Allow {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			a, _ := netip.ParseAddr(s)
			p = netip.PrefixFrom(a, a.BitLen())
		}
		add(protocol.IsolationRule{Purpose: "allow", Direction: "both", Protocol: "any", Remote: p.String()})
	}
	return rules, nil
}

// Enforcer applies and removes isolation.
type Enforcer interface {
	Apply(rules []protocol.IsolationRule) error
	Remove() error
	// Mode is enforced or dry_run.
	Mode() string
}

// DryRun records the rules without blocking anything.
type DryRun struct{ Rules []protocol.IsolationRule }

func (d *DryRun) Apply(r []protocol.IsolationRule) error { d.Rules = r; return nil }
func (d *DryRun) Remove() error                          { d.Rules = nil; return nil }
func (*DryRun) Mode() string                             { return "dry_run" }

// HashCode is the SHA-256 (hex) of a release code as typed: case and the
// grouping dashes and spaces do not matter.
func HashCode(code string) string {
	c := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}

// CodeMatches compares a typed release code with the isolation's code hash.
func CodeMatches(code, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashCode(code)), []byte(hash)) == 1
}

// Dir is the isolation folder beside the agent's state folder: SYSTEM and
// Administrators can both use it, so the break-glass command (an
// administrator) reads and writes the state the agent service (SYSTEM) keeps
// there. The state folder itself is SYSTEM-only.
func Dir(state string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(state)), "isolation")
}

// SortRules orders rules for reports.
func SortRules(r []protocol.IsolationRule) {
	order := map[string]int{"server": 0, "dns": 1, "dhcp": 2, "loopback": 3, "allow": 4}
	sort.SliceStable(r, func(i, j int) bool { return order[r[i].Purpose] < order[r[j].Purpose] })
}
