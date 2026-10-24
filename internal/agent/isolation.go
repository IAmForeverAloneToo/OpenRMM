package agent

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/isolation"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sysinfo"
)

// Network isolation. The isolate and release response actions run
// through the evidence pipeline like other mutating actions (journaled, never
// run twice) in their own worker, so they never wait behind a collection;
// the state is reported in every heartbeat. Enforcement is a dry run until it
// is verified on a disposable VM (isolation.Enforce).

// isolationRefresh is how often an isolation's rules are worked out again.
const isolationRefresh = 15 * time.Minute

// newIsolation prepares the isolation folder beside the state folder: the
// installed service limits it to SYSTEM and Administrators, so the
// break-glass command (an administrator) can use it.
func newIsolation(c configState) (*isolation.Manager, error) {
	dir := isolation.Dir(c.state)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if c.service {
		if e := privatefs.RestrictInstallation(dir); e != nil {
			return nil, e
		}
	}
	return &isolation.Manager{Dir: dir, Enforcer: isolation.NewEnforcer()}, nil
}

type configState struct {
	state   string
	service bool
}

// isolationLocal works out the server's addresses and port (from the device
// endpoint in the credentials, resolved, plus the address a connection to it
// actually reaches) and the DNS resolvers and DHCP servers of connected
// adapters.
func (s *heartbeatSession) isolationLocal(ctx context.Context) isolation.Local {
	s.transportMu.RLock()
	origin := s.value.DeviceURL
	s.transportMu.RUnlock()
	var l isolation.Local
	u, e := url.Parse(origin)
	if e != nil {
		return l
	}
	host, portText := u.Hostname(), u.Port()
	if portText == "" {
		portText = "443"
	}
	if port, e := strconv.Atoi(portText); e == nil {
		l.ServerPort = port
	}
	if a, e := netip.ParseAddr(host); e == nil {
		l.ServerIPs = []netip.Addr{a}
	} else {
		l.ServerByName = true
		lookup, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, _ := net.DefaultResolver.LookupNetIP(lookup, "ip", host)
		cancel()
		l.ServerIPs = ips
	}
	// The address a connection reaches now (a load balancer or round-robin
	// DNS may answer differently from the lookup above).
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if conn, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, portText)); e == nil {
		if a, e := netip.ParseAddrPort(conn.RemoteAddr().String()); e == nil {
			l.ServerIPs = append(l.ServerIPs, a.Addr())
		}
		conn.Close()
	}
	info, e := sysinfo.NewCollector().Collect(ctx)
	if e == nil {
		for _, a := range info.Adapters {
			if a.Status != "up" {
				continue
			}
			for _, d := range a.DNS {
				if ip, e := netip.ParseAddr(d); e == nil {
					l.DNS = append(l.DNS, ip)
				}
			}
			if ip, e := netip.ParseAddr(a.DHCPServer); e == nil && a.DHCP {
				l.DHCPServers = append(l.DHCPServers, ip)
			}
		}
	}
	return l
}

// isolate runs an isolate action; release lifts isolation. The result keeps
// the action without the release code's hash (it becomes case evidence).
func (s *heartbeatSession) isolate(ctx context.Context, job string, a protocol.ResponseAction) protocol.ActionResult {
	shown := a
	if a.Isolate != nil {
		spec := *a.Isolate
		spec.CodeHash = ""
		shown.Isolate = &spec
	}
	result := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: shown, DeviceTime: time.Now().UTC().Format(time.RFC3339Nano)}
	var state protocol.IsolationState
	if s.isolation == nil {
		state.Error = "isolation is unavailable on this device"
	} else if a.Kind == "release" {
		state, _ = s.isolation.Release()
	} else {
		state, _ = s.isolation.Isolate(job, *a.Isolate, s.isolationLocal(ctx))
	}
	result.Isolation = &state
	return result
}

// refreshIsolation works an isolation's rules out again now and then (the
// server's addresses and the resolvers can change).
func (s *heartbeatSession) refreshIsolation(ctx context.Context, state protocol.IsolationState) {
	if s.isolation == nil || !state.Isolated || time.Since(s.isolationRefreshed) < isolationRefresh {
		return
	}
	s.isolationRefreshed = time.Now()
	if e := s.isolation.Refresh(s.isolationLocal(ctx)); e != nil && s.logger != nil {
		s.logger.Warn("network isolation rules not refreshed; keeping the rules in force", "reason", e.Error())
	}
}
