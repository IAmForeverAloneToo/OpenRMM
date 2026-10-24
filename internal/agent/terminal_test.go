package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
	"strings"
	"testing"
	"time"
)

type fakeTerminal struct {
	inputs []string
	closes int
}

func (s *fakeTerminal) Input(b []byte) error  { s.inputs = append(s.inputs, string(b)); return nil }
func (s *fakeTerminal) Drain() ([]byte, bool) { return []byte("output"), false }
func (s *fakeTerminal) Close()                { s.closes++ }
func TestTerminalTransportFailureTerminatesAndChangesPeerWithoutReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q := &terminal.Request{ID: strings.Repeat("a", 32), Actor: "admin", Identity: "sid", Expires: time.Now().Add(time.Minute).Unix()}
	shell := &fakeTerminal{}
	calls, starts := 0, 0
	peer := ""
	runTerminal(ctx, t.TempDir(), func(_ context.Context, p terminal.Exchange) (terminal.Reply, error) {
		calls++
		switch calls {
		case 1:
			peer = p.Peer
			return terminal.Reply{Request: q}, nil
		case 2:
			return terminal.Reply{Request: q, Inputs: []terminal.Input{{Sequence: 1, Data: "once\r"}}}, nil
		case 3:
			if len(shell.inputs) != 1 || p.Sequence != 2 {
				t.Fatal("missing execution/output")
			}
			return terminal.Reply{}, errors.New("response lost")
		default:
			if p.Peer == peer || p.ID != "" || shell.closes != 1 {
				t.Fatal("old epoch or shell survived")
			}
			cancel()
			return terminal.Reply{}, nil
		}
	}, func(string) (terminal.Shell, error) { starts++; return shell, nil }, "sid", func() bool { return true })
	if starts != 1 || len(shell.inputs) != 1 || shell.inputs[0] != "once\r" {
		t.Fatal("replayed input/start")
	}
}
func TestTerminalRejectsDuplicateInputsAndMalformedRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	shell := &fakeTerminal{}
	calls := 0
	q := &terminal.Request{ID: strings.Repeat("a", 32), Actor: "admin", Identity: "sid", Expires: time.Now().Add(time.Minute).Unix()}
	runTerminal(ctx, t.TempDir(), func(context.Context, terminal.Exchange) (terminal.Reply, error) {
		calls++
		r := terminal.Reply{Request: q}
		if calls > 1 {
			r.Inputs = []terminal.Input{{Sequence: 1, Data: "once\r"}}
		}
		return r, nil
	}, func(string) (terminal.Shell, error) { return shell, nil }, "sid", func() bool { return true })
	if len(shell.inputs) != 1 || shell.closes == 0 {
		t.Fatal("duplicate reached shell")
	}
	q.ID = strings.Repeat("z", 32)
	if validTerminalRequest(q, "sid") {
		t.Fatal("malformed id")
	}
	q.ID = strings.Repeat("a", 32)
	q.Identity = "SYSTEM"
	if validTerminalRequest(q, "sid") {
		t.Fatal("identity change")
	}
}

func TestTerminalLocalDisableStopsShellWithoutFurtherRemoteInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	shell := &fakeTerminal{}
	allowed := true
	checks := 0
	calls := 0
	q := &terminal.Request{ID: strings.Repeat("a", 32), Actor: "admin", Identity: "sid", Expires: time.Now().Add(time.Minute).Unix()}
	runTerminal(ctx, t.TempDir(), func(context.Context, terminal.Exchange) (terminal.Reply, error) {
		calls++
		if calls == 2 {
			allowed = false
		}
		return terminal.Reply{Request: q}, nil
	}, func(string) (terminal.Shell, error) { return shell, nil }, "sid", func() bool {
		checks++
		if checks == 4 {
			cancel()
		}
		return allowed
	})
	if calls != 2 || shell.closes != 1 || len(shell.inputs) != 0 {
		t.Fatal("local disable did not close session", calls, shell.closes)
	}
}

// R7: an invalid request no longer ends terminal support; the epoch is
// abandoned with a fresh peer and a later valid request still starts a shell.
func TestTerminalRecoversAfterInvalidRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bad := &terminal.Request{ID: "not-an-id", Actor: "admin", Identity: "sid", Expires: time.Now().Add(time.Minute).Unix()}
	good := &terminal.Request{ID: strings.Repeat("b", 32), Actor: "admin", Identity: "sid", Expires: time.Now().Add(time.Minute).Unix()}
	shell := &fakeTerminal{}
	calls, starts := 0, 0
	peers := map[string]bool{}
	runTerminal(ctx, t.TempDir(), func(_ context.Context, p terminal.Exchange) (terminal.Reply, error) {
		calls++
		peers[p.Peer] = true
		switch calls {
		case 1:
			return terminal.Reply{Request: bad}, nil
		case 2:
			return terminal.Reply{Request: good}, nil
		default:
			cancel()
			return terminal.Reply{}, nil
		}
	}, func(string) (terminal.Shell, error) { starts++; return shell, nil }, "sid", func() bool { return true })
	if starts != 1 || len(peers) != 2 {
		t.Fatal("terminal did not recover with a fresh peer", starts, len(peers))
	}
}

// A normal request lasts at most 15 minutes; a long (recorded) one
// names an idle limit of at most 15 minutes and lasts at most two hours.
func TestTerminalRequestLimits(t *testing.T) {
	q := func(expires time.Duration, idle int64) *terminal.Request {
		return &terminal.Request{ID: strings.Repeat("a", 32), Actor: "admin", Identity: "sid", Expires: time.Now().Add(expires).Unix(), Idle: idle}
	}
	for _, c := range []struct {
		r  *terminal.Request
		ok bool
	}{{q(15*time.Minute, 0), true}, {q(20*time.Minute, 0), false}, {q(2*time.Hour, 900), true}, {q(3*time.Hour, 900), false}, {q(time.Hour, 901), false}, {q(time.Hour, -1), false}} {
		if validTerminalRequest(c.r, "sid") != c.ok {
			t.Fatal("limits", c.r.Expires-time.Now().Unix(), c.r.Idle)
		}
	}
}
