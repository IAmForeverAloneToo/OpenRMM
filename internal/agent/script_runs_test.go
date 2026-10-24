package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func agentScriptJob() protocol.ScriptJob {
	v := protocol.ScriptVersion{ID: strings.Repeat("a", 32), ScriptID: strings.Repeat("b", 32), Number: 1, Definition: protocol.ScriptDefinition{Name: "Test", Body: "Write-Output fixture", Parameters: []protocol.ScriptParameter{}, Timeout: 5, RunAs: "restricted"}}
	v.Hash = scripting.Digest(v)
	return protocol.ScriptJob{ID: strings.Repeat("c", 32), Version: v, Arguments: map[string]string{}, ExpiresAt: 1}
}
func TestScriptResultRetryAndRestartNeverExecuteAgain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := t.TempDir()
	q := agentScriptJob()
	var calls atomic.Int32
	polls, sends := 0, 0
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runScripts(ctx, state, func(context.Context) (protocol.ScriptDispatch, error) {
		polls++
		if polls == 1 {
			return protocol.ScriptDispatch{Job: &q}, nil
		}
		cancel()
		return protocol.ScriptDispatch{}, nil
	}, func(_ context.Context, r protocol.ScriptResult) (bool, error) {
		if r.Outcome != "running" {
			sends++
			if sends == 1 {
				return false, errors.New("outage")
			}
		}
		return false, nil
	}, func(context.Context, protocol.ScriptJob) protocol.ScriptResult {
		calls.Add(1)
		return scripting.Failure(q.ID, "cancelled")
	}, func(ctx context.Context, _ time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
			return true
		}
	}, logger)
	if calls.Load() != 1 || sends != 2 {
		t.Fatal("execution replayed", calls.Load(), sends)
	}
	j := scriptJournal{q, scripting.Failure(q.ID, "running")}
	raw, _ := json.Marshal(j)
	if e := os.WriteFile(filepath.Join(state, "script-run.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	runScripts(ctx, state, func(context.Context) (protocol.ScriptDispatch, error) {
		cancel()
		return protocol.ScriptDispatch{}, nil
	}, func(_ context.Context, r protocol.ScriptResult) (bool, error) {
		if r.Outcome != "unknown" {
			t.Fatal("interrupted execution not unknown")
		}
		return false, nil
	}, func(context.Context, protocol.ScriptJob) protocol.ScriptResult {
		t.Fatal("restart re-executed code")
		return protocol.ScriptResult{}
	}, func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }, logger)
}
