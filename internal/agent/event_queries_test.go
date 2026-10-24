package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"log/slog"
	"testing"
	"time"
)

type eventAdapter struct{ calls int }

func (a *eventAdapter) Probe(context.Context) (protocol.EventLogSupport, error) {
	return protocol.EventLogSupport{System: "readable", Application: "readable"}, nil
}
func (a *eventAdapter) Query(_ context.Context, q protocol.EventQuery) protocol.EventResult {
	a.calls++
	return protocol.EventResult{ID: q.ID, Outcome: "ok", Events: []protocol.WindowsEvent{}}
}
func TestEventResultsRetryWithoutRepeatingNativeQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &eventAdapter{}
	polls, sends := 0, 0
	runEventQueries(ctx, a, func(context.Context) (protocol.EventDispatch, error) {
		polls++
		if polls > 1 {
			cancel()
			return protocol.EventDispatch{}, nil
		}
		return protocol.EventDispatch{Query: &protocol.EventQuery{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Filter: protocol.EventFilter{Channel: "System", From: 1, To: 2, Level: -1, EventID: -1, Limit: 25}}}, nil
	}, func(context.Context, protocol.EventResult) error {
		sends++
		if sends == 1 {
			return errors.New("outage")
		}
		return nil
	}, func(context.Context, time.Duration) bool { return true }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if a.calls != 1 || sends != 2 {
		t.Fatal("result retry repeated the query")
	}
}
