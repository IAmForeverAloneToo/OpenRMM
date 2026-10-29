package agent

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"time"
)

func (s *heartbeatSession) desktopExchange(ctx context.Context, p desktop.Exchange) (desktop.Reply, error) {
	if s.desktop.quiet(s.wake, p) {
		return desktop.Reply{}, nil
	}
	// Desktop traffic has a shorter fail-closed deadline than ordinary collectors.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var r desktop.Reply
	e := s.call(ctx, "/api/v1/agent/desktop", p, &r)
	if e == nil {
		s.desktop.forwarded(p, r)
	}
	return r, e
}
