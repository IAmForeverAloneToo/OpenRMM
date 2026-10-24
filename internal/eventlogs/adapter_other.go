//go:build !windows

package eventlogs

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type native struct{}

func NewAdapter() Adapter { return native{} }
func (native) Probe(context.Context) (protocol.EventLogSupport, error) {
	return protocol.EventLogSupport{}, features.ErrUnsupported
}
func (native) Query(_ context.Context, q protocol.EventQuery) protocol.EventResult {
	return protocol.EventResult{ID: q.ID, Outcome: "unsupported", Events: []protocol.WindowsEvent{}}
}
