//go:build !windows

package processes

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type native struct{}

func NewAdapter() Adapter { return native{} }
func (native) Collect(context.Context) (protocol.Processes, error) {
	return protocol.Processes{}, features.ErrUnsupported
}
func (native) Execute(_ context.Context, a protocol.ProcessAction) protocol.ProcessResult {
	return protocol.ProcessResult{ID: a.ID, Outcome: "denied"}
}
