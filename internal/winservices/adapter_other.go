//go:build !windows

package winservices

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type unsupported struct{}

func NewAdapter() Adapter { return unsupported{} }
func (unsupported) Collect(context.Context) (protocol.Services, error) {
	return protocol.Services{}, features.ErrUnsupported
}
func (unsupported) Execute(_ context.Context, a protocol.ServiceAction) protocol.ServiceResult {
	return protocol.ServiceResult{ID: a.ID, Outcome: "denied", State: "unknown"}
}
