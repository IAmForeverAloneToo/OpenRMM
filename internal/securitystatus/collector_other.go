//go:build !windows

package securitystatus

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type native struct{}

func NewCollector() Collector { return native{} }

func (native) Collect(context.Context) (protocol.SecurityStatus, error) {
	return protocol.SecurityStatus{}, features.ErrUnsupported
}
