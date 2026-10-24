//go:build !windows

package memory

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(context.Context) (protocol.Memory, error) {
	return protocol.Memory{}, features.ErrUnsupported
}
