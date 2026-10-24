//go:build !windows

package cpu

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(context.Context) (protocol.CPU, error) {
	return protocol.CPU{}, features.ErrUnsupported
}
