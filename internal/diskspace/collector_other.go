//go:build !windows

package diskspace

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(context.Context) (protocol.DiskSpace, error) {
	return protocol.DiskSpace{}, features.ErrUnsupported
}
