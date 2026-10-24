//go:build !windows

package sysinfo

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(context.Context) (protocol.SystemInfo, error) {
	return protocol.SystemInfo{}, features.ErrUnsupported
}
