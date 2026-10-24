//go:build !windows

package inventory

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type unsupportedCollector struct{}

func NewCollector(string) Collector { return unsupportedCollector{} }
func (unsupportedCollector) Collect(context.Context) (protocol.Inventory, error) {
	return protocol.Inventory{}, features.ErrUnsupported
}
