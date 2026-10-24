//go:build !windows

package localaccounts

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(context.Context) (protocol.LocalAccounts, error) {
	return protocol.LocalAccounts{}, features.ErrUnsupported
}
