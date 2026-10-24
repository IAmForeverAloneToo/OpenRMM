//go:build !windows

package agentupdate

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type unavailable struct{}

func NewClient() Client { return unavailable{} }
func (unavailable) Probe(context.Context) (protocol.AgentUpgradeSupport, error) {
	return protocol.AgentUpgradeSupport{}, features.ErrUnsupported
}
func (unavailable) Submit(context.Context, protocol.AgentUpgradeJob) (protocol.AgentUpgradeResult, error) {
	return protocol.AgentUpgradeResult{}, features.ErrUnsupported
}
func (unavailable) Status(context.Context, string) (protocol.AgentUpgradeResult, error) {
	return protocol.AgentUpgradeResult{}, features.ErrUnsupported
}
func (unavailable) Healthy(context.Context, string) error { return features.ErrUnsupported }

// Self-update through Windows Installer exists only on Windows.
const HelperFlag = "--update-helper"

func NewAgentClient() Client { return unavailable{} }
func HelperMain() int        { return 2 }
func Resume()                {}
func CleanupLegacy()         {}
