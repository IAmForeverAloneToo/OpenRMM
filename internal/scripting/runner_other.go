//go:build !windows

package scripting

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func Supported() bool { return false }
func WorkerMain() int { return 2 }
func RunContained(context.Context, string, protocol.ScriptJob) protocol.ScriptResult {
	return protocol.ScriptResult{Outcome: "unsupported"}
}
