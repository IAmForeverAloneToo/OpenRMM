//go:build !windows

package processes

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// CanKill reports whether a listed process may be ended by a case action.
func CanKill(uint32, string, string) bool { return false }

// Kill is available on Windows only.
func Kill(_ context.Context, a protocol.ResponseAction, _ func(string) (string, string)) ([]protocol.KillResult, bool) {
	return []protocol.KillResult{{PID: a.PID, Name: a.Name, Start: a.Start, Outcome: "denied"}}, false
}
