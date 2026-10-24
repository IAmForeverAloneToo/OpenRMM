//go:build !windows

package windowsupdate

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type unsupported struct{}

// WorkerFlag runs one Windows Update job in a child process (Windows only).
const WorkerFlag = "--update-worker"

func NewLocal(context.Context, string) (Adapter, error) { return unsupported{}, nil }
func WorkerMain() int                                   { return 2 }
func (unsupported) Probe(context.Context) (protocol.UpdateSupport, error) {
	return protocol.UpdateSupport{Broker: "unsupported"}, nil
}
func (unsupported) Submit(_ context.Context, q protocol.UpdateJob) (protocol.UpdateProgress, error) {
	return Failure(q, "unsupported"), nil
}
func (unsupported) Status(context.Context, string) (protocol.UpdateProgress, error) {
	return protocol.UpdateProgress{}, ErrInvalid
}
