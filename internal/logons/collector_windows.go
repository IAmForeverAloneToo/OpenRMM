package logons

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
)

type native struct{}

// NewReader reads the Security log, which the agent (SYSTEM) may read.
func NewReader() Reader { return native{} }

func (native) Read(ctx context.Context, xpath string, max int, each func(string) bool) error {
	return eventlogs.ReadForward(ctx, "Security", xpath, max, each)
}
