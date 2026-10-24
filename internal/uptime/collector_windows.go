package uptime

import (
	"context"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(ctx context.Context) (protocol.Uptime, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Uptime{}, err
	}
	elapsed := windows.DurationSinceBoot()
	value, err := fromDuration(elapsed, time.Now())
	if err != nil {
		return protocol.Uptime{}, err
	}
	return value, ctx.Err()
}
