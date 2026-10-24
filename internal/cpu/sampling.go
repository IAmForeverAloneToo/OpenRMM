package cpu

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Windows kernel time includes idle time. These are unsigned raw 100ns counters,
// not timestamps to convert through FILETIME's calendar epoch.
type times struct{ idle, kernel, user uint64 }

func utilization(before, after times) (float64, error) {
	if after.idle < before.idle || after.kernel < before.kernel || after.user < before.user {
		return 0, errors.New("CPU counters moved backwards")
	}
	idle, kernel, user := after.idle-before.idle, after.kernel-before.kernel, after.user-before.user
	if idle > kernel || kernel > math.MaxUint64-user || kernel+user == 0 {
		return 0, errors.New("invalid CPU counter deltas")
	}
	total := kernel + user
	return 100 * (float64(total-idle) / float64(total)), nil
}

func waitSample(ctx context.Context) error {
	timer := time.NewTimer(SampleWindow)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sample(ctx context.Context, read func() (times, error), wait func(context.Context) error, now func() time.Time) (protocol.CPU, error) {
	if err := ctx.Err(); err != nil {
		return protocol.CPU{}, err
	}
	before, err := read()
	if err != nil {
		return protocol.CPU{}, err
	}
	started := now()
	if err := wait(ctx); err != nil {
		return protocol.CPU{}, err
	}
	if err := ctx.Err(); err != nil {
		return protocol.CPU{}, err
	}
	after, err := read()
	if err != nil {
		return protocol.CPU{}, err
	}
	elapsed := now().Sub(started)
	if err := ctx.Err(); err != nil {
		return protocol.CPU{}, err
	}
	if elapsed < SampleWindow || elapsed > 5*time.Second {
		return protocol.CPU{}, errors.New("invalid CPU sampling duration")
	}
	usage, err := utilization(before, after)
	if err != nil {
		return protocol.CPU{}, err
	}
	return protocol.CPU{UsagePercent: usage, SampleMilliseconds: uint32(elapsed / time.Millisecond)}, nil
}
