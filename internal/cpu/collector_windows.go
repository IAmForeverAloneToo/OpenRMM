package cpu

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

var systemDLL = windows.NewLazySystemDLL("kernel32.dll")
var getSystemTimes = systemDLL.NewProc("GetSystemTimes")
var getProcessorGroups = systemDLL.NewProc("GetActiveProcessorGroupCount")

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(ctx context.Context) (protocol.CPU, error) {
	return sample(ctx, readTimes, waitSample, time.Now)
}

func readTimes() (times, error) {
	if err := getProcessorGroups.Find(); err != nil {
		return times{}, errors.New("Windows processor group API unavailable")
	}
	groupResult, _, _ := getProcessorGroups.Call()
	groups := uint16(groupResult) // The API returns WORD, not a pointer-sized value.
	if groups == 0 {
		return times{}, errors.New("Windows processor group query failed")
	}
	// GetSystemTimes covers only the calling thread's group on multi-group
	// machines. Report unsupported rather than labeling a partial value overall.
	if groups != 1 {
		return times{}, features.ErrUnsupported
	}
	if err := getSystemTimes.Find(); err != nil {
		return times{}, errors.New("Windows CPU API unavailable")
	}
	var idle, kernel, user windows.Filetime
	result, _, _ := getSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if result == 0 {
		return times{}, errors.New("Windows CPU query failed")
	}
	ticks := func(value windows.Filetime) uint64 { return uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime) }
	return times{idle: ticks(idle), kernel: ticks(kernel), user: ticks(user)}, nil
}
