package memory

import (
	"context"
	"errors"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

// x/sys v0.49.0 has no typed GlobalMemoryStatusEx wrapper. Load the fixed system
// DLL using its safe loader; never search user-controlled DLL directories.
var globalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// MEMORYSTATUSEX, matching sysinfoapi.h (DWORD, DWORD, seven DWORDLONGs).
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(ctx context.Context) (protocol.Memory, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Memory{}, err
	}
	if err := globalMemoryStatusEx.Find(); err != nil {
		return protocol.Memory{}, errors.New("Windows memory API unavailable")
	}
	value := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	result, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&value)))
	if result == 0 {
		return protocol.Memory{}, errors.New("Windows memory query failed")
	}
	return protocol.Memory{TotalBytes: value.TotalPhys, AvailableBytes: value.AvailPhys}, ctx.Err()
}
