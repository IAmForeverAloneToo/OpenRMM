package diskspace

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }
func (nativeCollector) Collect(ctx context.Context) (protocol.DiskSpace, error) {
	if err := ctx.Err(); err != nil {
		return protocol.DiskSpace{}, err
	}
	directory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return protocol.DiskSpace{}, err
	}
	value := protocol.DiskSpace{Drive: strings.ToUpper(filepath.VolumeName(directory)) + `\`}
	path, err := windows.UTF16PtrFromString(value.Drive)
	if err != nil {
		return protocol.DiskSpace{}, err
	}
	// Use the caller's total/available pair consistently, including any quotas.
	if err := windows.GetDiskFreeSpaceEx(path, &value.AvailableBytes, &value.TotalBytes, nil); err != nil {
		return protocol.DiskSpace{}, err
	}
	return value, ctx.Err()
}
