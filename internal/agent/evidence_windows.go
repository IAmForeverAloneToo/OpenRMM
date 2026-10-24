package agent

import (
	"os"
	"syscall"
)

// fileTimes returns the modification and creation times in Unix nanoseconds.
func fileTimes(i os.FileInfo) (int64, int64) {
	created := int64(0)
	if d, ok := i.Sys().(*syscall.Win32FileAttributeData); ok {
		created = d.CreationTime.Nanoseconds()
	}
	return i.ModTime().UnixNano(), created
}
