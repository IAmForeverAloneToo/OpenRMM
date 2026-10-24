//go:build !windows

package agent

import "os"

// fileTimes returns the modification time; creation time is not reported.
func fileTimes(i os.FileInfo) (int64, int64) { return i.ModTime().UnixNano(), 0 }
