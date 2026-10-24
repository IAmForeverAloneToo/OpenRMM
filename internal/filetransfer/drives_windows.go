package filetransfer

import (
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

// fixedDrives lists local fixed drives in letter order (at most eight, the
// protocol limit). Removable, network and optical drives are never offered.
func fixedDrives() []LocalRoot {
	roots := []LocalRoot{}
	mask, e := windows.GetLogicalDrives()
	if e != nil {
		return roots
	}
	for i := 0; i < 26 && len(roots) < 8; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A' + i))
		p, e := windows.UTF16PtrFromString(letter + `:\`)
		if e != nil || windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		roots = append(roots, LocalRoot{FileRoot: protocol.FileRoot{Name: letter + ":", Read: true, Write: true}, Path: letter + `:\`})
	}
	return roots
}
