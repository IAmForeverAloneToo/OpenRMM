package filetransfer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func canonicalFile(f *os.File) (string, error) {
	buf := make([]uint16, 32768)
	n, e := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], uint32(len(buf)), 0)
	if e != nil || n == 0 || n >= uint32(len(buf)) {
		return "", errors.New("cannot resolve native file identity")
	}
	return strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`), nil
}

// longName expands 8.3 short components (such as PROGRA~1) of an existing
// path, so it can be compared with the final path Windows reports, which is
// always long. It resolves no links; a path that cannot be expanded is
// returned unchanged and still has to pass every later check.
func longName(p string) string {
	in, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return p
	}
	buf := make([]uint16, 32768)
	n, e := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if e != nil || n == 0 || n >= uint32(len(buf)) {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}

func canonical(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	return canonicalFile(f)
}

func safeRoot(p string) bool {
	volume, e := windows.UTF16PtrFromString(filepath.VolumeName(p) + `\`)
	if e != nil || windows.GetDriveType(volume) != windows.DRIVE_FIXED {
		return false
	}
	for {
		v, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return false
		}
		a, e := windows.GetFileAttributes(v)
		if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		if p == filepath.Dir(p) {
			return true
		}
		p = filepath.Dir(p)
	}
}
func singleLink(f *os.File) bool {
	var i windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i) == nil && i.NumberOfLinks == 1 && i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	findFirstFileName = kernel32.NewProc("FindFirstFileNameW")
	findNextFileName  = kernel32.NewProc("FindNextFileNameW")
)

// hardLinks lists every name of a file, as full paths on its volume.
func hardLinks(physical string) ([]string, error) {
	p, e := windows.UTF16PtrFromString(physical)
	if e != nil {
		return nil, e
	}
	volume := filepath.VolumeName(physical)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	h, _, err := findFirstFileName.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0])))
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, err
	}
	defer windows.FindClose(windows.Handle(h))
	names := []string{}
	for len(names) <= 64 {
		names = append(names, volume+windows.UTF16ToString(buf[:n]))
		n = uint32(len(buf))
		if r, _, err := findNextFileName.Call(h, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				return names, nil
			}
			return nil, err
		}
	}
	return nil, errors.New("too many hard links")
}

// linksAllowed accepts a regular, non-reparse file whose every name is
// outside the blocked folders (for evidence: system files often have
// several hard links). A name that cannot be listed refuses the file.
func linksAllowed(f *os.File, physical string, blocked func(string) bool) bool {
	var i windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i) != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if i.NumberOfLinks == 1 {
		return true
	}
	names, e := hardLinks(physical)
	if e != nil || len(names) < int(i.NumberOfLinks) {
		return false
	}
	for _, name := range names {
		if blocked(name) {
			return false
		}
	}
	return true
}
