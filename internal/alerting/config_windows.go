package alerting

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func privateConfig(path string, f *os.File) error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrMailConfig
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		info, e := os.Lstat(p)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrMailConfig
		}
		var sd *windows.SECURITY_DESCRIPTOR
		if p == path {
			sd, e = windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		} else {
			sd, e = windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		}
		if e != nil {
			return ErrMailConfig
		}
		owner, _, e := sd.Owner()
		if e != nil || !(owner.Equals(u.User.Sid) || owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
			return ErrMailConfig
		}
		dacl, _, e := sd.DACL()
		if e != nil || dacl == nil {
			return ErrMailConfig
		}
		for i := uint16(0); i < dacl.AceCount; i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(dacl, uint32(i), &ace) != nil {
				return ErrMailConfig
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				return ErrMailConfig
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(u.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
				continue
			}
			// File readers can steal credentials; parent readers are safe but
			// any unrelated writer could replace the protected file.
			mask := uint32(0xf01f01ff)
			if p != path {
				mask = 0x500d0156
			}
			if uint32(ace.Mask)&mask != 0 {
				return ErrMailConfig
			}
		}
	}
	return nil
}
