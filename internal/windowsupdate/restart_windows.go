package windowsupdate

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func scheduleRestart() error {
	var token windows.Token
	if e := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); e != nil {
		return e
	}
	defer token.Close()
	n, _ := windows.UTF16PtrFromString("SeShutdownPrivilege")
	var luid windows.LUID
	if e := windows.LookupPrivilegeValue(nil, n, &luid); e != nil {
		return e
	}
	p := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	var previous windows.Tokenprivileges
	var size uint32
	if e := windows.AdjustTokenPrivileges(token, false, &p, uint32(unsafe.Sizeof(previous)), &previous, &size); e != nil {
		return e
	}
	defer windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
	message, _ := windows.UTF16PtrFromString("OpenRMM administrator requested a restart to finish Windows updates. Save your work.")
	r, _, e := windows.NewLazySystemDLL("advapi32.dll").NewProc("InitiateSystemShutdownExW").Call(0, uintptr(unsafe.Pointer(message)), 60, 0, 1, 0x80020003)
	if r == 0 {
		return e
	}
	return nil
}
