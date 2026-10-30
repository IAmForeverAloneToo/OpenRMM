package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// policyProxy reads the string "Proxy" from the agent's machine policy key.
func policyProxy() string {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\OpenRMM\Agent`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return ""
	}
	defer k.Close()
	v, _, e := k.GetStringValue("Proxy")
	if e != nil {
		return ""
	}
	return v
}

var (
	winhttp                                 = windows.NewLazySystemDLL("winhttp.dll")
	procWinHttpGetDefaultProxyConfiguration = winhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	procGlobalFree                          = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

// winhttpProxyInfo is WINHTTP_PROXY_INFO.
type winhttpProxyInfo struct {
	accessType uint32
	proxy      *uint16
	bypass     *uint16
}

const winhttpAccessTypeNamedProxy = 3

// machineProxy reads the machine's WinHTTP proxy (netsh winhttp show proxy).
func machineProxy() systemProxy {
	if procWinHttpGetDefaultProxyConfiguration.Find() != nil {
		return systemProxy{}
	}
	var info winhttpProxyInfo
	if r, _, _ := procWinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return systemProxy{}
	}
	list, bypass := windows.UTF16PtrToString(info.proxy), windows.UTF16PtrToString(info.bypass)
	for _, p := range []*uint16{info.proxy, info.bypass} {
		if p != nil {
			_, _, _ = procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
		}
	}
	if info.accessType != winhttpAccessTypeNamedProxy {
		return systemProxy{}
	}
	return parseSystemProxy(list, bypass)
}
