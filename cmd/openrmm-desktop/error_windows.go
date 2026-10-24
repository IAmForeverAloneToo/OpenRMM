package main

import (
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

func showError(message string) {
	text, _ := windows.UTF16PtrFromString(message)
	title, _ := windows.UTF16PtrFromString("OpenRMM desktop support")
	windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
	runtime.KeepAlive(text)
	runtime.KeepAlive(title)
}
