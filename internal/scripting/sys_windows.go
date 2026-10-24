package scripting

import "syscall"
import "golang.org/x/sys/windows"

var windowsSysProcAttr = syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
