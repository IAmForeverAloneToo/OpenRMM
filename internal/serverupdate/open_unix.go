//go:build unix

package serverupdate

import (
	"os"
	"syscall"
)

// openFlags never follow a symbolic link and never block on a FIFO.
const openFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
