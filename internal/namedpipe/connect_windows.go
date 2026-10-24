// Package namedpipe holds the one connection step shared by OpenRMM's local
// single-instance, non-blocking named-pipe servers.
package namedpipe

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Connect polls a non-blocking pipe instance. It reports true when a client is
// connected. A client that connected and closed before being served leaves the
// instance in ERROR_NO_DATA until it is disconnected; merely waiting would
// poison the sole instance for every later client, so it is reset here and the
// caller simply polls again.
func Connect(h windows.Handle) (bool, error) {
	e := windows.ConnectNamedPipe(h, nil)
	if e == nil || errors.Is(e, windows.ERROR_PIPE_CONNECTED) {
		return true, nil
	}
	if errors.Is(e, windows.ERROR_PIPE_LISTENING) {
		return false, nil
	}
	if errors.Is(e, windows.ERROR_NO_DATA) {
		e = windows.DisconnectNamedPipe(h)
		if e == nil || errors.Is(e, windows.ERROR_PIPE_NOT_CONNECTED) {
			return false, nil
		}
	}
	return false, e
}
