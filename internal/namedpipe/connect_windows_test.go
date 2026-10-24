package namedpipe

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestEarlyDisconnectDoesNotPoisonNextConnection(t *testing.T) {
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\pipe\OpenRMM.NamedPipe.test.%d.%d`, os.Getpid(), time.Now().UnixNano()))
	h, e := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 1024, 1024, 0, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	open := func() windows.Handle {
		t.Helper()
		peer, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if e != nil {
			t.Fatal(e)
		}
		return peer
	}
	peer := open()
	windows.CloseHandle(peer)
	connected, e := Connect(h)
	if e != nil || connected {
		t.Fatal("abandoned client not reset", connected, e)
	}
	// The server loop must re-enter listening after disconnecting the instance.
	if connected, e = Connect(h); e != nil || connected {
		t.Fatal("listener not reset", connected, e)
	}
	peer = open()
	defer windows.CloseHandle(peer)
	connected, e = Connect(h)
	if e != nil || !connected {
		t.Fatal("next legitimate client blocked", connected, e)
	}
}
