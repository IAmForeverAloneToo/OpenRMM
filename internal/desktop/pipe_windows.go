package desktop

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/namedpipe"
)

const PipeName = `\\.\pipe\OpenRMM.Desktop.v1`

var clientSessionProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientSessionId")

func pipeWait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return nil
	}
}
func pipeTransfer(ctx context.Context, h windows.Handle, b []byte, write bool) error {
	for len(b) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var n uint32
		var e error
		// Keep each NOWAIT operation below the pipe's 64-KiB quota. A full
		// image-sized native operation can stall despite a concurrent reader.
		// The frame limit is independent of these transport chunks.
		chunk := b
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		if write {
			e = windows.WriteFile(h, chunk, &n, nil)
		} else {
			e = windows.ReadFile(h, chunk, &n, nil)
		}
		if n > 0 {
			b = b[n:]
		}
		if e != nil && !errors.Is(e, windows.ERROR_NO_DATA) && !errors.Is(e, windows.ERROR_PIPE_LISTENING) {
			return e
		}
		if n == 0 {
			if e = pipeWait(ctx); e != nil {
				return e
			}
		}
	}
	return nil
}
func pipeWrite(ctx context.Context, h windows.Handle, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) == 0 || len(b) > MaxWire {
		return ErrInvalid
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(b)))
	if e = pipeTransfer(ctx, h, header[:], true); e != nil {
		return e
	}
	return pipeTransfer(ctx, h, b, true)
}
func pipeRead(ctx context.Context, h windows.Handle, v any) error {
	var header [4]byte
	if e := pipeTransfer(ctx, h, header[:], false); e != nil {
		return e
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > MaxWire {
		return ErrInvalid
	}
	b := make([]byte, n)
	if e := pipeTransfer(ctx, h, b, false); e != nil {
		return e
	}
	return Decode(b, v)
}
func consolePipe(h windows.Handle) bool {
	var session uint32
	r, _, _ := clientSessionProc.Call(uintptr(h), uintptr(unsafe.Pointer(&session)))
	return r != 0 && session != 0 && session != 0xffffffff && session == windows.WTSGetActiveConsoleSessionId()
}

// ServePipe runs only in the installed SYSTEM service. The pipe is
// owned by SYSTEM, which the companion requires; the interactive ACE excludes
// CREATE_PIPE_INSTANCE. A retained connection binds one console helper
// and one unpredictable peer identity; reconnects cannot resume consent.
func ServePipe(ctx context.Context, exchange func(context.Context, Exchange) (Reply, error)) error {
	sd, e := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;IU)")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(PipeName)
	h, e := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &sa)
	runtime.KeepAlive(sd)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	for ctx.Err() == nil {
		// An abandoned connection is reset so it cannot block later clients.
		connected, e := namedpipe.Connect(h)
		if e != nil {
			return e
		}
		if !connected {
			if pipeWait(ctx) != nil {
				break
			}
			continue
		}
		if consolePipe(h) {
			peer, err := RandomID()
			if err == nil {
				_ = serveCompanion(ctx, h, peer, exchange)
			}
		}
		_ = windows.DisconnectNamedPipe(h)
		// Report absence after every connection, including ambiguous transport loss.
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, _ = exchange(c, Exchange{})
		cancel()
	}
	return nil
}
func serveCompanion(ctx context.Context, h windows.Handle, peer string, exchange func(context.Context, Exchange) (Reply, error)) error {
	for ctx.Err() == nil && consolePipe(h) {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		var p Exchange
		e := pipeRead(c, h, &p)
		if e == nil {
			p.Ready = true
			p.Peer = peer
			if !p.Valid() {
				e = ErrInvalid
			} else {
				var r Reply
				r, e = exchange(c, p)
				if e == nil {
					e = pipeWrite(c, h, r)
				}
			}
		}
		cancel()
		if e != nil {
			return e
		}
	}
	return ctx.Err()
}
func agentPipe() (windows.Handle, error) {
	p, _ := windows.UTF16PtrFromString(PipeName)
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.FILE_WRITE_DATA|windows.FILE_WRITE_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if e != nil {
		return 0, e
	}
	valid := false
	defer func() {
		if !valid {
			windows.CloseHandle(h)
		}
	}()
	sd, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return 0, e
	}
	owner, _, e := sd.Owner()
	if e != nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return 0, ErrUnavailable
	}
	var pid uint32
	if e = windows.GetNamedPipeServerProcessId(h, &pid); e != nil {
		return 0, e
	}
	scm, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return 0, e
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString("OpenRMMAgent")
	svc, e := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return 0, e
	}
	defer windows.CloseServiceHandle(svc)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	e = windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	if e != nil || status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 || status.ProcessId != pid {
		return 0, ErrUnavailable
	}
	mode := uint32(windows.PIPE_NOWAIT)
	if e = windows.SetNamedPipeHandleState(h, &mode, nil, nil); e != nil {
		return 0, e
	}
	valid = true
	return h, nil
}
