package agentupdate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/namedpipe"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"runtime"
	"time"
	"unsafe"
)

const PipeName = `\\.\pipe\OpenRMM.AgentUpdater.v1`

type pipeAdapter struct{}

func NewClient() Client { return pipeAdapter{} }
func nap(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return nil
	}
}
func transfer(ctx context.Context, h windows.Handle, b []byte, write bool) error {
	for len(b) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var n uint32
		var e error
		if write {
			e = windows.WriteFile(h, b, &n, nil)
		} else {
			e = windows.ReadFile(h, b, &n, nil)
		}
		if n > 0 {
			b = b[n:]
		}
		if e != nil && !errors.Is(e, windows.ERROR_NO_DATA) && !errors.Is(e, windows.ERROR_PIPE_LISTENING) {
			return e
		}
		if n == 0 {
			if e = nap(ctx); e != nil {
				return e
			}
		}
	}
	return nil
}
func readFrame(ctx context.Context, h windows.Handle, max int) ([]byte, error) {
	var header [4]byte
	if e := transfer(ctx, h, header[:], false); e != nil {
		return nil, e
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > uint32(max) {
		return nil, ErrInvalid
	}
	b := make([]byte, n)
	return b, transfer(ctx, h, b, false)
}
func writeFrame(ctx context.Context, h windows.Handle, b []byte) error {
	if len(b) > MaxIPC {
		return ErrInvalid
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(b)))
	if e := transfer(ctx, h, header[:], true); e != nil {
		return e
	}
	return transfer(ctx, h, b, true)
}
func callBroker(ctx context.Context, r IPCRequest) (IPCReply, error) {
	var reply IPCReply
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	p, _ := windows.UTF16PtrFromString(PipeName)
	var h windows.Handle
	var e error
	for {
		h, e = windows.CreateFile(p, windows.GENERIC_READ|windows.FILE_WRITE_DATA|windows.FILE_WRITE_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if !errors.Is(e, windows.ERROR_PIPE_BUSY) {
			break
		}
		if e = nap(ctx); e != nil {
			return reply, e
		}
	}
	if e != nil {
		return reply, e
	}
	defer windows.CloseHandle(h)
	// A restricted LocalService token cannot necessarily query a SYSTEM process
	// token. Authenticate the pipe object itself: an unprivileged creator cannot
	// set its owner to SYSTEM. The handle pins that same pipe for the exchange.
	sd, e := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return reply, e
	}
	owner, _, e := sd.Owner()
	if e != nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return reply, ErrInvalid
	}
	mode := uint32(windows.PIPE_NOWAIT)
	if e = windows.SetNamedPipeHandleState(h, &mode, nil, nil); e != nil {
		return reply, e
	}
	b, _ := json.Marshal(r)
	if len(b) > MaxIPC {
		return reply, ErrInvalid
	}
	if e = writeFrame(ctx, h, b); e != nil {
		return reply, e
	}
	b, e = readFrame(ctx, h, MaxIPC)
	if e != nil {
		return reply, e
	}
	if e = Decode(b, &reply); e != nil {
		return reply, e
	}
	e = transfer(ctx, h, []byte{1}, true)
	return reply, e
}

// ServePipe has a single, nonblocking, remote-client-rejecting pipe instance.
// The client ACE omits FILE_CREATE_PIPE_INSTANCE. Only the installed agent's
// service SID can connect; LocalService as a general identity is not granted.
func ServePipe(ctx context.Context, b *Broker, agentSID string) error {
	if _, e := windows.StringToSid(agentSID); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;" + agentSID + ")")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(PipeName)
	h, e := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, MaxIPC+4, MaxIPC+4, 0, &sa)
	runtime.KeepAlive(sd)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	for ctx.Err() == nil {
		connected, e := namedpipe.Connect(h)
		if e != nil {
			return e
		}
		if !connected {
			if nap(ctx) != nil {
				break
			}
			continue
		}
		requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		raw, err := readFrame(requestCtx, h, MaxIPC)
		if err == nil {
			var req IPCRequest
			if Decode(raw, &req) == nil {
				var pid uint32
				if windows.GetNamedPipeClientProcessId(h, &pid) != nil {
					cancel()
					_ = windows.DisconnectNamedPipe(h)
					continue
				}
				reply := b.Handle(req, pid)
				data, err := json.Marshal(reply)
				if err == nil && writeFrame(requestCtx, h, data) == nil {
					var ack [1]byte
					_ = transfer(requestCtx, h, ack[:], false)
				}
			}
		}
		cancel()
		_ = windows.DisconnectNamedPipe(h)
	}
	return nil
}

// probe asks a running helper; an error means none is reachable.
func (pipeAdapter) probe(ctx context.Context) (protocol.AgentUpgradeSupport, error) {
	r, e := callBroker(ctx, IPCRequest{Op: "probe"})
	if e != nil || r.Support == nil || r.Error != "" || !SupportValid(*r.Support) {
		return protocol.AgentUpgradeSupport{}, ErrInvalid
	}
	return *r.Support, nil
}
func (pipeAdapter) Probe(ctx context.Context) (protocol.AgentUpgradeSupport, error) {
	r, e := callBroker(ctx, IPCRequest{Op: "probe"})
	if e != nil {
		status := "missing"
		if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
			status = "denied"
		}
		return protocol.AgentUpgradeSupport{Broker: status, CurrentHash: string(makeHashZero()), KeyIDs: []string{}}, nil
	}
	if r.Support == nil || r.Error != "" || !SupportValid(*r.Support) {
		return protocol.AgentUpgradeSupport{}, ErrInvalid
	}
	return *r.Support, nil
}
func makeHashZero() string { return "0000000000000000000000000000000000000000000000000000000000000000" }
func (pipeAdapter) Submit(ctx context.Context, q protocol.AgentUpgradeJob) (protocol.AgentUpgradeResult, error) {
	r, e := callBroker(ctx, IPCRequest{Op: "submit", Job: &q})
	if e != nil || r.Result == nil {
		return protocol.AgentUpgradeResult{}, ErrInvalid
	}
	return *r.Result, nil
}
func (pipeAdapter) Status(ctx context.Context, id string) (protocol.AgentUpgradeResult, error) {
	r, e := callBroker(ctx, IPCRequest{Op: "status", ID: id})
	if e != nil || r.Result == nil {
		return protocol.AgentUpgradeResult{}, ErrInvalid
	}
	return *r.Result, nil
}
func (pipeAdapter) Healthy(ctx context.Context, version string) error {
	r, e := callBroker(ctx, IPCRequest{Op: "healthy", Version: version})
	if r.Error != "" {
		return ErrInvalid
	}
	return e
}
