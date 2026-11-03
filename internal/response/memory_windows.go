package response

import (
	"context"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/yara"
)

// Process memory is read (never written) for YARA scans: every committed
// region that allows reading, in chunks, into one reused batch buffer that
// is scanned whenever it is full.
const (
	memoryChunk = 16 << 20
	memoryBatch = 64 << 20
	// memoryLimit bounds what is read of one process.
	memoryLimit = 1 << 30
)

// batches reuses batch buffers between processes.
var batches = sync.Pool{New: func() any { b := make([]byte, memoryBatch); return &b }}

func processMemory(ctx context.Context, pid uint32, fn func([]yara.Block) error) error {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	bp := batches.Get().(*[]byte)
	defer batches.Put(bp)
	buf := *bp
	var blocks []yara.Block
	used, total := 0, 0
	flush := func() error {
		if len(blocks) == 0 {
			return nil
		}
		err := fn(blocks)
		blocks, used = blocks[:0], 0
		return err
	}
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); total < memoryLimit; {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)) != nil {
			break
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		readable := mbi.Protect&0xFF != 0 && mbi.Protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) == 0
		if mbi.State == windows.MEM_COMMIT && readable {
			for off := uintptr(0); off < mbi.RegionSize && total < memoryLimit; {
				if used == len(buf) {
					if err := flush(); err != nil {
						return err
					}
				}
				n := min(uintptr(memoryChunk), mbi.RegionSize-off, uintptr(len(buf)-used))
				var got uintptr
				// A partial copy still returns what was read.
				_ = windows.ReadProcessMemory(h, mbi.BaseAddress+off, &buf[used], n, &got)
				if got > 0 {
					blocks = append(blocks, yara.Block{Base: uint64(mbi.BaseAddress + off), Data: buf[used : used+int(got)]})
					used += int(got)
					total += int(got)
				}
				off += n
			}
		}
		addr = next
	}
	return flush()
}
