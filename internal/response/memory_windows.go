package response

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/yara"
)

// Process memory is read (never written) for YARA scans: every committed
// region that allows reading, in chunks, handed over in batches so the
// agent holds at most one batch at a time.
const (
	memoryChunk = 16 << 20
	memoryBatch = 64 << 20
	// memoryLimit bounds what is read of one process.
	memoryLimit = 1 << 30
)

func processMemory(ctx context.Context, pid uint32, fn func([]yara.Block) error) error {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	var blocks []yara.Block
	size, total := 0, 0
	flush := func() error {
		if len(blocks) == 0 {
			return nil
		}
		err := fn(blocks)
		blocks, size = nil, 0
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
			for off := uintptr(0); off < mbi.RegionSize && total < memoryLimit; off += memoryChunk {
				n := min(uintptr(memoryChunk), mbi.RegionSize-off)
				buf := make([]byte, n)
				var got uintptr
				// A partial copy still returns what was read.
				_ = windows.ReadProcessMemory(h, mbi.BaseAddress+off, &buf[0], n, &got)
				if got == 0 {
					continue
				}
				blocks = append(blocks, yara.Block{Base: uint64(mbi.BaseAddress + off), Data: buf[:got]})
				size += int(got)
				total += int(got)
				if size >= memoryBatch {
					if err := flush(); err != nil {
						return err
					}
				}
			}
		}
		addr = next
	}
	return flush()
}
