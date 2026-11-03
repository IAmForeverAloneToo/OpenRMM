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

// imageLimit bounds what is read of a process's main executable image.
const imageLimit = 64 << 20

// processImage reads a process's main executable as mapped in memory, for
// YARA's pe module: the committed, readable regions within it (the rest
// stays zero), at most imageLimit.
func processImage(ctx context.Context, pid uint32) (*yara.Block, error) {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(h)
	// The first module is the program itself.
	var mod windows.Handle
	var need uint32
	if e = windows.EnumProcessModulesEx(h, &mod, uint32(unsafe.Sizeof(mod)), &need, windows.LIST_MODULES_ALL); e != nil {
		return nil, e
	}
	var info windows.ModuleInfo
	if e = windows.GetModuleInformation(h, mod, &info, uint32(unsafe.Sizeof(info))); e != nil {
		return nil, e
	}
	size := min(uintptr(info.SizeOfImage), imageLimit)
	buf := make([]byte, size)
	var mbi windows.MemoryBasicInformation
	for off := uintptr(0); off < size; {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		addr := info.BaseOfDll + off
		if windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)) != nil {
			break
		}
		end := min(mbi.BaseAddress+mbi.RegionSize-info.BaseOfDll, size)
		if end <= off {
			break
		}
		readable := mbi.Protect&0xFF != 0 && mbi.Protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) == 0
		if mbi.State == windows.MEM_COMMIT && readable {
			var got uintptr
			_ = windows.ReadProcessMemory(h, addr, &buf[off], end-off, &got)
		}
		off = end
	}
	return &yara.Block{Base: uint64(info.BaseOfDll), Data: buf}, nil
}

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
