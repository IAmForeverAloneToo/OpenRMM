package processes

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// native runs inside the SYSTEM agent. Any process passing the
// self-protection and critical-process checks may be ended; server-side
// permissions decide who may ask. There is no local delegation list.
type native struct{}

func NewAdapter() Adapter { return native{} }

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var memoryInfo = kernel.NewProc("K32GetProcessMemoryInfo")
var isCritical = kernel.NewProc("IsProcessCritical")
var groupCount = kernel.NewProc("GetActiveProcessorGroupCount")

type memoryCounters struct {
	Size, Faults                                                                    uint32
	Peak, Working, PeakPaged, Paged, PeakNonPaged, NonPaged, Pagefile, PeakPagefile uintptr
}

func filetime(v windows.Filetime) uint64 { return uint64(v.HighDateTime)<<32 | uint64(v.LowDateTime) }
func counters(h windows.Handle) (string, uint64, error) {
	var c, e, k, u windows.Filetime
	err := windows.GetProcessTimes(h, &c, &e, &k, &u)
	if err != nil {
		return "", 0, err
	}
	return strconv.FormatUint(filetime(c), 10), filetime(k) + filetime(u), nil
}
func imageName(h windows.Handle) (string, error) {
	var b [32768]uint16
	n := uint32(len(b))
	if e := windows.QueryFullProcessImageName(h, 0, &b[0], &n); e != nil {
		return "", e
	}
	return filepath.Base(windows.UTF16ToString(b[:n])), nil
}
func safe(h windows.Handle, pid uint32, name string) bool {
	if !Manageable(pid, name) || pid == uint32(os.Getpid()) || isCritical.Find() != nil {
		return false
	}
	actual, e := imageName(h)
	if e != nil || !strings.EqualFold(actual, name) || !Manageable(pid, actual) {
		return false
	}
	var critical uint32
	r, _, _ := isCritical.Call(uintptr(h), uintptr(unsafe.Pointer(&critical)))
	return r != 0 && critical == 0
}

// maxListed bounds the raw Toolhelp listing held before Bound selects the
// snapshot; anything past it is only counted.
const maxListed = 1 << 16

// enumerate lists processes and bounds them. Invalid names and processes over
// the limits are counted as skipped instead of failing the snapshot.
func enumerate(ctx context.Context, priority func(protocol.Process) bool) ([]protocol.Process, int, error) {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, 0, e
	}
	defer windows.CloseHandle(h)
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	e = windows.Process32First(h, &p)
	items := []protocol.Process{}
	over := 0
	for e == nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		if len(items) < maxListed {
			items = append(items, protocol.Process{PID: p.ProcessID, Name: windows.UTF16ToString(p.ExeFile[:])})
		} else {
			over++
		}
		e = windows.Process32Next(h, &p)
	}
	if !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return nil, 0, e
	}
	items, skipped := Bound(items, priority)
	return items, min(skipped+over, MaxSkipped), nil
}

type sample struct {
	start string
	ticks uint64
	at    time.Time
}

func sampleOne(pid uint32) (sample, *uint64) {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return sample{}, nil
	}
	defer windows.CloseHandle(h)
	start, ticks, e := counters(h)
	if e != nil {
		return sample{}, nil
	}
	s := sample{start, ticks, time.Now()}
	var mem *uint64
	c := memoryCounters{Size: uint32(unsafe.Sizeof(memoryCounters{}))}
	if memoryInfo.Find() == nil {
		r, _, _ := memoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.Size))
		if r != 0 {
			v := uint64(c.Working)
			mem = &v
		}
	}
	return s, mem
}
func (n native) Collect(ctx context.Context) (protocol.Processes, error) {
	v := protocol.Processes{Coverage: Coverage, Items: []protocol.Process{}}
	first, _, e := enumerate(ctx, nil)
	if e != nil {
		return v, e
	}
	before := map[uint32]sample{}
	for _, p := range first {
		if ctx.Err() != nil {
			return v, ctx.Err()
		}
		s, _ := sampleOne(p.PID)
		if s.start != "" {
			before[p.PID] = s
		}
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return v, ctx.Err()
	case <-timer.C:
	}
	v.Items, v.Skipped, e = enumerate(ctx, nil)
	if e != nil {
		return v, e
	}
	processors := windows.GetActiveProcessorCount(0)
	if groupCount.Find() != nil {
		processors = 0
	} else {
		groups, _, _ := groupCount.Call()
		if groups != 1 {
			processors = 0
		}
	}
	for i := range v.Items {
		if ctx.Err() != nil {
			return v, ctx.Err()
		}
		p := &v.Items[i]
		s, mem := sampleOne(p.PID)
		p.Start = s.start
		p.Memory = mem
		if b, ok := before[p.PID]; ok && b.start == s.start {
			p.CPU = CPU(b.ticks, s.ticks, s.at.Sub(b.at), processors)
		}
		if Manageable(p.PID, p.Name) {
			h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, p.PID)
			if e == nil {
				start, _, e := counters(h)
				p.CanTerminate = e == nil && start == p.Start && safe(h, p.PID, p.Name)
				windows.CloseHandle(h)
			}
		}
	}
	return v, nil
}
func (n native) Execute(ctx context.Context, a protocol.ProcessAction) protocol.ProcessResult {
	r := protocol.ProcessResult{ID: a.ID, Outcome: "denied"}
	if !Manageable(a.PID, a.Name) || !Start(a.Start) {
		return r
	}
	if ctx.Err() != nil {
		r.Outcome = "interrupted"
		return r
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, a.PID)
	if e != nil {
		if errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
			r.Outcome = "not_found"
		}
		return r
	}
	defer windows.CloseHandle(h)
	start, _, e := counters(h)
	if e != nil {
		return r
	}
	if start != a.Start {
		r.Outcome = "identity_changed"
		return r
	}
	if !safe(h, a.PID, a.Name) {
		return r
	}
	// The retained handle prevents PID reuse between validation, termination
	// and observed completion.
	if ctx.Err() != nil {
		r.Outcome = "interrupted"
		return r
	}
	if e = windows.TerminateProcess(h, 1); e != nil {
		r.Outcome = "failed"
		return r
	}
	for {
		state, e := windows.WaitForSingleObject(h, 50)
		if e != nil {
			r.Outcome = "failed"
			return r
		}
		if state == windows.WAIT_OBJECT_0 {
			r.Outcome = "succeeded"
			return r
		}
		if ctx.Err() != nil {
			r.Outcome = "timed_out"
			return r
		}
	}
}
