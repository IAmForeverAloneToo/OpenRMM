package isolation

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

// Windows Filtering Platform enforcer. NOT YET VERIFIED: it runs only when
// Enforce is true, which waits for a test on a disposable VM. It adds a
// persistent provider and sublayer
// (highest weight) with permit filters for the planned rules and block
// filters for everything else, at the ALE connect and receive/accept
// layers for IPv4 and IPv6. Persistent filters survive a restart of the
// agent and of Windows; Remove deletes them by their fixed keys, so a
// separate process (the break-glass command) can remove them too.

var (
	fwpuclnt                       = windows.NewLazySystemDLL("fwpuclnt.dll")
	procEngineOpen                 = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose                = fwpuclnt.NewProc("FwpmEngineClose0")
	procTransactionBegin           = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procTransactionCommit          = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procTransactionAbort           = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procProviderAdd                = fwpuclnt.NewProc("FwpmProviderAdd0")
	procProviderDeleteByKey        = fwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procSubLayerAdd                = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procSubLayerDeleteByKey        = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFilterAdd                  = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFilterDeleteByKey          = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	providerKey                    = windows.GUID{Data1: 0x4f70656e, Data2: 0x524d, Data3: 0x4d49, Data4: [8]byte{0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x00, 0x01}}
	subLayerKey                    = windows.GUID{Data1: 0x4f70656e, Data2: 0x524d, Data3: 0x4d49, Data4: [8]byte{0x73, 0x6f, 0x6c, 0x61, 0x74, 0x65, 0x00, 0x02}}
	layerConnectV4                 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerConnectV6                 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerAcceptV4                  = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerAcceptV6                  = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}
	conditionRemoteAddress         = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	conditionRemotePort            = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	conditionProtocol              = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	conditionLocalPort             = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	errFilterNotFound              = windows.Errno(0x80320003)
	errProviderNotFound            = windows.Errno(0x80320005)
	errSubLayerNotFound            = windows.Errno(0x80320007)
	errAlreadyExists               = windows.Errno(0x80320009)
	maxFilters                     = 2048
	rpcAuthnWinNT           uint32 = 10
)

const (
	fwpUint8       = 1
	fwpUint16      = 2
	fwpUint32      = 3
	fwpV4AddrMask  = 0x100
	fwpV6AddrMask  = 0x101
	actionBlock    = 0x1001
	actionPermit   = 0x1002
	flagPersistent = 1
)

type displayData struct{ name, description *uint16 }
type byteBlob struct {
	size uint32
	data *byte
}
type provider struct {
	key          windows.GUID
	display      displayData
	flags        uint32
	providerData byteBlob
	serviceName  *uint16
}
type subLayer struct {
	key          windows.GUID
	display      displayData
	flags        uint32
	providerKey  *windows.GUID
	providerData byteBlob
	weight       uint16
}

// value is FWP_VALUE0 / FWP_CONDITION_VALUE0: a type and an 8-byte union.
type value struct {
	kind uint32
	data uint64
}
type condition struct {
	field     windows.GUID
	matchType uint32
	value     value
}
type action struct {
	kind uint32
	key  windows.GUID
}
type filter struct {
	key             windows.GUID
	display         displayData
	flags           uint32
	providerKey     *windows.GUID
	providerData    byteBlob
	layer           windows.GUID
	subLayer        windows.GUID
	weight          value
	numConditions   uint32
	conditions      *condition
	action          action
	context         [2]uint64
	reserved        *windows.GUID
	filterID        uint64
	effectiveWeight value
}
type v4Mask struct{ addr, mask uint32 }
type v6Mask struct {
	addr   [16]byte
	prefix uint8
}

func check(r uintptr) error {
	if r != 0 {
		return windows.Errno(r)
	}
	return nil
}

func filterKey(n int) windows.GUID {
	k := providerKey
	k.Data4[6], k.Data4[7] = byte(0x10+n>>8), byte(n)
	return k
}

type wfp struct{}

// newPlatformEnforcer: the structures above mirror the 64-bit layout (the
// value union holds a pointer), so other architectures stay a dry run.
func newPlatformEnforcer() Enforcer {
	if runtime.GOARCH != "amd64" {
		return &DryRun{}
	}
	return wfp{}
}

func (wfp) Mode() string { return "enforced" }

func open() (uintptr, error) {
	if e := fwpuclnt.Load(); e != nil {
		return 0, e
	}
	var h uintptr
	r, _, _ := procEngineOpen.Call(0, uintptr(rpcAuthnWinNT), 0, 0, uintptr(unsafe.Pointer(&h)))
	if e := check(r); e != nil {
		return 0, fmt.Errorf("open the filtering engine: %w", e)
	}
	return h, nil
}

// Remove deletes every filter, the sublayer and the provider (missing ones
// are fine).
func (wfp) Remove() error {
	h, e := open()
	if e != nil {
		return e
	}
	defer procEngineClose.Call(h)
	for n := 0; n < maxFilters; n++ {
		k := filterKey(n)
		r, _, _ := procFilterDeleteByKey.Call(h, uintptr(unsafe.Pointer(&k)))
		if e := check(r); e != nil && !errors.Is(e, errFilterNotFound) {
			return fmt.Errorf("delete filter %d: %w", n, e)
		}
	}
	r, _, _ := procSubLayerDeleteByKey.Call(h, uintptr(unsafe.Pointer(&subLayerKey)))
	if e := check(r); e != nil && !errors.Is(e, errSubLayerNotFound) {
		return fmt.Errorf("delete the sublayer: %w", e)
	}
	r, _, _ = procProviderDeleteByKey.Call(h, uintptr(unsafe.Pointer(&providerKey)))
	if e := check(r); e != nil && !errors.Is(e, errProviderNotFound) {
		return fmt.Errorf("delete the provider: %w", e)
	}
	return nil
}

// Apply replaces any isolation filters with the planned ones in one
// transaction: the old filters are deleted and the new ones added together,
// so a failure leaves the previous filters in force.
func (w wfp) Apply(rules []protocol.IsolationRule) error {
	h, e := open()
	if e != nil {
		return e
	}
	defer procEngineClose.Call(h)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e = check(first(procTransactionBegin.Call(h, 0))); e != nil {
		return fmt.Errorf("begin: %w", e)
	}
	committed := false
	defer func() {
		if !committed {
			procTransactionAbort.Call(h)
		}
	}()
	// Everything the structures point at (also through the integers of the
	// condition values) is pinned until the transaction ends.
	var pin runtime.Pinner
	defer pin.Unpin()
	name, _ := windows.UTF16PtrFromString("OpenRMM network isolation")
	pin.Pin(name)
	p := provider{key: providerKey, display: displayData{name: name}, flags: flagPersistent}
	if e = check(first(procProviderAdd.Call(h, uintptr(unsafe.Pointer(&p)), 0))); e != nil && !errors.Is(e, errAlreadyExists) {
		return fmt.Errorf("add the provider: %w", e)
	}
	pk := new(windows.GUID)
	*pk = providerKey
	pin.Pin(pk)
	s := subLayer{key: subLayerKey, display: displayData{name: name}, flags: flagPersistent, providerKey: pk, weight: 0xffff}
	if e = check(first(procSubLayerAdd.Call(h, uintptr(unsafe.Pointer(&s)), 0))); e != nil && !errors.Is(e, errAlreadyExists) {
		return fmt.Errorf("add the sublayer: %w", e)
	}
	for k := 0; k < maxFilters; k++ {
		key := filterKey(k)
		if e = check(first(procFilterDeleteByKey.Call(h, uintptr(unsafe.Pointer(&key))))); e != nil && !errors.Is(e, errFilterNotFound) {
			return fmt.Errorf("delete filter %d: %w", k, e)
		}
	}
	n := 0
	add := func(layer windows.GUID, kind uint32, weight uint64, conds []condition) error {
		if n >= maxFilters {
			return errors.New("too many isolation filters")
		}
		f := filter{key: filterKey(n), display: displayData{name: name}, flags: flagPersistent, providerKey: pk, layer: layer, subLayer: subLayerKey,
			weight: value{kind: fwpUint8, data: weight}, numConditions: uint32(len(conds)), action: action{kind: kind}}
		if len(conds) > 0 {
			pin.Pin(&conds[0])
			f.conditions = &conds[0]
		}
		var id uint64
		r, _, _ := procFilterAdd.Call(h, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
		n++
		return check(r)
	}
	for _, r := range rules {
		p, e := netip.ParsePrefix(r.Remote)
		if e != nil {
			return e
		}
		addr := condition{field: conditionRemoteAddress}
		if p.Addr().Is4() {
			b := p.Addr().As4()
			v4 := &v4Mask{addr: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])}
			if p.Bits() > 0 {
				v4.mask = ^uint32(0) << (32 - p.Bits())
			}
			pin.Pin(v4)
			addr.value = value{kind: fwpV4AddrMask, data: uint64(uintptr(unsafe.Pointer(v4)))}
		} else {
			v6 := &v6Mask{addr: p.Addr().As16(), prefix: uint8(p.Bits())}
			pin.Pin(v6)
			addr.value = value{kind: fwpV6AddrMask, data: uint64(uintptr(unsafe.Pointer(v6)))}
		}
		conds := []condition{addr}
		switch r.Protocol {
		case "tcp":
			conds = append(conds, condition{field: conditionProtocol, value: value{kind: fwpUint8, data: 6}})
		case "udp":
			conds = append(conds, condition{field: conditionProtocol, value: value{kind: fwpUint8, data: 17}})
		}
		if r.Port > 0 {
			conds = append(conds, condition{field: conditionRemotePort, value: value{kind: fwpUint16, data: uint64(r.Port)}})
		}
		if r.LocalPort > 0 {
			conds = append(conds, condition{field: conditionLocalPort, value: value{kind: fwpUint16, data: uint64(r.LocalPort)}})
		}
		layers := []windows.GUID{layerConnectV4}
		if !p.Addr().Is4() {
			layers = []windows.GUID{layerConnectV6}
		}
		if r.Direction == "both" {
			if p.Addr().Is4() {
				layers = append(layers, layerAcceptV4)
			} else {
				layers = append(layers, layerAcceptV6)
			}
		}
		for _, l := range layers {
			if e = add(l, actionPermit, 15, conds); e != nil {
				return fmt.Errorf("add a permit filter: %w", e)
			}
		}
	}
	for _, l := range []windows.GUID{layerConnectV4, layerConnectV6, layerAcceptV4, layerAcceptV6} {
		if e = add(l, actionBlock, 0, nil); e != nil {
			return fmt.Errorf("add a block filter: %w", e)
		}
	}
	if e = check(first(procTransactionCommit.Call(h))); e != nil {
		return fmt.Errorf("commit: %w", e)
	}
	committed = true
	return nil
}

func first(r, _ uintptr, _ error) uintptr { return r }
