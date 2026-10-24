package windowsupdate

import (
	"context"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// This deliberately small Automation binding is private to WUA. All objects,
// variants and BSTRs stay on one locked OS thread and have explicit ownership.
// Windows x64 only: VARIANT is 24 bytes (the BRECORD union has two pointers).
var ole32 = windows.NewLazySystemDLL("ole32.dll")
var oleaut = windows.NewLazySystemDLL("oleaut32.dll")
var coInit = ole32.NewProc("CoInitializeEx")
var coUninit = ole32.NewProc("CoUninitialize")
var clsidFrom = ole32.NewProc("CLSIDFromProgID")
var coCreate = ole32.NewProc("CoCreateInstance")
var variantClear = oleaut.NewProc("VariantClear")
var allocString = oleaut.NewProc("SysAllocStringLen")
var stringLen = oleaut.NewProc("SysStringLen")

type variant struct {
	VT       uint16
	Reserved [3]uint16
	Value    uintptr
	Extra    uintptr
}
type dispatch struct{ VTable *[7]uintptr }

// Read the pointer member of the native VARIANT union only after checking VT.
// Numeric VARIANT members are never converted to pointers.
func (v *variant) pointer() unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&v.Value)) }

type params struct {
	Args              *variant
	Named             *int32
	Count, NamedCount uint32
}
type hresult uint32

func (h hresult) Error() string { return fmt.Sprintf("Windows Update HRESULT 0x%08x", uint32(h)) }
func checkHR(r uintptr) {
	if int32(r) < 0 {
		panic(hresult(uint32(r)))
	}
}
func (d *dispatch) release() { syscall.SyscallN(d.VTable[2], uintptr(unsafe.Pointer(d))) }
func (v *variant) clear()    { variantClear.Call(uintptr(unsafe.Pointer(v))) }
func (v *variant) number() int {
	if v.VT != 3 && v.VT != 22 {
		panic(ErrInvalid)
	}
	return int(int32(v.Value))
}
func (v *variant) boolean() bool {
	if v.VT != 11 {
		panic(ErrInvalid)
	}
	return int16(v.Value) != 0
}
func (v *variant) text(max int) string {
	if v.VT == 0 || v.VT == 1 {
		return ""
	}
	if v.VT != 8 {
		panic(ErrInvalid)
	}
	if v.Value == 0 {
		return ""
	}
	n, _, _ := stringLen.Call(v.Value)
	if n > 1024*1024 {
		panic(ErrInvalid)
	}
	// Control characters in WUA text are replaced, not fatal (see Sanitize).
	s := Sanitize(string(utf16.Decode(unsafe.Slice((*uint16)(v.pointer()), int(n)))))
	if len(s) > max {
		s = s[:max]
		for !text(s, max) {
			s = s[:len(s)-1]
		}
	}
	if !text(s, max) {
		panic(ErrInvalid)
	}
	return s
}

type apartment struct{ objects []*dispatch }

func (a *apartment) close() {
	for i := len(a.objects) - 1; i >= 0; i-- {
		a.objects[i].release()
	}
}
func (a *apartment) object(v variant) *dispatch {
	if v.VT != 9 || v.Value == 0 {
		v.clear()
		panic(ErrInvalid)
	}
	d := (*dispatch)(v.pointer())
	a.objects = append(a.objects, d)
	return d
}
func (a *apartment) create(name string) *dispatch {
	p, e := windows.UTF16PtrFromString(name)
	if e != nil {
		panic(e)
	}
	var cls windows.GUID
	r, _, _ := clsidFrom.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&cls)))
	checkHR(r)
	iid := windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	var d *dispatch
	r, _, _ = coCreate.Call(uintptr(unsafe.Pointer(&cls)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&d)))
	checkHR(r)
	if d == nil {
		panic(ErrInvalid)
	}
	a.objects = append(a.objects, d)
	return d
}
func arg(v any) variant {
	switch x := v.(type) {
	case int:
		return variant{VT: 3, Value: uintptr(int64(x))}
	case bool:
		if x {
			return variant{VT: 11, Value: 65535}
		}
		return variant{VT: 11}
	case *dispatch:
		syscall.SyscallN(x.VTable[1], uintptr(unsafe.Pointer(x)))
		return variant{VT: 9, Value: uintptr(unsafe.Pointer(x))}
	case string:
		w := utf16.Encode([]rune(x))
		var p *uint16
		if len(w) > 0 {
			p = &w[0]
		}
		r, _, _ := allocString.Call(uintptr(unsafe.Pointer(p)), uintptr(len(w)))
		if r == 0 {
			panic(ErrInvalid)
		}
		runtime.KeepAlive(w)
		return variant{VT: 8, Value: r}
	}
	panic(ErrInvalid)
}
func (d *dispatch) invoke(name string, flags uint16, values ...any) variant {
	w, e := windows.UTF16PtrFromString(name)
	if e != nil {
		panic(e)
	}
	var id int32
	var zero windows.GUID
	r, _, _ := syscall.SyscallN(d.VTable[5], uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&zero)), uintptr(unsafe.Pointer(&w)), 1, 0x409, uintptr(unsafe.Pointer(&id)))
	checkHR(r)
	args := make([]variant, len(values))
	defer func() {
		for i := range args {
			args[i].clear()
		}
	}()
	for i, v := range values {
		args[len(values)-1-i] = arg(v)
	}
	p := params{Count: uint32(len(args))}
	if len(args) > 0 {
		p.Args = &args[0]
	}
	named := int32(-3)
	if flags == 4 {
		p.Named = &named
		p.NamedCount = 1
	}
	var out variant
	// EXCEPINFO contains three owned BSTRs on x64; clear even on Invoke failure.
	var ex struct {
		Code, Reserved            uint16
		Source, Description, Help uintptr
		Context                   uint32
		Reserved2, Deferred       uintptr
		SCode                     int32
	}
	r, _, _ = syscall.SyscallN(d.VTable[6], uintptr(unsafe.Pointer(d)), uintptr(uint32(id)), uintptr(unsafe.Pointer(&zero)), 0x409, uintptr(flags), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&out)), uintptr(unsafe.Pointer(&ex)), 0)
	for _, b := range []uintptr{ex.Source, ex.Description, ex.Help} {
		if b != 0 {
			v := variant{VT: 8, Value: b}
			v.clear()
		}
	}
	if int32(r) < 0 {
		out.clear()
		if uint32(r) == 0x80020009 && ex.SCode != 0 {
			panic(hresult(uint32(ex.SCode)))
		}
		checkHR(r)
	}
	return out
}
func (d *dispatch) get(name string, values ...any) variant { return d.invoke(name, 3, values...) }
func (d *dispatch) set(name string, value any)             { v := d.invoke(name, 4, value); v.clear() }
func (d *dispatch) str(name string, n int, args ...any) string {
	v := d.get(name, args...)
	defer v.clear()
	return v.text(n)
}
func (d *dispatch) num(name string) int  { v := d.get(name); defer v.clear(); return v.number() }
func (d *dispatch) yes(name string) bool { v := d.get(name); defer v.clear(); return v.boolean() }
func (a *apartment) child(d *dispatch, name string, args ...any) *dispatch {
	return a.object(d.get(name, args...))
}
func (a *apartment) describe(d *dispatch) protocol.WindowsUpdate {
	i := a.child(d, "Identity")
	u := protocol.WindowsUpdate{UpdateIdentity: protocol.UpdateIdentity{ID: strings.ToLower(i.str("UpdateID", 36)), Revision: i.num("RevisionNumber")}, Title: d.str("Title", 512), Description: d.str("Description", 1024), Severity: d.str("MsrcSeverity", 64), KB: []string{}}
	kb := a.child(d, "KBArticleIDs")
	n := kb.num("Count")
	if n < 0 || n > 16 {
		panic(ErrInvalid)
	}
	for j := 0; j < n; j++ {
		u.KB = append(u.KB, kb.str("Item", 16, j))
	}
	if !d.yes("EulaAccepted") {
		u.Blocked = "license_required"
	}
	behavior := a.child(d, "InstallationBehavior")
	if behavior.yes("CanRequestUserInput") {
		u.Blocked = "interactive"
	}
	cs := a.child(d, "Categories")
	n = cs.num("Count")
	if n < 0 || n > 100 {
		panic(ErrInvalid)
	}
	for j := 0; j < n; j++ {
		c := a.child(cs, "Item", j)
		if strings.EqualFold(c.str("CategoryID", 36), "3689bdc8-b205-4af4-8d4a-a63924c5e9d5") {
			u.Blocked = "upgrade"
		}
	}
	if !ItemValid(u) {
		panic(ErrInvalid)
	}
	return u
}

// tryDescribe describes one search result, reporting false when its metadata
// cannot be represented (ErrInvalid) so the caller can skip it. COM failures
// and other panics still fail the job.
func (a *apartment) tryDescribe(us *dispatch, j int) (u protocol.WindowsUpdate, d *dispatch, ok bool) {
	defer func() {
		if v := recover(); v != nil {
			if e, isErr := v.(error); !isErr || e != ErrInvalid {
				panic(v)
			}
			ok = false
		}
	}()
	d = a.child(us, "Item", j)
	return a.describe(d), d, true
}
func outcome(code int) string {
	if code == 2 {
		return "ok"
	}
	return "failed"
}

// NativeRun is invoked only in the fixed broker worker process. Killing a stuck
// worker cannot undo an update already accepted by Windows; report Unknown.
func NativeRun(ctx context.Context, q protocol.UpdateJob, emit func(protocol.UpdateProgress) error) {
	p := initial(q)
	defer func() {
		if v := recover(); v != nil {
			p.Phase = "finished"
			p.Catalog = nil
			p.Truncated = false
			p.Skipped = 0
			p.Outcome = "failed"
			if h, ok := v.(hresult); ok {
				p.HResult = uint32(h)
				if uint32(h) == 0x80070005 {
					p.Outcome = "denied"
				}
			} else {
				p.Outcome = "unknown"
			}
			_ = emit(p)
		}
	}()
	send := func() {
		if ctx.Err() != nil {
			panic(ctx.Err())
		}
		if e := emit(p); e != nil {
			panic(e)
		}
	}
	if !JobValid(q) {
		panic(ErrInvalid)
	}
	var windowDeadline time.Time
	if q.WindowEnd != 0 {
		at := time.Now()
		windowDeadline = at.Add(time.Unix(q.WindowEnd, 0).Sub(at))
	}
	within := func() bool {
		if WindowAllows(q, time.Now()) && (windowDeadline.IsZero() || time.Now().Before(windowDeadline)) {
			return true
		}
		p.Phase = "finished"
		p.Outcome = "blocked"
		if p.Completed > 0 {
			p.Outcome = "partial"
		}
		send()
		return false
	}
	if !within() {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, _ := coInit.Call(0, 2)
	checkHR(r)
	defer coUninit.Call()
	a := &apartment{}
	defer a.close()
	info := a.create("Microsoft.Update.SystemInfo")
	p.RebootRequired = info.yes("RebootRequired")
	p.RebootKnown = true
	if q.Action == "restart" {
		if !p.RebootRequired {
			p = Failure(q, "blocked")
			p.RebootKnown = true
			send()
			return
		}
		if !within() {
			return
		}
		if e := scheduleRestart(); e != nil {
			panic(e)
		}
		p.Phase = "finished"
		p.Outcome = "restart_scheduled"
		send()
		return
	}
	session := a.create("Microsoft.Update.Session")
	session.set("ClientApplicationID", "OpenRMM")
	search := a.child(session, "CreateUpdateSearcher")
	search.set("ServerSelection", 0)
	search.set("CanAutomaticallyUpgradeService", false)
	p.Phase = "searching"
	send()
	if q.Action == "scan" {
		if !within() {
			return
		}
		res := a.child(search, "Search", "IsInstalled=0 and IsHidden=0 and Type='Software'")
		if res.num("ResultCode") != 2 {
			panic(ErrInvalid)
		}
		us := a.child(res, "Updates")
		n := us.num("Count")
		if n < 0 || n > MaxScanned {
			panic(ErrInvalid)
		}
		// One update with unrepresentable metadata is skipped and counted.
		p.Catalog, p.Truncated, p.Skipped = BuildCatalog(n, func(j int) (protocol.WindowsUpdate, bool) {
			u, _, ok := a.tryDescribe(us, j)
			return u, ok
		})
		p.RebootRequired = info.yes("RebootRequired")
		p.Phase = "finished"
		p.Outcome = "ok"
		send()
		return
	}
	if p.RebootRequired {
		p = Failure(q, "blocked")
		p.RebootKnown = true
		p.RebootRequired = true
		send()
		return
	}
	for _, selected := range q.Updates {
		if ctx.Err() != nil {
			panic(ctx.Err())
		}
		if !within() {
			return
		}
		criteria := fmt.Sprintf("IsInstalled=0 and IsHidden=0 and Type='Software' and UpdateID='%s' and RevisionNumber=%d", selected.ID, selected.Revision)
		res := a.child(search, "Search", criteria)
		if res.num("ResultCode") != 2 {
			panic(ErrInvalid)
		}
		us := a.child(res, "Updates")
		item := protocol.UpdateItemResult{UpdateIdentity: selected, Outcome: "blocked"}
		if us.num("Count") == 1 {
			// Unrepresentable metadata leaves this item blocked, not the job failed.
			desc, u, ok := a.tryDescribe(us, 0)
			if ok && desc.UpdateIdentity == selected && desc.Blocked == "" {
				coll := a.create("Microsoft.Update.UpdateColl")
				v := coll.get("Add", u)
				v.clear()
				dl := a.child(session, "CreateUpdateDownloader")
				dl.set("Updates", coll)
				p.Phase = "downloading"
				send()
				if !within() {
					return
				}
				dr := a.child(dl, "Download")
				item.Outcome = "failed"
				item.HResult = uint32(dr.num("HResult"))
				if dr.num("ResultCode") == 2 && u.yes("IsDownloaded") {
					installer := a.child(session, "CreateUpdateInstaller")
					installer.set("Updates", coll)
					installer.set("AllowSourcePrompts", false)
					// ForceQuiet is on IUpdateInstaller2; late binding resolves the
					// supported Windows implementation without a separate interface.
					installer.set("ForceQuiet", true)
					if !installer.yes("IsBusy") && !installer.yes("RebootRequiredBeforeInstallation") {
						p.Phase = "installing"
						send()
						if !within() {
							return
						}
						ir := a.child(installer, "Install")
						one := a.child(ir, "GetUpdateResult", 0)
						item.HResult = uint32(one.num("HResult"))
						item.Outcome = outcome(one.num("ResultCode"))
						p.RebootRequired = ir.yes("RebootRequired") || info.yes("RebootRequired")
					} else {
						item.Outcome = "blocked"
					}
				}
			}
		}
		p.Items = append(p.Items, item)
		p.Completed++
		send()
		if p.RebootRequired {
			break
		}
	}
	p.Phase = "finished"
	p.Outcome = "ok"
	for _, v := range p.Items {
		if v.Outcome != "ok" {
			p.Outcome = "partial"
		}
	}
	if p.Completed < p.Total {
		p.Outcome = "partial"
	}
	send()
}
