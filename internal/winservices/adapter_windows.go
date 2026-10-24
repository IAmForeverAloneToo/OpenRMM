package winservices

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"time"
	"unsafe"
)

// native runs inside the SYSTEM agent: every service except
// OpenRMM's own may be controlled; server-side permissions decide who may ask.
type native struct{}

func NewAdapter() Adapter                           { return native{} }
func manager(access uint32) (windows.Handle, error) { return windows.OpenSCManager(nil, nil, access) }
func open(m windows.Handle, name string, access uint32) (windows.Handle, error) {
	p, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, e
	}
	return windows.OpenService(m, p, access)
}
func stateName(s uint32) string {
	switch s {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	}
	return "unknown"
}
func query(h windows.Handle) (string, error) {
	var s windows.SERVICE_STATUS_PROCESS
	var needed uint32
	e := windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&s)), uint32(unsafe.Sizeof(s)), &needed)
	return stateName(s.CurrentState), e
}
func (n native) Collect(ctx context.Context) (protocol.Services, error) {
	v := protocol.Services{Items: []protocol.WindowsService{}, Visibility: "queryable_services_only"}
	m, e := manager(windows.SC_MANAGER_CONNECT | windows.SC_MANAGER_ENUMERATE_SERVICE)
	if e != nil {
		return v, e
	}
	defer windows.CloseServiceHandle(m)
	// Windows caps an enumeration buffer at 256 KiB. Resume across bounded pages.
	buffer := make([]byte, 256*1024)
	var resume uint32
	for pages := 0; pages < 32; pages++ {
		if e := ctx.Err(); e != nil {
			return v, e
		}
		var needed, count uint32
		before := resume
		e := windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &buffer[0], uint32(len(buffer)), &needed, &count, &resume, nil)
		if e != nil && !errors.Is(e, windows.ERROR_MORE_DATA) {
			return v, e
		}
		size := uint32(unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{}))
		if count > uint32(len(buffer))/size || len(v.Items)+int(count) > MaxItems {
			return v, errors.New("too many services")
		}
		rows := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0])), int(count))
		for _, row := range rows {
			name := windows.UTF16PtrToString(row.ServiceName)
			s := protocol.WindowsService{Name: name, DisplayName: windows.UTF16PtrToString(row.DisplayName), State: stateName(row.ServiceStatusProcess.CurrentState)}
			if Manageable(name) {
				if h, e := open(m, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_START); e == nil {
					s.CanStart = true
					windows.CloseServiceHandle(h)
				}
				if h, e := open(m, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP); e == nil {
					s.CanStop = true
					windows.CloseServiceHandle(h)
				}
			}
			v.Items = append(v.Items, s)
		}
		if e == nil {
			return v, nil
		}
		if resume == before {
			return v, errors.New("service enumeration did not progress")
		}
	}
	return v, errors.New("service enumeration limit reached")
}
func failure(e error) string {
	switch {
	case errors.Is(e, windows.ERROR_ACCESS_DENIED):
		return "denied"
	case errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return "not_found"
	case errors.Is(e, windows.ERROR_DEPENDENT_SERVICES_RUNNING):
		return "dependent_services"
	}
	return "failed"
}
func (n native) Execute(ctx context.Context, a protocol.ServiceAction) protocol.ServiceResult {
	r := protocol.ServiceResult{ID: a.ID, Outcome: "denied", State: "unknown"}
	if !Manageable(a.Service) || !Action(a.Action) {
		return r
	}
	if ctx.Err() != nil {
		r.Outcome = "interrupted"
		return r
	}
	rights := uint32(windows.SERVICE_QUERY_STATUS)
	if a.Action != "stop" {
		rights |= windows.SERVICE_START
	}
	if a.Action != "start" {
		rights |= windows.SERVICE_STOP
	}
	m, e := manager(windows.SC_MANAGER_CONNECT)
	if e != nil {
		r.Outcome = failure(e)
		return r
	}
	defer windows.CloseServiceHandle(m)
	h, e := open(m, a.Service, rights)
	if e != nil {
		r.Outcome = failure(e)
		return r
	}
	defer windows.CloseServiceHandle(h)
	update := func() bool {
		s, e := query(h)
		if e != nil {
			r.Outcome = failure(e)
			return false
		}
		r.State = s
		return true
	}
	if !update() {
		return r
	}
	if r.State != "running" && r.State != "stopped" {
		r.Outcome = "pending"
		return r
	}
	wait := func(target string) bool {
		for {
			if !update() {
				return false
			}
			if r.State == target {
				return true
			}
			select {
			case <-ctx.Done():
				r.Outcome = "timed_out"
				if errors.Is(ctx.Err(), context.Canceled) {
					r.Outcome = "interrupted"
				}
				return false
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	// Exactly one control per phase. Never stop dependent services or retry controls.
	if a.Action != "start" && r.State == "running" {
		if ctx.Err() != nil {
			r.Outcome = "interrupted"
			return r
		}
		var status windows.SERVICE_STATUS
		e = windows.ControlService(h, windows.SERVICE_CONTROL_STOP, &status)
		if e != nil {
			r.Outcome = failure(e)
			update()
			return r
		}
		if !wait("stopped") {
			return r
		}
	}
	if a.Action != "stop" && r.State == "stopped" {
		if ctx.Err() != nil {
			r.Outcome = "interrupted"
			return r
		}
		e = windows.StartService(h, 0, nil)
		if e != nil {
			r.Outcome = failure(e)
			update()
			return r
		}
		if !wait("running") {
			return r
		}
	}
	r.Outcome = "succeeded"
	return r
}
