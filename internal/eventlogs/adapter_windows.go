package eventlogs

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

var errEventSize = errors.New("event XML exceeds limit")

var eventDLL = windows.NewLazySystemDLL("wevtapi.dll")
var evtQuery = eventDLL.NewProc("EvtQuery")
var evtNext = eventDLL.NewProc("EvtNext")
var evtRender = eventDLL.NewProc("EvtRender")
var evtClose = eventDLL.NewProc("EvtClose")
var evtPublisher = eventDLL.NewProc("EvtOpenPublisherMetadata")
var evtMessage = eventDLL.NewProc("EvtFormatMessage")

type native struct{}

func NewAdapter() Adapter { return native{} }
func api() error {
	for _, p := range []*windows.LazyProc{evtQuery, evtNext, evtRender, evtClose, evtPublisher, evtMessage} {
		if e := p.Find(); e != nil {
			return e
		}
	}
	return nil
}
func closeEvent(h uintptr) {
	if h != 0 {
		evtClose.Call(h)
	}
}
func queryEvent(channel, filter string) (uintptr, error) {
	c, e := windows.UTF16PtrFromString(channel)
	if e != nil {
		return 0, e
	}
	f, e := windows.UTF16PtrFromString(filter)
	if e != nil {
		return 0, e
	}
	h, _, callErr := evtQuery.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(f)), 0x201)
	runtime.KeepAlive(c)
	runtime.KeepAlive(f)
	if h == 0 {
		return 0, callErr
	}
	return h, nil
}
func outcome(e error) string {
	switch {
	case errors.Is(e, windows.ERROR_ACCESS_DENIED):
		return "denied"
	case errors.Is(e, windows.ERROR_TIMEOUT), errors.Is(e, context.DeadlineExceeded), errors.Is(e, context.Canceled):
		return "timed_out"
	case errors.Is(e, windows.Errno(15011)):
		return "log_changed"
	case errors.Is(e, windows.Errno(15007)), errors.Is(e, windows.ERROR_FILE_NOT_FOUND):
		return "unavailable"
	}
	return "failed"
}
func (native) Probe(ctx context.Context) (protocol.EventLogSupport, error) {
	if e := ctx.Err(); e != nil {
		return protocol.EventLogSupport{}, e
	}
	if e := api(); e != nil {
		return protocol.EventLogSupport{}, e
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	check := func(channel string) string {
		h, e := queryEvent(channel, "*")
		if e != nil {
			if outcome(e) == "denied" {
				return "denied"
			}
			return "unavailable"
		}
		closeEvent(h)
		return "readable"
	}
	v := protocol.EventLogSupport{System: check("System"), Application: check("Application"), Channels: map[string]string{}}
	for _, name := range KeyChannels {
		v.Channels[name] = check(name)
	}
	return v, ctx.Err()
}
func renderEvent(h uintptr) (string, error) {
	var bytes, properties uint32
	r, _, e := evtRender.Call(0, h, 1, 0, 0, uintptr(unsafe.Pointer(&bytes)), uintptr(unsafe.Pointer(&properties)))
	if r == 0 && !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) {
		return "", e
	}
	if bytes == 0 || bytes > 512*1024 || bytes%2 != 0 {
		return "", errEventSize
	}
	buf := make([]uint16, bytes/2)
	r, _, e = evtRender.Call(0, h, 1, uintptr(bytes), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bytes)), uintptr(unsafe.Pointer(&properties)))
	if r == 0 {
		return "", e
	}
	return windows.UTF16ToString(buf), nil
}
func message(h uintptr, provider string) (string, string) {
	p, e := windows.UTF16PtrFromString(provider)
	if e != nil {
		return "", "unavailable"
	}
	meta, _, _ := evtPublisher.Call(0, uintptr(unsafe.Pointer(p)), 0, 0x409, 0)
	runtime.KeepAlive(p)
	if meta == 0 {
		return "", "unavailable"
	}
	defer closeEvent(meta)
	var used uint32
	r, _, e := evtMessage.Call(meta, h, 0, 0, 0, 1, 0, 0, uintptr(unsafe.Pointer(&used)))
	if r == 0 && !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) {
		return "", "unavailable"
	}
	if used == 0 || used > 65536 {
		return "", "unavailable"
	}
	buf := make([]uint16, used)
	r, _, _ = evtMessage.Call(meta, h, 0, 0, 0, 1, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
	if r == 0 {
		return "", "unavailable"
	}
	value, truncated := clip(windows.UTF16ToString(buf), 4096)
	if truncated {
		return value, "truncated"
	}
	return value, "formatted"
}
func (native) Query(ctx context.Context, q protocol.EventQuery) protocol.EventResult {
	result := protocol.EventResult{ID: q.ID, Outcome: "failed", Events: []protocol.WindowsEvent{}}
	xpath, e := XPath(q.Filter)
	if e != nil || !protocol.ValidID(q.ID) {
		return result
	}
	if e = api(); e != nil {
		return result
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if e = ctx.Err(); e != nil {
		result.Outcome = outcome(e)
		return result
	}
	h, e := queryEvent(q.Filter.Channel, xpath)
	if e != nil {
		result.Outcome = outcome(e)
		return result
	}
	defer closeEvent(h)
	used := 0
	for {
		if e = ctx.Err(); e != nil {
			result.Outcome = outcome(e)
			result.Events, result.Skipped = []protocol.WindowsEvent{}, 0
			return result
		}
		var event uintptr
		var count uint32
		r, _, callErr := evtNext.Call(h, 1, uintptr(unsafe.Pointer(&event)), 200, 0, uintptr(unsafe.Pointer(&count)))
		if r == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			if errors.Is(callErr, windows.ERROR_TIMEOUT) {
				continue
			}
			result.Outcome = outcome(callErr)
			result.Events, result.Skipped = []protocol.WindowsEvent{}, 0
			return result
		}
		if count != 1 || event == 0 {
			closeEvent(event)
			result.Events, result.Skipped = []protocol.WindowsEvent{}, 0
			return result
		}
		if len(result.Events) == q.Filter.Limit {
			closeEvent(event)
			result.More = true
			result.NextBefore = result.Events[len(result.Events)-1].RecordID
			break
		}
		raw, e := renderEvent(event)
		if errors.Is(e, errEventSize) {
			// One oversized event is skipped and counted, not the whole query.
			closeEvent(event)
			Accept(&result, q.Filter, protocol.WindowsEvent{}, e)
			continue
		}
		if e != nil {
			closeEvent(event)
			result.Outcome = outcome(e)
			result.Events, result.Skipped = []protocol.WindowsEvent{}, 0
			return result
		}
		value, e := ParseEvent(raw)
		if e == nil {
			value.Message, value.MessageStatus = message(event, value.Provider)
		}
		closeEvent(event)
		// A page ends early, with a cursor, before its JSON would exceed the
		// result limit (250 large events can).
		if e == nil {
			b, _ := json.Marshal(value)
			if used+len(b)+1 > resultBudget && len(result.Events) > 0 {
				result.More = true
				result.NextBefore = result.Events[len(result.Events)-1].RecordID
				break
			}
			used += len(b) + 1
		}
		// Malformed or out-of-range events are skipped and counted.
		Accept(&result, q.Filter, value, e)
	}
	result.Outcome = "ok"
	if !ResultValid(result, q.Filter) {
		return protocol.EventResult{ID: q.ID, Outcome: "failed", Events: []protocol.WindowsEvent{}}
	}
	return result
}

// ReadForward calls each with the XML of at most max events of a channel
// that match an XPath query, oldest first (for the logon history); each
// returning false stops early. Oversized events are skipped.
func ReadForward(ctx context.Context, channel, xpath string, max int, each func(string) bool) error {
	if e := api(); e != nil {
		return e
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c, e := windows.UTF16PtrFromString(channel)
	if e != nil {
		return e
	}
	f, e := windows.UTF16PtrFromString(xpath)
	if e != nil {
		return e
	}
	// EvtQueryChannelPath | EvtQueryForwardDirection
	h, _, callErr := evtQuery.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(f)), 0x101)
	runtime.KeepAlive(c)
	runtime.KeepAlive(f)
	if h == 0 {
		return callErr
	}
	defer closeEvent(h)
	for n := 0; n < max; n++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		var event uintptr
		var count uint32
		r, _, callErr := evtNext.Call(h, 1, uintptr(unsafe.Pointer(&event)), 200, 0, uintptr(unsafe.Pointer(&count)))
		if r == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
				return nil
			}
			if errors.Is(callErr, windows.ERROR_TIMEOUT) {
				n--
				continue
			}
			return callErr
		}
		if count != 1 || event == 0 {
			closeEvent(event)
			return errors.New("unexpected event batch")
		}
		raw, e := renderEvent(event)
		closeEvent(event)
		if errors.Is(e, errEventSize) {
			continue
		}
		if e != nil {
			return e
		}
		if !each(raw) {
			return nil
		}
	}
	return nil
}
