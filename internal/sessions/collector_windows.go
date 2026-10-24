package sessions

import (
	"context"
	"net/netip"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

var queryInformation = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")

// WTS_INFO_CLASS values used here.
const (
	wtsUserName           = 5
	wtsDomainName         = 7
	wtsClientName         = 10
	wtsClientAddress      = 14
	wtsClientProtocolType = 16
	wtsSessionInfo        = 24
)

// wtsInfo is WTSINFOW. Its short user and domain fields are not used (they can
// be truncated); the full names come from their own queries.
type wtsInfo struct {
	State                   uint32
	SessionID               uint32
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
	WinStationName          [32]uint16
	Domain                  [17]uint16
	UserName                [21]uint16
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	LogonTime               int64
	CurrentTime             int64
}

// wtsClientAddressInfo is WTS_CLIENT_ADDRESS.
type wtsClientAddressInfo struct {
	AddressFamily uint32
	Address       [20]byte
}

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }

// query returns a copy of one session value; Windows frees its buffer here.
func query(id uint32, class uint32, limit uint32) ([]byte, bool) {
	var buffer *byte
	var n uint32
	r, _, _ := queryInformation.Call(0, uintptr(id), uintptr(class), uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buffer == nil {
		return nil, false
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	if n > limit {
		return nil, false
	}
	return append([]byte(nil), unsafe.Slice(buffer, n)...), true
}

// queryText decodes a NUL-terminated UTF-16 value of at most 512 characters.
func queryText(id, class uint32) string {
	b, ok := query(id, class, 1026)
	if !ok || len(b)%2 != 0 {
		return ""
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	for i, u := range units {
		if u == 0 {
			units = units[:i]
			break
		}
	}
	return strings.TrimSpace(string(utf16.Decode(units)))
}

// unixTime converts a FILETIME count; 0 means not provided.
func unixTime(filetime int64) int64 {
	const epoch = 116444736000000000
	if filetime <= epoch {
		return 0
	}
	return (filetime - epoch) / 10000000
}

func clientAddress(id uint32) string {
	b, ok := query(id, wtsClientAddress, uint32(unsafe.Sizeof(wtsClientAddressInfo{})))
	if !ok || len(b) != int(unsafe.Sizeof(wtsClientAddressInfo{})) {
		return ""
	}
	var v wtsClientAddressInfo
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v)), len(b)), b)
	switch v.AddressFamily {
	case windows.AF_INET:
		return netip.AddrFrom4([4]byte(v.Address[2:6])).String()
	case windows.AF_INET6:
		return netip.AddrFrom16([16]byte(v.Address[2:18])).String()
	}
	return ""
}

// Collect lists sessions with a signed-in user; the services session and
// listeners have none and are not reported.
func (nativeCollector) Collect(ctx context.Context) (protocol.Sessions, error) {
	var list *windows.WTS_SESSION_INFO
	var count uint32
	if e := windows.WTSEnumerateSessions(0, 0, 1, &list, &count); e != nil {
		return protocol.Sessions{}, e
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(list)))
	out := protocol.Sessions{Sessions: []protocol.Session{}}
	for _, s := range unsafe.Slice(list, count) {
		if ctx.Err() != nil {
			return protocol.Sessions{}, ctx.Err()
		}
		user := queryText(s.SessionID, wtsUserName)
		if user == "" {
			continue
		}
		v := protocol.Session{ID: s.SessionID, User: user, Domain: queryText(s.SessionID, wtsDomainName), State: "other", Connection: "other", IdleSeconds: -1}
		if s.WindowStationName != nil {
			v.Station = strings.TrimSpace(windows.UTF16PtrToString(s.WindowStationName))
			if len(v.Station) > 64 {
				v.Station = ""
			}
		}
		switch s.State {
		case windows.WTSActive:
			v.State = "active"
		case windows.WTSDisconnected:
			v.State = "disconnected"
		}
		if b, ok := query(s.SessionID, wtsClientProtocolType, 2); ok && len(b) == 2 {
			switch uint16(b[0]) | uint16(b[1])<<8 {
			case 0:
				v.Connection = "console"
			case 2:
				v.Connection = "rdp"
			}
		}
		if v.Connection != "console" {
			v.ClientName = queryText(s.SessionID, wtsClientName)
			v.ClientAddress = clientAddress(s.SessionID)
		}
		if b, ok := query(s.SessionID, wtsSessionInfo, uint32(unsafe.Sizeof(wtsInfo{}))); ok && len(b) == int(unsafe.Sizeof(wtsInfo{})) {
			// Copy into an aligned value; the byte copy has no alignment guarantee.
			var info wtsInfo
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&info)), len(b)), b)
			v.LogonAt = unixTime(info.LogonTime)
			// The console often reports no last input time; idle is then unknown.
			if info.LastInputTime > 0 && info.CurrentTime >= info.LastInputTime {
				v.IdleSeconds = (info.CurrentTime - info.LastInputTime) / 10000000
			}
		}
		out.Sessions = append(out.Sessions, v)
	}
	return out, nil
}
