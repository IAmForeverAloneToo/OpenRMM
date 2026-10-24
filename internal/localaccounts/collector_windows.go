package localaccounts

import (
	"context"
	"errors"
	"strings"
	"time"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

var (
	netapi                  = windows.NewLazySystemDLL("netapi32.dll")
	netUserEnum             = netapi.NewProc("NetUserEnum")
	netLocalGroupGetMembers = netapi.NewProc("NetLocalGroupGetMembers")
)

const (
	filterNormalAccount = 2
	maxPreferredLength  = 0xFFFFFFFF
	errorMoreData       = 234

	ufAccountDisable     = 0x0002
	ufLockout            = 0x0010
	ufDontExpirePassword = 0x10000
)

// userInfo3 is USER_INFO_3.
type userInfo3 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UsrComment      *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserID          uint32
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

// localGroupMembersInfo2 is LOCALGROUP_MEMBERS_INFO_2.
type localGroupMembersInfo2 struct {
	SID           *windows.SID
	SIDUsage      uint32
	DomainAndName *uint16
}

var groupSIDs = map[string]string{"administrators": "S-1-5-32-544", "remote_desktop_users": "S-1-5-32-555"}

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }

func str(p *uint16) string {
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	if len(s) > 512 {
		return ""
	}
	return strings.TrimSpace(s)
}

func kind(use uint32) string {
	switch use {
	case windows.SidTypeUser:
		return "user"
	case windows.SidTypeGroup, windows.SidTypeAlias:
		return "group"
	case windows.SidTypeWellKnownGroup:
		return "well_known"
	case windows.SidTypeComputer:
		return "computer"
	case windows.SidTypeDeletedAccount:
		return "deleted"
	}
	return "other"
}

// accounts also returns how many accounts were left unread at the read limit.
func accounts(ctx context.Context, now time.Time) ([]protocol.LocalAccount, int, error) {
	out := []protocol.LocalAccount{}
	var resume uint32
	computer, _ := windows.ComputerName()
	for {
		var buffer *byte
		var read, total uint32
		r, _, _ := netUserEnum.Call(0, 3, filterNormalAccount, uintptr(unsafe.Pointer(&buffer)), maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != 0 && r != errorMoreData {
			return nil, 0, windows.Errno(r)
		}
		if buffer != nil {
			for _, u := range unsafe.Slice((*userInfo3)(unsafe.Pointer(buffer)), read) {
				name := str(u.Name)
				a := protocol.LocalAccount{Name: name, FullName: str(u.FullName), Enabled: u.Flags&ufAccountDisable == 0, LockedOut: u.Flags&ufLockout != 0, PasswordNeverExpires: u.Flags&ufDontExpirePassword != 0, PasswordExpired: u.PasswordExpired != 0, LastLogonAt: int64(u.LastLogon)}
				if u.PasswordAge > 0 {
					a.PasswordLastSetAt = now.Add(-time.Duration(u.PasswordAge) * time.Second).Unix()
				}
				// Qualify the name so a built-in or well-known name never wins.
				if sid, _, _, e := windows.LookupSID("", computer+`\`+name); e == nil {
					a.SID = sid.String()
				}
				out = append(out, a)
			}
			windows.NetApiBufferFree(buffer)
		}
		if r != errorMoreData || ctx.Err() != nil {
			return out, 0, ctx.Err()
		}
		if len(out) > 4*MaxAccounts {
			return out, max(int(total)-len(out), 0), nil
		}
	}
}

func members(ctx context.Context, key string) (protocol.LocalGroup, error) {
	g := protocol.LocalGroup{Key: key, Members: []protocol.GroupMember{}}
	sid, e := windows.StringToSid(groupSIDs[key])
	if e != nil {
		return g, e
	}
	name, _, _, e := sid.LookupAccount("")
	if errors.Is(e, windows.ERROR_NONE_MAPPED) && key == "remote_desktop_users" {
		// Remote Desktop Users is missing on some editions: report it empty.
		return g, nil
	}
	if e != nil {
		return g, e
	}
	g.Name = name
	group, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return g, e
	}
	var resume uintptr
	for {
		var buffer *byte
		var read, total uint32
		r, _, _ := netLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(group)), 2, uintptr(unsafe.Pointer(&buffer)), maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if r != 0 && r != errorMoreData {
			return g, windows.Errno(r)
		}
		if buffer != nil {
			for _, m := range unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buffer)), read) {
				if m.SID == nil {
					g.Skipped++
					continue
				}
				g.Members = append(g.Members, protocol.GroupMember{Name: str(m.DomainAndName), SID: m.SID.String(), Kind: kind(m.SIDUsage)})
			}
			windows.NetApiBufferFree(buffer)
		}
		if r != errorMoreData || ctx.Err() != nil {
			return g, ctx.Err()
		}
		if len(g.Members) > 4*MaxMembers {
			// Members never read count as skipped too.
			g.Skipped += max(int(total)-len(g.Members), 0)
			return g, nil
		}
	}
}

func (nativeCollector) Collect(ctx context.Context) (protocol.LocalAccounts, error) {
	list, unread, e := accounts(ctx, time.Now())
	if e != nil {
		return protocol.LocalAccounts{}, e
	}
	v := protocol.LocalAccounts{Accounts: list, Groups: []protocol.LocalGroup{}, Skipped: unread}
	for _, key := range Groups {
		g, e := members(ctx, key)
		if e != nil {
			return protocol.LocalAccounts{}, e
		}
		v.Groups = append(v.Groups, g)
	}
	return v, nil
}
