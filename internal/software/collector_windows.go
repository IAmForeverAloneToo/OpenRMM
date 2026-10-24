package software

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
const maxRegistryKeys = 4096

type nativeCollector struct{}

func NewCollector() Collector { return nativeCollector{} }

// Read fixed buffers: registry-reported lengths must never choose allocations.
func metadata(k registry.Key, name string) (string, error) {
	var buf [2048]byte
	n, kind, e := k.GetValue(name, buf[:])
	if errors.Is(e, registry.ErrNotExist) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	if (kind != registry.SZ && kind != registry.EXPAND_SZ) || n < 2 || n > len(buf) || n%2 != 0 {
		return "", features.ErrReport
	}
	units := make([]uint16, n/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	if units[len(units)-1] != 0 {
		return "", features.ErrReport
	}
	units = units[:len(units)-1]
	for i, u := range units {
		if u == 0 || u >= 0xd800 && u <= 0xdbff && (i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff) || u >= 0xdc00 && u <= 0xdfff && (i == 0 || units[i-1] < 0xd800 || units[i-1] > 0xdbff) {
			return "", features.ErrReport
		}
	}
	return strings.TrimSpace(string(utf16.Decode(units))), nil
}
func hidden(k registry.Key) (bool, error) {
	var buf [4]byte
	n, t, e := k.GetValue("SystemComponent", buf[:])
	if errors.Is(e, registry.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if t != registry.DWORD || n != 4 {
		return false, features.ErrReport
	}
	return binary.LittleEndian.Uint32(buf[:]) == 1, nil
}
func readEntry(k registry.Key, key, view string) (*protocol.SoftwareEntry, error) {
	return readScoped(k, key, view, protocol.SoftwareEntry{View: view})
}

// readScoped reads one registration; its ID is a digest of the scope (the
// registry view, or "user" and the SID) and the key name.
func readScoped(k registry.Key, key, scope string, base protocol.SoftwareEntry) (*protocol.SoftwareEntry, error) {
	skip, e := hidden(k)
	if e != nil || skip {
		return nil, e
	}
	name, e := metadata(k, "DisplayName")
	if e != nil || name == "" {
		return nil, e
	}
	version, e := metadata(k, "DisplayVersion")
	if e != nil {
		return nil, e
	}
	publisher, e := metadata(k, "Publisher")
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256([]byte(scope + "\x00" + strings.ToLower(key)))
	v := base
	v.ID, v.Name, v.Version, v.Publisher = hex.EncodeToString(digest[:]), name, version, publisher
	if !EntryValid(v) {
		return nil, features.ErrReport
	}
	return &v, nil
}

// readUninstall reads the registrations under one Uninstall key. A
// registration whose key or metadata is unreadable or invalid is skipped and
// counted; only failures of the Uninstall key itself are returned.
func readUninstall(ctx context.Context, root registry.Key, flag uint32, read func(k registry.Key, name string) (*protocol.SoftwareEntry, error), value *protocol.Software) error {
	names, e := root.ReadSubKeyNames(maxRegistryKeys + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		return errors.New("software registry collection incomplete")
	}
	if len(names) > maxRegistryKeys {
		// Keys past the enumeration bound are counted, never read.
		over := 1
		if info, e := root.Stat(); e == nil && int(info.SubKeyCount) > maxRegistryKeys {
			over = int(info.SubKeyCount) - maxRegistryKeys
		}
		value.Skipped += over
		names = names[:maxRegistryKeys]
	}
	for _, name := range names {
		if e = ctx.Err(); e != nil {
			return e
		}
		key, openErr := registry.OpenKey(root, name, registry.QUERY_VALUE|flag)
		if errors.Is(openErr, registry.ErrNotExist) {
			continue // uninstalled since enumeration
		}
		if openErr != nil {
			value.Skipped++
			continue
		}
		item, readErr := read(key, name)
		key.Close()
		if readErr != nil {
			value.Skipped++
			continue
		}
		if item != nil {
			value.Entries = append(value.Entries, *item)
		}
	}
	return nil
}

// accountName is DOMAIN\user for a SID, or the SID when it does not resolve.
func accountName(sid string) string {
	s, e := windows.StringToSid(sid)
	if e != nil {
		return sid
	}
	user, domain, _, e := s.LookupAccount("")
	if e != nil || user == "" {
		return sid
	}
	if domain != "" {
		user = domain + `\` + user
	}
	if !Text(user, 256, true) {
		return sid
	}
	return user
}

// Collect reads both machine registry views, then the per-user registrations
// in the hives of signed-in users (loaded under HKEY_USERS). Users
// who are not signed in are not covered. Module.Collect applies the count and
// size bounds (see Bound).
func (nativeCollector) Collect(ctx context.Context) (protocol.Software, error) {
	if runtime.GOARCH != "amd64" {
		return protocol.Software{}, features.ErrUnsupported
	}
	value := protocol.Software{Coverage: CoverageUsers, Entries: []protocol.SoftwareEntry{}}
	for _, view := range []struct {
		flag uint32
		name string
	}{{registry.WOW64_64KEY, "64"}, {registry.WOW64_32KEY, "32"}} {
		if e := ctx.Err(); e != nil {
			return protocol.Software{}, e
		}
		root, e := registry.OpenKey(registry.LOCAL_MACHINE, uninstallPath, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|view.flag)
		if errors.Is(e, registry.ErrNotExist) {
			continue
		}
		if e != nil {
			return protocol.Software{}, errors.New("software registry view unavailable")
		}
		e = readUninstall(ctx, root, view.flag, func(k registry.Key, name string) (*protocol.SoftwareEntry, error) {
			return readEntry(k, name, view.name)
		}, &value)
		if closeErr := root.Close(); e == nil {
			e = closeErr
		}
		if e != nil {
			return protocol.Software{}, errors.New("software registry collection incomplete")
		}
	}
	users, e := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if e != nil {
		return protocol.Software{}, errors.New("user registry unavailable")
	}
	sids, e := users.ReadSubKeyNames(1024)
	users.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return protocol.Software{}, errors.New("user registry unavailable")
	}
	sort.Strings(sids)
	for _, sid := range sids {
		if e := ctx.Err(); e != nil {
			return protocol.Software{}, e
		}
		if !UserSIDValid(sid) {
			continue // service accounts and the _Classes hives
		}
		if len(value.Users) == MaxUsers {
			value.UserSkipped++
			continue
		}
		name := accountName(sid)
		root, e := registry.OpenKey(registry.USERS, sid+`\`+uninstallPath, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if errors.Is(e, registry.ErrNotExist) {
			value.Users = append(value.Users, protocol.SoftwareUser{SID: sid, Name: name})
			continue
		}
		if e != nil {
			value.UserSkipped++ // unloaded since enumeration, or unreadable
			continue
		}
		before, machineSkipped := len(value.Entries), value.Skipped
		e = readUninstall(ctx, root, 0, func(k registry.Key, key string) (*protocol.SoftwareEntry, error) {
			return readScoped(k, key, "user\x00"+sid, protocol.SoftwareEntry{View: "user", User: name, UserSID: sid})
		}, &value)
		root.Close()
		// readUninstall counts into Skipped: move this user's share.
		value.UserSkipped += value.Skipped - machineSkipped
		value.Skipped = machineSkipped
		if e != nil {
			if ctx.Err() != nil {
				return protocol.Software{}, ctx.Err()
			}
			// A user's hive unloaded while it was read: none of it is reported.
			value.Entries = value.Entries[:before]
			value.UserSkipped++
			continue
		}
		value.Users = append(value.Users, protocol.SoftwareUser{SID: sid, Name: name})
	}
	value.Skipped, value.UserSkipped = min(value.Skipped, MaxSkipped), min(value.UserSkipped, MaxSkipped)
	sort.Slice(value.Entries, func(i, j int) bool { return value.Entries[i].ID < value.Entries[j].ID })
	return value, ctx.Err()
}
