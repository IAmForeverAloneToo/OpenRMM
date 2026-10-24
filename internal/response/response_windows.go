package response

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// ---- processes ----

var (
	ntdll                     = windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

const processCommandLineInformation = 60

func fileTime(v windows.Filetime) uint64 { return uint64(v.HighDateTime)<<32 | uint64(v.LowDateTime) }

func commandLine(h windows.Handle) string {
	for size := 8 << 10; size <= 1<<20; size *= 4 {
		buf := make([]byte, size)
		var needed uint32
		status, _, _ := ntQueryInformationProcess.Call(uintptr(h), processCommandLineInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
		if status == 0 {
			s := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			if s.Buffer == nil || s.Length == 0 {
				return ""
			}
			return windows.UTF16ToString(unsafe.Slice(s.Buffer, s.Length/2))
		}
		if uint32(status) != 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
			return ""
		}
	}
	return ""
}

type accounts map[string]string

func (a accounts) name(sid *windows.SID) string {
	key := sid.String()
	if v, ok := a[key]; ok {
		return v
	}
	v := ""
	if account, domain, _, e := sid.LookupAccount(""); e == nil {
		v = account
		if domain != "" {
			v = domain + `\` + account
		}
	}
	a[key] = v
	return v
}

func processList(ctx context.Context, cache *HashCache, n *notes) ([]protocol.ProcessDetail, error) {
	snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(snap)
	names := accounts{}
	out := []protocol.ProcessDetail{}
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(snap, &p); e == nil; e = windows.Process32Next(snap, &p) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(out) == maxItems {
			n.add("process list truncated at " + strconv.Itoa(maxItems))
			break
		}
		d := protocol.ProcessDetail{PID: p.ProcessID, ParentPID: p.ParentProcessID, Name: windows.UTF16ToString(p.ExeFile[:])}
		_ = windows.ProcessIdToSessionId(d.PID, &d.Session)
		if d.PID > 4 {
			describe(ctx, &d, cache, names, n)
		}
		out = append(out, d)
	}
	if e != nil && !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return nil, e
	}
	return out, nil
}

func describe(ctx context.Context, d *protocol.ProcessDetail, cache *HashCache, names accounts, n *notes) {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, d.PID)
	if e != nil {
		n.add("process " + strconv.FormatUint(uint64(d.PID), 10) + " (" + d.Name + "): details unavailable")
		return
	}
	defer windows.CloseHandle(h)
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
		d.Start = strconv.FormatUint(fileTime(c), 10)
		d.StartedAt = stamp(time.Unix(0, c.Nanoseconds()))
	}
	var b [32768]uint16
	size := uint32(len(b))
	if windows.QueryFullProcessImageName(h, 0, &b[0], &size) == nil {
		d.Image = windows.UTF16ToString(b[:size])
		d.SHA256, d.HashNote = cache.Hash(ctx, d.Image)
	} else {
		d.HashNote = "unreadable"
	}
	d.CommandLine = clip(commandLine(h), 32768)
	var t windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &t) == nil {
		if user, e := t.GetTokenUser(); e == nil {
			d.UserSID = user.User.Sid.String()
			d.User = names.name(user.User.Sid)
		}
		t.Close()
	}
	if d.Start != "" {
		d.CanKill = processes.CanKill(d.PID, d.Name, d.Start)
	}
}

// fileIdentity names an open file by volume, file number and change time
// ("" when they cannot be read), for the hash cache.
func fileIdentity(f *os.File) string {
	var i windows.ByHandleFileInformation
	var b struct {
		Creation, Access, Write, Change int64
		Attributes, _                   uint32
	}
	h := windows.Handle(f.Fd())
	if windows.GetFileInformationByHandle(h, &i) != nil || windows.GetFileInformationByHandleEx(h, 0, (*byte)(unsafe.Pointer(&b)), uint32(unsafe.Sizeof(b))) != nil {
		return ""
	}
	return strconv.FormatUint(uint64(i.VolumeSerialNumber), 16) + ":" + strconv.FormatUint(uint64(i.FileIndexHigh)<<32|uint64(i.FileIndexLow), 16) + ":" + strconv.FormatInt(b.Change, 16)
}

// ---- network connections ----

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	getExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

var tcpStates = []string{"", "closed", "listen", "syn_sent", "syn_received", "established", "fin_wait_1", "fin_wait_2", "close_wait", "closing", "last_ack", "time_wait", "delete_tcb"}

func table(proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(64 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		if r == 0 {
			return buf, nil
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size > 64<<20 {
			return nil, windows.Errno(r)
		}
		size += 16 << 10
	}
	return nil, errors.New("connection table keeps growing")
}

func port(v uint32) uint16 { return uint16(v&0xff)<<8 | uint16(v>>8&0xff) }

func rows(buf []byte, width int) (int, bool) {
	if len(buf) < 4 {
		return 0, false
	}
	count := int(binary.LittleEndian.Uint32(buf))
	return count, 4+count*width <= len(buf)
}

func connections(ctx context.Context, n *notes) ([]protocol.Connection, error) {
	names := map[uint32]string{}
	if snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0); e == nil {
		p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
		for e = windows.Process32First(snap, &p); e == nil; e = windows.Process32Next(snap, &p) {
			names[p.ProcessID] = windows.UTF16ToString(p.ExeFile[:])
		}
		windows.CloseHandle(snap)
	}
	out := []protocol.Connection{}
	add := func(c protocol.Connection) {
		if len(out) < maxItems {
			c.Process = names[c.PID]
			out = append(out, c)
		}
	}
	u32 := func(b []byte, at int) uint32 { return binary.LittleEndian.Uint32(b[at:]) }
	addr4 := func(b []byte, at int) string { return netip.AddrFrom4([4]byte(b[at : at+4])).String() }
	addr6 := func(b []byte, at int) string { return netip.AddrFrom16([16]byte(b[at : at+16])).String() }
	state := func(v uint32) string {
		if int(v) < len(tcpStates) {
			return tcpStates[v]
		}
		return "unknown"
	}
	if b, e := table(getExtendedTcpTable, windows.AF_INET, tcpTableOwnerPIDAll); e == nil {
		if count, ok := rows(b, 24); ok {
			for i := 0; i < count; i++ {
				r := 4 + i*24
				add(protocol.Connection{Protocol: "tcp", State: state(u32(b, r)), LocalAddress: addr4(b, r+4), LocalPort: port(u32(b, r+8)), RemoteAddress: addr4(b, r+12), RemotePort: port(u32(b, r+16)), PID: u32(b, r+20)})
			}
		}
	} else {
		n.add("IPv4 TCP table unavailable")
	}
	if b, e := table(getExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPIDAll); e == nil {
		if count, ok := rows(b, 56); ok {
			for i := 0; i < count; i++ {
				r := 4 + i*56
				add(protocol.Connection{Protocol: "tcp6", LocalAddress: addr6(b, r), LocalPort: port(u32(b, r+20)), RemoteAddress: addr6(b, r+24), RemotePort: port(u32(b, r+44)), State: state(u32(b, r+48)), PID: u32(b, r+52)})
			}
		}
	} else {
		n.add("IPv6 TCP table unavailable")
	}
	if b, e := table(getExtendedUdpTable, windows.AF_INET, udpTableOwnerPID); e == nil {
		if count, ok := rows(b, 12); ok {
			for i := 0; i < count; i++ {
				r := 4 + i*12
				add(protocol.Connection{Protocol: "udp", LocalAddress: addr4(b, r), LocalPort: port(u32(b, r+4)), PID: u32(b, r+8)})
			}
		}
	} else {
		n.add("IPv4 UDP table unavailable")
	}
	if b, e := table(getExtendedUdpTable, windows.AF_INET6, udpTableOwnerPID); e == nil {
		if count, ok := rows(b, 28); ok {
			for i := 0; i < count; i++ {
				r := 4 + i*28
				add(protocol.Connection{Protocol: "udp6", LocalAddress: addr6(b, r), LocalPort: port(u32(b, r+20)), PID: u32(b, r+24)})
			}
		}
	} else {
		n.add("IPv6 UDP table unavailable")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, nil
}

// ---- services ----

var serviceStates = []string{"", "stopped", "start_pending", "stop_pending", "running", "continue_pending", "pause_pending", "paused"}

func startType(v uint32) string {
	switch v {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "automatic"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	}
	return "unknown"
}

func serviceType(v uint32) string {
	switch {
	case v&windows.SERVICE_KERNEL_DRIVER != 0:
		return "kernel_driver"
	case v&windows.SERVICE_FILE_SYSTEM_DRIVER != 0:
		return "file_system_driver"
	case v&windows.SERVICE_WIN32_OWN_PROCESS != 0:
		return "own_process"
	case v&windows.SERVICE_WIN32_SHARE_PROCESS != 0:
		return "shared_process"
	}
	return "other"
}

func expand(s string) string {
	p, e := windows.UTF16PtrFromString(s)
	if e != nil {
		return s
	}
	buf := make([]uint16, 32768)
	n, e := windows.ExpandEnvironmentStrings(p, &buf[0], uint32(len(buf)))
	if e != nil || n == 0 || n > uint32(len(buf)) {
		return s
	}
	return windows.UTF16ToString(buf[:n])
}

// imagePath extracts the executable from a service command line.
func imagePath(command string) string {
	s := strings.TrimSpace(expand(command))
	root := os.Getenv("SystemRoot")
	switch {
	case strings.HasPrefix(s, `\??\`):
		s = s[4:]
	case strings.HasPrefix(strings.ToLower(s), `\systemroot\`):
		s = root + s[len(`\systemroot`):]
	case strings.HasPrefix(strings.ToLower(s), `system32\`):
		s = filepath.Join(root, s)
	}
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return s[1 : end+1]
		}
		return ""
	}
	low := strings.ToLower(s)
	for _, ext := range []string{".exe", ".sys", ".dll"} {
		if i := strings.Index(low, ext); i >= 0 && (i+len(ext) == len(s) || s[i+len(ext)] == ' ') {
			return s[:i+len(ext)]
		}
	}
	return s
}

func services(ctx context.Context, cache *HashCache, n *notes) ([]protocol.ServiceDetail, error) {
	m, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if e != nil {
		return nil, e
	}
	defer windows.CloseServiceHandle(m)
	out := []protocol.ServiceDetail{}
	buffer := make([]byte, 256<<10)
	var resume uint32
	for pages := 0; pages < 64; pages++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var needed, count uint32
		before := resume
		e := windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32|windows.SERVICE_DRIVER, windows.SERVICE_STATE_ALL, &buffer[0], uint32(len(buffer)), &needed, &count, &resume, nil)
		if e != nil && !errors.Is(e, windows.ERROR_MORE_DATA) {
			return nil, e
		}
		size := uint32(unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{}))
		if count > uint32(len(buffer))/size {
			return nil, errors.New("service enumeration overflow")
		}
		for _, row := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0])), int(count)) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if len(out) == maxItems {
				n.add("service list truncated")
				return out, nil
			}
			d := protocol.ServiceDetail{Name: windows.UTF16PtrToString(row.ServiceName), DisplayName: windows.UTF16PtrToString(row.DisplayName), PID: row.ServiceStatusProcess.ProcessId}
			if s := row.ServiceStatusProcess.CurrentState; int(s) < len(serviceStates) {
				d.State = serviceStates[s]
			}
			d.Type = serviceType(row.ServiceStatusProcess.ServiceType)
			configure(ctx, m, &d, cache, n)
			out = append(out, d)
		}
		if e == nil {
			return out, nil
		}
		if resume == before {
			return out, errors.New("service enumeration did not progress")
		}
	}
	return out, errors.New("service enumeration limit reached")
}

func configure(ctx context.Context, m windows.Handle, d *protocol.ServiceDetail, cache *HashCache, n *notes) {
	name, e := windows.UTF16PtrFromString(d.Name)
	if e != nil {
		return
	}
	h, e := windows.OpenService(m, name, windows.SERVICE_QUERY_CONFIG)
	if e != nil {
		n.add("service " + d.Name + ": configuration unavailable")
		return
	}
	defer windows.CloseServiceHandle(h)
	var needed uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &needed)
	if needed == 0 || needed > 64<<10 {
		return
	}
	buf := make([]byte, needed)
	c := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if windows.QueryServiceConfig(h, c, needed, &needed) != nil {
		return
	}
	d.StartType = startType(c.StartType)
	d.BinaryPath = clip(windows.UTF16PtrToString(c.BinaryPathName), 4096)
	d.Account = clip(windows.UTF16PtrToString(c.ServiceStartName), 256)
	if d.BinaryPath != "" {
		d.Image = imagePath(d.BinaryPath)
		d.SHA256, _ = cache.Hash(ctx, d.Image)
	}
	if k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+d.Name+`\Parameters`, registry.QUERY_VALUE); e == nil {
		if dll, _, e := k.GetStringValue("ServiceDll"); e == nil && dll != "" {
			d.ServiceDLL = clip(expand(dll), 1024)
			d.DLLSHA256, _ = cache.Hash(ctx, d.ServiceDLL)
		}
		k.Close()
	}
}

// ---- scheduled tasks ----

func tasks(ctx context.Context, n *notes) ([]protocol.TaskDetail, error) {
	base := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	out := []protocol.TaskDetail{}
	e := filepath.WalkDir(base, func(p string, d fs.DirEntry, e error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(base, p)
		if e != nil {
			n.add("tasks: cannot read " + rel)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || d.Type()&fs.ModeIrregular != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if len(out) == maxItems {
			n.add("task list truncated")
			return fs.SkipAll
		}
		i, e := d.Info()
		if e != nil || i.Size() > 1<<20 {
			n.add("tasks: skipped " + rel)
			return nil
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			n.add("tasks: cannot read " + rel)
			return nil
		}
		sum := sha256.Sum256(raw)
		t, e := parseTask(raw)
		if e != nil {
			n.add("tasks: cannot parse " + rel)
		}
		t.Path = `\` + rel
		t.Modified = stamp(i.ModTime())
		t.SHA256 = hex.EncodeToString(sum[:])
		out = append(out, t)
		return nil
	})
	return out, e
}

// ---- registry ----

const (
	regOptionBackupRestore = 0x4
	maxRegistryEntries     = 1000
	maxRegistryHex         = 4096
)

var registryTypes = map[uint32]string{0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}

// ErrNotFound reports a registry key that does not exist.
var ErrNotFound = errors.New("not found")

func utf16Text(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func registryKey(key string, n *notes) (*protocol.RegistryKeyState, error) {
	rootName, sub, _ := strings.Cut(key, `\`)
	root := map[string]registry.Key{"HKLM": registry.LOCAL_MACHINE, "HKU": registry.USERS, "HKCR": registry.CLASSES_ROOT}[rootName]
	state := &protocol.RegistryKeyState{Key: key, Subkeys: []protocol.RegistrySubkey{}, Values: []protocol.RegistryValue{}}
	k, e := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		// Read-only, with the backup privilege (any key).
		var h windows.Handle
		e = filetransfer.WithBackupPrivilege(func() error {
			p, err := windows.UTF16PtrFromString(sub)
			if err != nil {
				return err
			}
			return windows.RegOpenKeyEx(windows.Handle(root), p, regOptionBackupRestore, windows.KEY_READ, &h)
		})
		k, state.BackupPrivilege = registry.Key(h), true
	}
	if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	defer k.Close()
	if info, e := k.Stat(); e == nil {
		state.LastWrite = stamp(info.ModTime())
	}
	if names, e := k.ReadSubKeyNames(maxRegistryEntries + 1); e == nil || errors.Is(e, io.EOF) {
		state.SubkeysMore = len(names) > maxRegistryEntries
		for _, name := range names[:min(len(names), maxRegistryEntries)] {
			s := protocol.RegistrySubkey{Name: name}
			if c, e := registry.OpenKey(k, name, registry.QUERY_VALUE); e == nil {
				if info, e := c.Stat(); e == nil {
					s.LastWrite = stamp(info.ModTime())
				}
				c.Close()
			}
			state.Subkeys = append(state.Subkeys, s)
		}
	} else {
		n.add("subkeys unavailable")
	}
	names, e := k.ReadValueNames(maxRegistryEntries + 1)
	if e != nil && !errors.Is(e, io.EOF) {
		n.add("values unavailable")
		return state, nil
	}
	state.ValuesMore = len(names) > maxRegistryEntries
	for _, name := range names[:min(len(names), maxRegistryEntries)] {
		size, kind, e := k.GetValue(name, nil)
		if e != nil {
			n.add("value " + name + ": unreadable")
			continue
		}
		buf := make([]byte, size)
		if size > 0 {
			if _, _, e = k.GetValue(name, buf); e != nil {
				n.add("value " + name + ": unreadable")
				continue
			}
		}
		v := protocol.RegistryValue{Name: name, Type: registryTypes[kind], Size: size}
		if v.Type == "" {
			v.Type = "type " + strconv.FormatUint(uint64(kind), 10)
		}
		switch {
		case (kind == registry.SZ || kind == registry.EXPAND_SZ) && size%2 == 0:
			v.Data = clip(strings.TrimRight(utf16Text(buf), "\x00"), 32768)
		case kind == registry.DWORD && size == 4:
			x := binary.LittleEndian.Uint32(buf)
			v.Data = strconv.FormatUint(uint64(x), 10) + " (0x" + strconv.FormatUint(uint64(x), 16) + ")"
		case kind == registry.QWORD && size == 8:
			x := binary.LittleEndian.Uint64(buf)
			v.Data = strconv.FormatUint(x, 10) + " (0x" + strconv.FormatUint(x, 16) + ")"
		case kind == registry.MULTI_SZ && size%2 == 0:
			for _, s := range strings.Split(strings.TrimRight(utf16Text(buf), "\x00"), "\x00") {
				if len(v.Strings) < 1000 {
					v.Strings = append(v.Strings, clip(s, 4096))
				}
			}
		default:
			v.Hex = hex.EncodeToString(buf[:min(len(buf), maxRegistryHex)])
			v.Truncated = len(buf) > maxRegistryHex
		}
		state.Values = append(state.Values, v)
	}
	return state, nil
}
