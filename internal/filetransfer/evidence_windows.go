package filetransfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Evidence collection on Windows. The backup privilege bypasses file and
// registry permissions, so it is enabled only on an impersonation token of
// the calling thread for one open or save, never for the whole agent: Go
// opens every file with backup semantics, which would otherwise give all of
// the agent's file access the bypass.

// WithBackupPrivilege runs f on a locked thread whose impersonation token has
// the backup privilege enabled; it is dropped before the thread is reused.
func WithBackupPrivilege(f func() error) error {
	runtime.LockOSThread()
	if e := windows.ImpersonateSelf(windows.SecurityImpersonation); e != nil {
		runtime.UnlockOSThread()
		return e
	}
	defer func() {
		// A thread that cannot drop the impersonation is never reused.
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
	}()
	var t windows.Token
	if e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &t); e != nil {
		return e
	}
	defer t.Close()
	var luid windows.LUID
	if e := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid); e != nil {
		return e
	}
	p := windows.Tokenprivileges{PrivilegeCount: 1}
	p.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if e := windows.AdjustTokenPrivileges(t, false, &p, 0, nil, nil); e != nil {
		return e
	}
	return f()
}

const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

func createFile(p string, access, flags uint32) (*os.File, error) {
	name, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(name, access, shareAll, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: e}
	}
	return os.NewFile(uintptr(h), p), nil
}

func privileged(p string, access uint32) (*os.File, error) {
	var f *os.File
	err := WithBackupPrivilege(func() error {
		var e error
		f, e = createFile(p, access, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT)
		return e
	})
	return f, err
}

func openBackup(full string) (*os.File, error) {
	return privileged(longPath(full), windows.GENERIC_READ)
}

// openAttributes reads attributes, times, owner and links only; Windows
// allows that even while another program holds the file exclusively.
func openAttributes(full string) (*os.File, error) {
	return privileged(longPath(full), windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
}

func openSnapshotFile(p string) (*os.File, error) {
	f, e := privileged(p, windows.GENERIC_READ)
	if e != nil {
		return nil, e
	}
	var i windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i) != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		f.Close()
		return nil, os.ErrPermission
	}
	return f, nil
}

// openStream opens an alternate data stream, normally or (privileged true)
// with the backup privilege.
func openStream(p string) (*os.File, bool, error) {
	f, e := createFile(p, windows.GENERIC_READ, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if e == nil {
		return f, false, nil
	}
	f, e = privileged(p, windows.GENERIC_READ)
	return f, true, e
}

// fileIndex is the file's number on its volume (kept in a shadow copy);
// 0 when it cannot be read.
func fileIndex(f *os.File) uint64 {
	var i windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i) != nil {
		return 0
	}
	return uint64(i.FileIndexHigh)<<32 | uint64(i.FileIndexLow)
}

// sameFile reports whether two handles (such as a file and one of its
// streams) refer to the same file on the same volume.
func sameFile(a, b *os.File) bool {
	var x, y windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(a.Fd()), &x) == nil && windows.GetFileInformationByHandle(windows.Handle(b.Fd()), &y) == nil &&
		x.VolumeSerialNumber == y.VolumeSerialNumber && x.FileIndexHigh == y.FileIndexHigh && x.FileIndexLow == y.FileIndexLow
}

// inSnapshot reports whether an opened file is at relative inside the
// shadow copy device (its NT path), not reached through a junction.
func inSnapshot(f *os.File, device, relative string) bool {
	buf := make([]uint16, 32768)
	n, e := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], uint32(len(buf)), volumeNameNT)
	if e != nil || n == 0 || n >= uint32(len(buf)) {
		return false
	}
	want := strings.TrimPrefix(device, `\\?\GLOBALROOT`) + `\` + filepath.FromSlash(relative)
	return strings.EqualFold(windows.UTF16ToString(buf[:n]), want)
}

func isLocked(e error) bool {
	return errors.Is(e, windows.ERROR_SHARING_VIOLATION) || errors.Is(e, windows.ERROR_LOCK_VIOLATION)
}

type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

const fileBasicInfoClass = 0

func fileTimeNanos(t int64) int64 {
	if t <= 116444736000000000 {
		return 0
	}
	return (t - 116444736000000000) * 100
}

// fileMeta reads access and change times, attributes and owner; whatever
// cannot be read is left empty.
func fileMeta(f *os.File) protocol.EvidenceMeta {
	var m protocol.EvidenceMeta
	h := windows.Handle(f.Fd())
	var b fileBasicInfo
	if windows.GetFileInformationByHandleEx(h, fileBasicInfoClass, (*byte)(unsafe.Pointer(&b)), uint32(unsafe.Sizeof(b))) == nil {
		m.Accessed, m.Changed, m.Attributes = fileTimeNanos(b.LastAccessTime), fileTimeNanos(b.ChangeTime), b.FileAttributes
	}
	if sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); e == nil {
		if owner, _, e := sd.Owner(); e == nil && owner != nil {
			m.OwnerSID = owner.String()
			if account, domain, _, e := owner.LookupAccount(""); e == nil {
				m.Owner = account
				if domain != "" {
					m.Owner = domain + `\` + account
				}
			}
		}
	}
	return m
}

const (
	fileStreamInfoClass = 7
	volumeNameNT        = 0x2
)

// listStreams lists the alternate data streams of an open file from its
// handle, with their sizes, at most protocol.MaxEvidenceStreams (more
// reports that there were more). Streams up to protocol.SmallStream are
// hashed, each opened by path from source and checked to belong to the same
// file; a larger stream is not hashed (so a huge stream cannot stall the
// collection), and a stream that cannot be read has no hash either.
func listStreams(f *os.File, source string) (streams []protocol.EvidenceStream, more bool) {
	var buf []byte
	for size := 64 << 10; size <= 4<<20; size *= 4 {
		buf = make([]byte, size)
		e := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), fileStreamInfoClass, &buf[0], uint32(len(buf)))
		if e == nil {
			break
		}
		if !errors.Is(e, windows.ERROR_MORE_DATA) || size == 4<<20 {
			return nil, false
		}
	}
	for offset := 0; offset+24 <= len(buf); {
		next := *(*uint32)(unsafe.Pointer(&buf[offset]))
		length := int(*(*uint32)(unsafe.Pointer(&buf[offset+4])))
		size := *(*int64)(unsafe.Pointer(&buf[offset+8]))
		if offset+24+length > len(buf) || length%2 != 0 {
			return streams, false
		}
		name := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[offset+24])), length/2)
		// Names look like ":Zone.Identifier:$DATA"; "::$DATA" is the content.
		raw := windows.UTF16ToString(name)
		s := strings.TrimSuffix(strings.TrimPrefix(raw, ":"), ":$DATA")
		if raw != "::$DATA" && strings.HasSuffix(raw, ":$DATA") && protocol.ValidStreamName(s) {
			if len(streams) == protocol.MaxEvidenceStreams {
				return streams, true
			}
			hash := ""
			if size <= protocol.SmallStream {
				hash = hashStream(f, source+":"+s)
			}
			streams = append(streams, protocol.EvidenceStream{Name: s, Size: size, SHA256: hash})
		}
		if next == 0 {
			break
		}
		offset += int(next)
	}
	return streams, false
}

func hashStream(file *os.File, p string) string {
	f, _, e := openStream(p)
	if e != nil {
		return ""
	}
	defer f.Close()
	if !sameFile(f, file) {
		return ""
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, protocol.SmallStream+1)); e != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Shadow copies: a temporary Volume Shadow Copy is
// made through WMI (Win32_ShadowCopy, run by Windows PowerShell as the
// agent), used for one file and deleted. Its ID is written to the ledger as
// soon as it exists, so one left by a crash is deleted by CleanupShadows.

type shadow struct {
	ID, Device string
	At         time.Time
}

var (
	shadowID     = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	shadowDevice = regexp.MustCompile(`^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]+$`)
	driveLetter  = regexp.MustCompile(`^[A-Za-z]:$`)
	ledgerMu     sync.Mutex
	// inUse holds shadow copies this process is reading: a cleanup started
	// by a restarted worker must not delete them.
	inUse = map[string]bool{}
)

func powershell(ctx context.Context, script string) (string, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	// Windows PowerShell must not load modules of a newer PowerShell.
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	// Output keeps what was printed even when the script fails or times out.
	out, e := cmd.Output()
	return strings.TrimSpace(string(out)), e
}

func createShadow(volume, ledger string) (shadow, error) {
	if !driveLetter.MatchString(volume) || ledger == "" {
		return shadow{}, errors.New("invalid volume")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	at := time.Now()
	// The ID is printed as soon as the copy exists, so it reaches the ledger
	// even if the rest of the script fails or times out.
	out, e := powershell(ctx, `$ErrorActionPreference='Stop'; $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='`+volume+`\'; Context='ClientAccessible'}; if ($r.ReturnValue -ne 0) { exit 3 }; [Console]::Out.WriteLine($r.ShadowID); [Console]::Out.Flush(); $s = Get-CimInstance -ClassName Win32_ShadowCopy -Filter ("ID='" + $r.ShadowID + "'"); [Console]::Out.Write($s.DeviceObject)`)
	id, device, _ := strings.Cut(out, "\n")
	id, device = strings.TrimSpace(id), strings.TrimSpace(device)
	if shadowID.MatchString(id) {
		_ = recordShadow(ledger, id, true)
	}
	if e != nil || !shadowID.MatchString(id) || !shadowDevice.MatchString(device) {
		if shadowID.MatchString(id) {
			_ = deleteShadow(id, ledger)
		}
		return shadow{}, errors.New("cannot create a shadow copy")
	}
	ledgerMu.Lock()
	inUse[id] = true
	ledgerMu.Unlock()
	return shadow{ID: id, Device: device, At: at}, nil
}

func deleteShadow(id, ledger string) error {
	if !shadowID.MatchString(id) {
		return errors.New("invalid shadow copy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, e := powershell(ctx, `$ErrorActionPreference='Stop'; Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='`+id+`'" | Remove-CimInstance`); e != nil {
		return e
	}
	ledgerMu.Lock()
	delete(inUse, id)
	ledgerMu.Unlock()
	return recordShadow(ledger, id, false)
}

func recordShadow(ledger, id string, add bool) error {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	ids := []string{}
	if b, e := os.ReadFile(ledger); e == nil {
		_ = json.Unmarshal(b, &ids)
	}
	out := []string{}
	for _, v := range ids {
		if v != id && shadowID.MatchString(v) {
			out = append(out, v)
		}
	}
	if add {
		out = append(out, id)
	}
	b, _ := json.Marshal(out)
	temp := ledger + ".tmp"
	if e := os.WriteFile(temp, b, 0600); e != nil {
		return e
	}
	return os.Rename(temp, ledger)
}

// CleanupShadows deletes shadow copies a previous run left behind.
func CleanupShadows(ledger string) {
	ledgerMu.Lock()
	ids := []string{}
	if b, e := os.ReadFile(ledger); e == nil {
		_ = json.Unmarshal(b, &ids)
	}
	busy := map[string]bool{}
	for id := range inUse {
		busy[id] = true
	}
	ledgerMu.Unlock()
	for _, id := range ids {
		if !busy[id] {
			_ = deleteShadow(id, ledger)
		}
	}
}

// Registry hives.

var regSaveKeyEx = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSaveKeyExW")

const (
	regOptionBackupRestore = 0x4
	regLatestFormat        = 2
)

// saveHive saves a loaded hive to a new private file.
func saveHive(root registry.Key, key, dir string) (string, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	random := make([]byte, 16)
	if _, e := rand.Read(random); e != nil {
		return "", e
	}
	target := filepath.Join(dir, "hive-"+hex.EncodeToString(random)+".dat")
	err := WithBackupPrivilege(func() error {
		var k windows.Handle
		if e := windows.RegOpenKeyEx(windows.Handle(root), windows.StringToUTF16Ptr(key), regOptionBackupRestore, windows.KEY_READ, &k); e != nil {
			return e
		}
		defer windows.RegCloseKey(k)
		p, e := windows.UTF16PtrFromString(target)
		if e != nil {
			return e
		}
		if r, _, _ := regSaveKeyEx.Call(uintptr(k), uintptr(unsafe.Pointer(p)), 0, regLatestFormat); r != 0 {
			return windows.Errno(r)
		}
		return nil
	})
	if err != nil {
		_ = os.Remove(target)
		return "", err
	}
	return target, nil
}

// profile finds a user profile by SID, or by profile folder name when
// exactly one profile has it; stale ".bak" entries are ignored.
func profile(user string) (sid, folder string, ok bool) {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if e != nil {
		return "", "", false
	}
	defer k.Close()
	names, e := k.ReadSubKeyNames(-1)
	if e != nil {
		return "", "", false
	}
	matches := 0
	for _, s := range names {
		if strings.HasSuffix(strings.ToLower(s), ".bak") {
			continue
		}
		p, e := registry.OpenKey(k, s, registry.QUERY_VALUE)
		if e != nil {
			continue
		}
		image, _, e := p.GetStringValue("ProfileImagePath")
		p.Close()
		if e != nil {
			continue
		}
		image, e = registry.ExpandString(image)
		if e != nil {
			continue
		}
		if strings.EqualFold(s, user) {
			return s, image, true
		}
		if strings.EqualFold(filepath.Base(image), user) {
			sid, folder = s, image
			matches++
		}
	}
	return sid, folder, matches == 1
}

func loaded(root registry.Key, key string) bool {
	k, e := registry.OpenKey(root, key, registry.QUERY_VALUE)
	if e != nil {
		return false
	}
	k.Close()
	return true
}

func openHive(name string, o EvidenceOptions) (Evidence, string) {
	root, key, resolved := registry.LOCAL_MACHINE, name, `HKLM\`+name
	if name == "DEFAULT" {
		root, key, resolved = registry.USERS, ".DEFAULT", `HKU\.DEFAULT`
	}
	if kind, user, ok := strings.Cut(name, ":"); ok {
		sid, folder, found := profile(user)
		if !found {
			return Evidence{}, "not_found"
		}
		root, key, resolved = registry.USERS, sid, `HKU\`+sid
		file := filepath.Join(folder, "NTUSER.DAT")
		if kind == "USRCLASS" {
			key, resolved = sid+"_Classes", `HKU\`+sid+"_Classes"
			file = filepath.Join(folder, `AppData\Local\Microsoft\Windows\UsrClass.dat`)
		}
		if !loaded(root, key) {
			return OpenEvidence(file, o)
		}
	}
	saved, e := saveHive(root, key, o.Temp)
	if e != nil {
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return Evidence{}, "not_found"
		}
		return Evidence{}, "failed"
	}
	f, e := os.Open(saved)
	if e != nil {
		_ = os.Remove(saved)
		return Evidence{}, "failed"
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		_ = os.Remove(saved)
		return Evidence{}, "failed"
	}
	return Evidence{File: f, Info: i, Resolved: resolved, Meta: protocol.EvidenceMeta{Method: "registry_save"}, cleanup: []func(){func() { _ = os.Remove(saved) }}}, ""
}

// Event logs.

var (
	wevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	evtExportLog  = wevtapi.NewProc("EvtExportLog")
	evtOpenLog    = wevtapi.NewProc("EvtOpenLog")
	evtGetLogInfo = wevtapi.NewProc("EvtGetLogInfo")
	evtClose      = wevtapi.NewProc("EvtClose")
)

const (
	evtExportLogChannelPath = 0x1
	evtOpenChannelPath      = 0x1
	evtLogFileSize          = 3
	evtVarTypeUInt64        = 10
	maxEventLogExport       = 16 << 30
)

// logFileSize reads the size of a channel's log file, which bounds its
// export.
func logFileSize(channel *uint16) (uint64, bool) {
	if evtOpenLog.Find() != nil || evtGetLogInfo.Find() != nil || evtClose.Find() != nil {
		return 0, false
	}
	h, _, _ := evtOpenLog.Call(0, uintptr(unsafe.Pointer(channel)), evtOpenChannelPath)
	if h == 0 {
		return 0, false
	}
	defer evtClose.Call(h)
	// EVT_VARIANT: an 8-byte value, a count and a type.
	var v struct {
		Value       uint64
		Count, Type uint32
	}
	var used uint32
	r, _, _ := evtGetLogInfo.Call(h, evtLogFileSize, unsafe.Sizeof(v), uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&used)))
	if r == 0 || v.Type != evtVarTypeUInt64 {
		return 0, false
	}
	return v.Value, true
}

func openEventLog(channel, query string, o EvidenceOptions) (Evidence, string) {
	if e := os.MkdirAll(o.Temp, 0700); e != nil {
		return Evidence{}, "failed"
	}
	random := make([]byte, 16)
	if _, e := rand.Read(random); e != nil {
		return Evidence{}, "failed"
	}
	target := filepath.Join(o.Temp, "eventlog-"+hex.EncodeToString(random)+".evtx")
	if query == "" {
		query = "*"
	}
	c, e1 := windows.UTF16PtrFromString(channel)
	q, e2 := windows.UTF16PtrFromString(query)
	t, e3 := windows.UTF16PtrFromString(target)
	if e1 != nil || e2 != nil || e3 != nil || evtExportLog.Find() != nil {
		return Evidence{}, "failed"
	}
	// The export is at most the log file's size: refuse one over the evidence
	// limit, or one the state folder's drive has no room for (keeping 1 GiB).
	if size, ok := logFileSize(c); ok {
		if size > maxEventLogExport {
			return Evidence{}, "too_large"
		}
		var free uint64
		dir, e := windows.UTF16PtrFromString(o.Temp)
		if e != nil || windows.GetDiskFreeSpaceEx(dir, &free, nil, nil) != nil || free < size+1<<30 {
			return Evidence{}, "failed"
		}
	}
	r, _, callErr := evtExportLog.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(t)), evtExportLogChannelPath)
	if r == 0 {
		_ = os.Remove(target)
		switch {
		case errors.Is(callErr, windows.ERROR_ACCESS_DENIED):
			return Evidence{}, "denied"
		case errors.Is(callErr, windows.Errno(15007)), errors.Is(callErr, windows.ERROR_FILE_NOT_FOUND):
			return Evidence{}, "not_found"
		}
		return Evidence{}, "failed"
	}
	f, e := os.Open(target)
	if e != nil {
		_ = os.Remove(target)
		return Evidence{}, "failed"
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		_ = os.Remove(target)
		return Evidence{}, "failed"
	}
	return Evidence{File: f, Info: i, Resolved: channel, Meta: protocol.EvidenceMeta{Method: "export"}, cleanup: []func(){func() { _ = os.Remove(target) }}}, ""
}
