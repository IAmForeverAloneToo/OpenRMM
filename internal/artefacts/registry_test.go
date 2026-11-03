package artefacts

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/registry"
	rt "github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/registry/registrytest"
)

func key(name string, subs ...*rt.Key) *rt.Key { return &rt.Key{Name: name, Time: when, Subkeys: subs} }

func val(k *rt.Key, values ...rt.Value) *rt.Key {
	k.Values = append(k.Values, values...)
	return k
}

func str(name, s string) rt.Value {
	return rt.Value{Name: name, Type: registry.String, Data: rt.U16(s)}
}

func ft8(t time.Time) []byte { return binary.LittleEndian.AppendUint64(nil, rt.FT(t)) }

// path builds nested keys A\B\C ending in leaf.
func path(p string, leaf *rt.Key) *rt.Key {
	parts := strings.Split(p, `\`)
	k := leaf
	for i := len(parts) - 1; i >= 0; i-- {
		k = key(parts[i], k)
	}
	return k
}

func systemHive() []byte {
	// AppCompatCache: Windows 10 header (0x34), then two "10ts" entries.
	shim := make([]byte, 0x34)
	binary.LittleEndian.PutUint32(shim, 0x34)
	for _, p := range []string{`C:\Tools\evil.exe`, `C:\Windows\notepad.exe`} {
		name := rt.U16(p)
		name = name[:len(name)-2]
		body := binary.LittleEndian.AppendUint16(nil, uint16(len(name)))
		body = append(body, name...)
		body = append(body, ft8(when)...)
		body = binary.LittleEndian.AppendUint32(body, 0)
		e := append([]byte("10ts"), 0, 0, 0, 0)
		e = binary.LittleEndian.AppendUint32(e, uint32(len(body)))
		shim = append(shim, append(e, body...)...)
	}
	svc := val(key("EvilSvc", val(key("Parameters"), rt.Value{Name: "ServiceDll", Type: registry.ExpandString, Data: rt.U16(`C:\evil.dll`)})),
		str("ImagePath", `C:\Windows\system32\svchost.exe -k netsvcs`), rt.Value{Name: "Start", Type: registry.DWord, Data: rt.DWord(2)})
	bamUser := val(key("S-1-5-21-1-2-3-1001"), rt.Value{Name: `\Device\HarddiskVolume3\Tools\evil.exe`, Type: registry.Binary, Data: append(ft8(when), make([]byte, 16)...)},
		rt.Value{Name: "Version", Type: registry.DWord, Data: rt.DWord(1)})
	// The install time property: the key's default value, a FILETIME.
	install := val(key("0064"), rt.Value{Name: "", Type: 0xFFFF0010, Data: ft8(when.Add(-time.Hour))})
	usbInstance := val(key("AA00BB11&0", path(`Properties\{83da6326-97a6-4088-9453-a1923f573b29}`, install)), str("FriendlyName", "Kingston DataTraveler USB Device"))
	cs := key("ControlSet001",
		path(`Control\Session Manager`, val(key("AppCompatCache"), rt.Value{Name: "AppCompatCache", Type: registry.Binary, Data: shim})),
		key("Services", svc, path(`bam\State`, key("UserSettings", bamUser))),
		path(`Enum\USBSTOR`, key("Disk&Ven_Kingston&Prod_DT&Rev_1.00", usbInstance)),
	)
	sel := val(key("Select"), rt.Value{Name: "Current", Type: registry.DWord, Data: rt.DWord(1)})
	return rt.Hive(key("ROOT", sel, cs), when)
}

func ntuser(extra bool) []byte {
	// UserAssist: ROT13 names, 72-byte data with counts and the last run.
	ua := make([]byte, 72)
	binary.LittleEndian.PutUint32(ua[4:], 9)
	binary.LittleEndian.PutUint32(ua[8:], 3)
	binary.LittleEndian.PutUint32(ua[12:], 61500)
	copy(ua[60:], ft8(when))
	count := val(key("Count"), rt.Value{Name: registry.Rot13(`C:\Tools\evil.exe`), Type: registry.Binary, Data: ua})
	run := val(key("Run"), str("Updater", `C:\Users\alice\AppData\evil.exe`))
	if extra {
		run.Values = append(run.Values, str("Added", `C:\later.exe`))
	}
	// BagMRU: item 0 is This PC, under it drive C:, under that the
	// folder Tools.
	root := append([]byte{20, 0, 0x1F, 0x50}, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D)
	drive := append([]byte{25, 0, 0x2F}, []byte("C:\\\x00")...)
	drive = append(drive, make([]byte, 25-len(drive))...)
	folder := make([]byte, 14)
	folder[2] = 0x31
	binary.LittleEndian.PutUint16(folder[8:], uint16(46<<9|11<<5|3)) // 2026-11-03
	folder = append(folder, []byte("TOOLS\x00")...)
	binary.LittleEndian.PutUint16(folder, uint16(len(folder)))
	mru := func(k *rt.Key, item []byte) *rt.Key {
		return val(k, rt.Value{Name: "0", Type: registry.Binary, Data: item}, rt.Value{Name: "MRUListEx", Type: registry.Binary, Data: []byte{0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}})
	}
	bags := mru(key("BagMRU", mru(key("0", mru(key("0", val(key("0"), str("NodeSlot", "3"))), folder)), drive)), root)
	explorer := path(`Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`, count)
	current := key("CurrentVersion", run, explorer)
	return rt.Hive(key("ROOT", key("Software", key("Microsoft", key("Windows", current, key("Shell", bags))))), when)
}

func amcacheHive() []byte {
	f := val(key("0006aa"), str("LowerCaseLongPath", `c:\tools\evil.exe`), str("FileId", "0000a9993e364706816aba3e25717850c26c9cd0d89d"), str("Publisher", "Evil Corp"))
	p := val(key("00000abc"), str("Name", "Evil Suite"), str("Version", "1.0"))
	return rt.Hive(key("ROOT", key("Root", key("InventoryApplicationFile", f), key("InventoryApplication", p))), when)
}

func TestParseRegistry(t *testing.T) {
	// alice's NTUSER.DAT is dirty: the Added value is only in its log.
	old, newer := ntuser(false), ntuser(true)
	dirty := append([]byte(nil), old...)
	binary.LittleEndian.PutUint32(dirty[4:], 6)
	in := pkg(t, map[string][]byte{
		"C/Windows/System32/config/SYSTEM":         systemHive(),
		"C/Users/alice/NTUSER.DAT":                 dirty,
		"C/Users/alice/NTUSER.DAT.LOG1":            rt.Log(old, newer, 5),
		"C/Windows/AppCompat/Programs/Amcache.hve": amcacheHive(),
	})
	req := request(t, in)
	m, err := Parse(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Errors) != 0 {
		t.Fatal(m.Errors)
	}
	rows := func(name string) string { return string(readTable(t, req.Output, name)) }
	hives := rows("registry_hives")
	if !strings.Contains(hives, `C:\Users\alice\NTUSER.DAT,NTUSER,alice,2026-11-03 09:30:00.0000000,true,1,`) || !strings.Contains(hives, `C:\Windows\System32\config\SYSTEM,SYSTEM,,`) {
		t.Fatal(hives)
	}
	for table, want := range map[string][]string{
		"registry_keys":     {`SYSTEM,,ControlSet001\Services\EvilSvc,2026-11-03 09:30:00.0000000,2,1`},
		"shimcache":         {`ControlSet001,1,C:\Tools\evil.exe,2026-11-03 09:30:00.0000000`, `ControlSet001,2,C:\Windows\notepad.exe`},
		"bam":               {`S-1-5-21-1-2-3-1001,\Device\HarddiskVolume3\Tools\evil.exe,2026-11-03 09:30:00.0000000,bam`},
		"services":          {`ControlSet001,EvilSvc,,C:\Windows\system32\svchost.exe -k netsvcs,C:\evil.dll,Automatic,`},
		"usb_devices":       {`USBSTOR,Disk&Ven_Kingston&Prod_DT&Rev_1.00,AA00BB11&0,Kingston DataTraveler USB Device,2026-11-03 08:30:00.0000000,,,`},
		"userassist":        {`alice,{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA},C:\Tools\evil.exe,9,3,61.5,2026-11-03 09:30:00.0000000`},
		"registry_autoruns": {`NTUSER,alice,Software\Microsoft\Windows\CurrentVersion\Run,Updater,C:\Users\alice\AppData\evil.exe`, `Added,C:\later.exe`},
		"shellbags":         {`alice,NTUSER,This PC,Root folder,0,`, `alice,NTUSER,This PC\C:\,Drive,0,`, `alice,NTUSER,This PC\C:\TOOLS,Folder,0,3,2026-11-03 09:30:00.0000000,2026-11-03 00:00:00.0000000,`},
		"amcache_files":     {`c:\tools\evil.exe,a9993e364706816aba3e25717850c26c9cd0d89d,,,Evil Corp,`},
		"amcache_programs":  {`Evil Suite,,1.0,`},
	} {
		got := rows(table)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s lacks %q:\n%s", table, w, got)
			}
		}
	}
	// A hive collection is parsed by its name.
	single := request(t, "")
	single.Source, single.Name = "hive", "NTUSER:bob"
	single.Input = filepath.Join(single.Temp, "hive.dat")
	if err := writeFile(single.Input, old); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(context.Background(), single); err != nil {
		t.Fatal(err)
	}
	if got := string(readTable(t, single.Output, "userassist")); !strings.Contains(got, "bob,{CEBFF5CD") {
		t.Fatal(got)
	}
}
