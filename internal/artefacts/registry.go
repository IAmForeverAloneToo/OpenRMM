package artefacts

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/registry"
)

var (
	hivesTable = Def{Name: "registry_hives", Title: "Registry hives",
		Columns: []string{"SourceFile", "Hive", "User", "LastWritten", "Dirty", "LogEntriesApplied", "Keys"}, Times: []string{"LastWritten"}}
	keysTable = Def{Name: "registry_keys", Title: "Registry keys",
		Columns: []string{"Hive", "User", "Path", "LastWrite", "Values", "Subkeys"}, Times: []string{"LastWrite"}}
	amcacheFilesTable = Def{Name: "amcache_files", Title: "Amcache files",
		Columns: []string{"Path", "SHA1", "Size", "Name", "Publisher", "Product", "Version", "LinkDate", "BinaryType", "OsComponent", "ProgramId", "KeyLastWrite"}, Times: []string{"KeyLastWrite"}}
	amcacheProgramsTable = Def{Name: "amcache_programs", Title: "Amcache programs",
		Columns: []string{"Name", "Publisher", "Version", "InstallDate", "Source", "RootDirPath", "UninstallString", "ProgramId", "KeyLastWrite"}, Times: []string{"KeyLastWrite"}}
	shimTable = Def{Name: "shimcache", Title: "ShimCache (AppCompatCache)",
		Columns: []string{"ControlSet", "Position", "Path", "Modified"}, Times: []string{"Modified"}}
	userAssistTable = Def{Name: "userassist", Title: "UserAssist",
		Columns: []string{"User", "Guid", "Name", "RunCount", "FocusCount", "FocusSeconds", "LastRun"}, Times: []string{"LastRun"}}
	bamTable = Def{Name: "bam", Title: "BAM / DAM",
		Columns: []string{"Sid", "Path", "LastRun", "Source"}, Times: []string{"LastRun"}}
	shellbagsTable = Def{Name: "shellbags", Title: "ShellBags",
		Columns: []string{"User", "Hive", "Path", "Type", "MRUPosition", "NodeSlot", "KeyLastWrite", "Modified", "Created", "Accessed", "MFTEntry", "MFTSequence"}, Times: []string{"KeyLastWrite", "Modified", "Created", "Accessed"}}
	autorunsTable = Def{Name: "registry_autoruns", Title: "Registry autostart entries",
		Columns: []string{"Hive", "User", "Key", "Name", "Value", "KeyLastWrite"}, Times: []string{"KeyLastWrite"}}
	servicesTable = Def{Name: "services", Title: "Services",
		Columns: []string{"ControlSet", "Name", "DisplayName", "ImagePath", "ServiceDll", "Start", "Type", "Account", "KeyLastWrite"}, Times: []string{"KeyLastWrite"}}
	usbTable = Def{Name: "usb_devices", Title: "USB devices",
		Columns: []string{"Bus", "Device", "Serial", "FriendlyName", "FirstInstall", "LastArrival", "LastRemoval", "KeyLastWrite"}, Times: []string{"FirstInstall", "LastArrival", "LastRemoval", "KeyLastWrite"}}
)

// maxKeys bounds the keys listed per hive.
const maxKeys = 3_000_000

// hiveKind recognizes a hive by its path in a triage package or by the
// name of a hive collection ("system", "ntuser:alice"), returning its kind
// and, for a user's hive, the user (from original, in its original case).
func hiveKind(source, lower, original string) (kind, user string, ok bool) {
	if source == "hive" {
		k, u, _ := strings.Cut(lower, ":")
		switch k {
		case "system", "software", "sam", "security", "default", "ntuser", "usrclass":
			_, u, _ = strings.Cut(original, ":")
			return k, u, true
		}
		return "", "", false
	}
	if source != "triage" {
		return "", "", false
	}
	for _, k := range []string{"system", "software", "sam", "security", "default"} {
		if strings.HasSuffix(lower, `\windows\system32\config\`+k) {
			return k, "", true
		}
	}
	if strings.HasSuffix(lower, `\windows\appcompat\programs\amcache.hve`) {
		return "amcache", "", true
	}
	// C:\Users\<user>\NTUSER.DAT and ...\AppData\Local\Microsoft\Windows\UsrClass.dat
	parts := strings.Split(lower, `\`)
	if len(parts) < 4 || parts[1] != "users" {
		return "", "", false
	}
	user = strings.Split(original, `\`)[2]
	switch {
	case len(parts) == 4 && parts[3] == "ntuser.dat":
		return "ntuser", user, true
	case len(parts) == 8 && strings.HasSuffix(lower, `\appdata\local\microsoft\windows\usrclass.dat`):
		return "usrclass", user, true
	}
	return "", "", false
}

var hiveLabels = map[string]string{"system": "SYSTEM", "software": "SOFTWARE", "sam": "SAM", "security": "SECURITY", "default": "DEFAULT", "ntuser": "NTUSER", "usrclass": "UsrClass", "amcache": "Amcache"}

var registryParser = parser{
	table: hivesTable.Name,
	match: func(source, p string) bool {
		_, _, ok := hiveKind(source, p, p)
		return ok
	},
	max:   registry.MaxHive,
	parse: parseHive,
}

func parseHive(ctx context.Context, o *Output, f file) error {
	kind, user, _ := hiveKind(o.m.Source, strings.ToLower(f.path), f.path)
	b, err := readAll(f, registry.MaxHive)
	if err != nil {
		return err
	}
	var logs [][]byte
	for _, ext := range []string{".LOG1", ".LOG2"} {
		if s, ok := f.sibling(f.path + ext); ok {
			if l, err := readAll(s, registry.MaxHive); err == nil {
				logs = append(logs, l)
			}
		}
	}
	h, err := registry.Open(b, logs...)
	if err != nil {
		return err
	}
	root, err := h.Root()
	if err != nil {
		return err
	}
	label := hiveLabels[kind]
	keys := 0
	var walk func(k registry.Key, path string, depth int) error
	walk = func(k registry.Key, path string, depth int) error {
		if keys++; keys > maxKeys || depth > 512 {
			return errors.New("the hive has more keys than are listed")
		}
		if keys%10000 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		values, _ := k.Values()
		subs, subErr := k.Subkeys()
		if err := o.Add(keysTable, f.path, []string{label, user, path, Stamp(k.LastWrite()), strconv.Itoa(len(values)), strconv.Itoa(len(subs))}); err != nil {
			return err
		}
		if subErr != nil {
			o.Fail(f.path, keysTable.Name, fmt.Errorf("%s: %w", path, subErr))
		}
		for _, s := range subs {
			p := s.Name()
			if path != "" {
				p = path + `\` + p
			}
			if err := walk(s, p, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		if errors.Is(err, ErrOutputLimit) || ctx.Err() != nil {
			return err
		}
		o.Fail(f.path, keysTable.Name, err)
	}
	var extract []func() error
	switch kind {
	case "system":
		cs := controlSet(root)
		extract = []func() error{
			func() error { return shimcache(o, f, root, cs) },
			func() error { return bam(o, f, root, cs) },
			func() error { return services(o, f, root, cs) },
			func() error { return usb(o, f, root, cs) },
		}
	case "software":
		extract = []func() error{func() error { return autoruns(o, f, root, label, user, softwareAutoruns) }}
	case "ntuser":
		extract = []func() error{
			func() error { return userAssist(o, f, root, user) },
			func() error { return shellbags(o, f, root, `Software\Microsoft\Windows\Shell\BagMRU`, label, user) },
			func() error { return autoruns(o, f, root, label, user, userAutoruns) },
		}
	case "usrclass":
		extract = []func() error{func() error {
			return shellbags(o, f, root, `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`, label, user)
		}}
	case "amcache":
		extract = []func() error{func() error { return amcache(o, f, root) }}
	}
	for _, x := range extract {
		if err := x(); errors.Is(err, ErrOutputLimit) || ctx.Err() != nil {
			return err
		} else if err != nil {
			o.Fail(f.path, "registry", err)
		}
	}
	return o.Add(hivesTable, f.path, []string{f.path, label, user, Stamp(h.LastWritten), strconv.FormatBool(h.Dirty), strconv.Itoa(h.Replayed), strconv.Itoa(min(keys, maxKeys))})
}

// controlSet names the current control set of a SYSTEM hive.
func controlSet(root registry.Key) string {
	if sel, ok := root.Subkey("Select"); ok {
		if v, ok := sel.Value("Current"); ok {
			if n, ok := v.Uint(); ok && n > 0 && n < 1000 {
				return fmt.Sprintf("ControlSet%03d", n)
			}
		}
	}
	return "ControlSet001"
}

func text(k registry.Key, name string) string {
	if v, ok := k.Value(name); ok {
		return v.Text()
	}
	return ""
}

func shimcache(o *Output, f file, root registry.Key, cs string) error {
	k, ok := root.Subkey(cs + `\Control\Session Manager\AppCompatCache`)
	if !ok {
		return nil
	}
	v, ok := k.Value("AppCompatCache")
	if !ok {
		return nil
	}
	d, err := v.Data()
	if err != nil {
		return err
	}
	entries, err := registry.AppCompatCache(d)
	for i, e := range entries {
		if err := o.Add(shimTable, f.path, []string{cs, strconv.Itoa(i + 1), e.Path, Stamp(e.Modified)}); err != nil {
			return err
		}
	}
	return err
}

func bam(o *Output, f file, root registry.Key, cs string) error {
	for _, src := range []string{"bam", "dam"} {
		for _, at := range []string{`\State\UserSettings`, `\UserSettings`} {
			k, ok := root.Subkey(cs + `\Services\` + src + at)
			if !ok {
				continue
			}
			sids, _ := k.Subkeys()
			for _, sid := range sids {
				values, _ := sid.Values()
				for _, v := range values {
					d, err := v.Data()
					if err != nil || v.Type() != registry.Binary || len(d) < 8 {
						continue
					}
					if err := o.Add(bamTable, f.path, []string{sid.Name(), v.Name(), Stamp(registry.FileTime(binaryLE(d))), src}); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func binaryLE(d []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(d[i])
	}
	return v
}

var startTypes = []string{"Boot", "System", "Automatic", "Manual", "Disabled"}

func services(o *Output, f file, root registry.Key, cs string) error {
	k, ok := root.Subkey(cs + `\Services`)
	if !ok {
		return nil
	}
	subs, err := k.Subkeys()
	for _, s := range subs {
		start := text(s, "Start")
		if n, err := strconv.Atoi(start); err == nil && n >= 0 && n < len(startTypes) {
			start = startTypes[n]
		}
		dll := ""
		if p, ok := s.Subkey("Parameters"); ok {
			dll = text(p, "ServiceDll")
		}
		if err := o.Add(servicesTable, f.path, []string{cs, s.Name(), text(s, "DisplayName"), text(s, "ImagePath"), dll, start, text(s, "Type"), text(s, "ObjectName"), Stamp(s.LastWrite())}); err != nil {
			return err
		}
	}
	return err
}

// Device properties holding install, arrival and removal times.
const deviceTimes = `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\`

func usb(o *Output, f file, root registry.Key, cs string) error {
	for _, bus := range []string{"USBSTOR", "USB"} {
		k, ok := root.Subkey(cs + `\Enum\` + bus)
		if !ok {
			continue
		}
		devices, _ := k.Subkeys()
		for _, d := range devices {
			instances, _ := d.Subkeys()
			for _, i := range instances {
				when := func(id string) string {
					p, ok := i.Subkey(deviceTimes + id)
					if !ok {
						return ""
					}
					v, ok := p.Value("")
					if !ok {
						return ""
					}
					b, err := v.Data()
					if err != nil || len(b) < 8 {
						return ""
					}
					return Stamp(registry.FileTime(binaryLE(b)))
				}
				if err := o.Add(usbTable, f.path, []string{bus, d.Name(), i.Name(), text(i, "FriendlyName"), when("0064"), when("0066"), when("0067"), Stamp(i.LastWrite())}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Autostart locations: a key, and the values read there ("" for all).
type autorun struct {
	key    string
	values []string
	// sub reads the named value of every subkey instead.
	sub string
}

var softwareAutoruns = []autorun{
	{key: `Microsoft\Windows\CurrentVersion\Run`},
	{key: `Microsoft\Windows\CurrentVersion\RunOnce`},
	{key: `Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{key: `WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{key: `WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	{key: `Microsoft\Windows NT\CurrentVersion\Winlogon`, values: []string{"Userinit", "Shell", "Taskman", "AppSetup"}},
	{key: `Microsoft\Windows NT\CurrentVersion\Windows`, values: []string{"AppInit_DLLs", "Load", "Run"}},
	{key: `Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, sub: "Debugger"},
	{key: `Microsoft\Windows NT\CurrentVersion\SilentProcessExit`, sub: "MonitorProcess"},
	{key: `Microsoft\Active Setup\Installed Components`, sub: "StubPath"},
}

var userAutoruns = []autorun{
	{key: `Software\Microsoft\Windows\CurrentVersion\Run`},
	{key: `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{key: `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`},
	{key: `Software\Microsoft\Windows NT\CurrentVersion\Windows`, values: []string{"Load", "Run"}},
	{key: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, values: []string{"Shell"}},
}

func autoruns(o *Output, f file, root registry.Key, label, user string, places []autorun) error {
	for _, a := range places {
		k, ok := root.Subkey(a.key)
		if !ok {
			continue
		}
		add := func(k registry.Key, path string, v registry.Value) error {
			return o.Add(autorunsTable, f.path, []string{label, user, path, v.Name(), v.Text(), Stamp(k.LastWrite())})
		}
		if a.sub != "" {
			subs, _ := k.Subkeys()
			for _, s := range subs {
				if v, ok := s.Value(a.sub); ok && v.Text() != "" {
					if err := add(s, a.key+`\`+s.Name(), v); err != nil {
						return err
					}
				}
			}
			continue
		}
		values, _ := k.Values()
		for _, v := range values {
			if len(a.values) > 0 && !containsFold(a.values, v.Name()) {
				continue
			}
			if err := add(k, a.key, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func userAssist(o *Output, f file, root registry.Key, user string) error {
	k, ok := root.Subkey(`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`)
	if !ok {
		return nil
	}
	guids, _ := k.Subkeys()
	for _, g := range guids {
		count, ok := g.Subkey("Count")
		if !ok {
			continue
		}
		values, _ := count.Values()
		for _, v := range values {
			d, err := v.Data()
			// Windows 7 and later: 72 bytes; the session marker is skipped.
			if err != nil || len(d) < 68 {
				continue
			}
			le := func(i int) uint32 { return uint32(d[i]) | uint32(d[i+1])<<8 | uint32(d[i+2])<<16 | uint32(d[i+3])<<24 }
			if err := o.Add(userAssistTable, f.path, []string{user, g.Name(), registry.Rot13(v.Name()), strconv.FormatUint(uint64(le(4)), 10), strconv.FormatUint(uint64(le(8)), 10),
				strconv.FormatFloat(float64(le(12))/1000, 'f', 1, 64), Stamp(registry.FileTime(binaryLE(d[60:68])))}); err != nil {
				return err
			}
		}
	}
	return nil
}

// shellbags walks a BagMRU tree: each numbered value is a shell item, and
// the subkey of the same number holds its children.
func shellbags(o *Output, f file, root registry.Key, at, label, user string) error {
	k, ok := root.Subkey(at)
	if !ok {
		return nil
	}
	nodes := 0
	var walk func(k registry.Key, path string, depth int) error
	walk = func(k registry.Key, path string, depth int) error {
		if depth > 64 {
			return nil
		}
		subs, _ := k.Subkeys()
		order := mruOrder(k)
		for _, s := range subs {
			if nodes++; nodes > 200_000 {
				return errors.New("more ShellBags entries than are listed")
			}
			n, err := strconv.Atoi(s.Name())
			if err != nil {
				continue
			}
			v, ok := k.Value(s.Name())
			if !ok {
				continue
			}
			d, err := v.Data()
			if err != nil {
				continue
			}
			it, _ := registry.ParseShellItem(d)
			name := it.Name
			if name == "" {
				name = "<" + it.Type + ">"
			}
			p := name
			if path != "" {
				p = strings.TrimSuffix(path, `\`) + `\` + name
			}
			mft, seq := "", ""
			if it.MFTEntry != 0 {
				mft, seq = strconv.FormatUint(it.MFTEntry, 10), strconv.Itoa(int(it.MFTSequence))
			}
			pos := ""
			if i, ok := order[n]; ok {
				pos = strconv.Itoa(i)
			}
			if err := o.Add(shellbagsTable, f.path, []string{user, label, p, it.Type, pos, text(s, "NodeSlot"), Stamp(s.LastWrite()), Stamp(it.Modified), Stamp(it.Created), Stamp(it.Accessed), mft, seq}); err != nil {
				return err
			}
			if err := walk(s, p, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(k, "", 0)
}

// mruOrder maps an item number to its position in MRUListEx (0 is the
// most recently used).
func mruOrder(k registry.Key) map[int]int {
	out := map[int]int{}
	v, ok := k.Value("MRUListEx")
	if !ok {
		return out
	}
	d, err := v.Data()
	if err != nil {
		return out
	}
	for i := 0; i+4 <= len(d); i += 4 {
		n := int32(uint32(d[i]) | uint32(d[i+1])<<8 | uint32(d[i+2])<<16 | uint32(d[i+3])<<24)
		if n < 0 {
			break
		}
		out[int(n)] = i / 4
	}
	return out
}

func amcache(o *Output, f file, root registry.Key) error {
	if k, ok := root.Subkey(`Root\InventoryApplicationFile`); ok {
		files, _ := k.Subkeys()
		for _, x := range files {
			if err := o.Add(amcacheFilesTable, f.path, []string{text(x, "LowerCaseLongPath"), strings.TrimPrefix(text(x, "FileId"), "0000"), text(x, "Size"), text(x, "Name"), text(x, "Publisher"), text(x, "ProductName"),
				text(x, "Version"), text(x, "LinkDate"), text(x, "BinaryType"), text(x, "IsOsComponent"), text(x, "ProgramId"), Stamp(x.LastWrite())}); err != nil {
				return err
			}
		}
	}
	// The older layout (Windows 8): Root\File\<volume>\<file>, with
	// numbered values (15 the path, 101 the SHA-1).
	if k, ok := root.Subkey(`Root\File`); ok {
		volumes, _ := k.Subkeys()
		for _, vol := range volumes {
			files, _ := vol.Subkeys()
			for _, x := range files {
				if err := o.Add(amcacheFilesTable, f.path, []string{text(x, "15"), strings.TrimPrefix(text(x, "101"), "0000"), text(x, "6"), "", text(x, "1"), text(x, "0"), text(x, "5"), "", "", "", text(x, "100"), Stamp(x.LastWrite())}); err != nil {
					return err
				}
			}
		}
	}
	if k, ok := root.Subkey(`Root\InventoryApplication`); ok {
		programs, _ := k.Subkeys()
		for _, x := range programs {
			if err := o.Add(amcacheProgramsTable, f.path, []string{text(x, "Name"), text(x, "Publisher"), text(x, "Version"), text(x, "InstallDate"), text(x, "Source"), text(x, "RootDirPath"), text(x, "UninstallString"), x.Name(), Stamp(x.LastWrite())}); err != nil {
				return err
			}
		}
	}
	return nil
}
