package response

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Persistence report: registry autostart locations (machine and
// every loaded user hive), services and drivers, scheduled task actions,
// startup folders and WMI event subscriptions, each with the program it
// starts, that program's SHA-256 and its Authenticode signature. Files on
// other computers are never opened (see networkPath).

// autorun is a registry autostart location. Mode values: every value is an
// entry; named: the listed values; subkeys: the listed values of every
// subkey; subkey_values: every value of every subkey. Split separates one
// value into several entries: "list" on spaces, commas and semicolons (DLL
// lists, LSA packages), "comma" on commas (Winlogon programs). DLL resolves
// bare names in System32 (adding .dll).
type autorun struct {
	Path     string
	Category string
	Mode     string
	Names    []string
	Split    string
	DLL      bool
}

var machineAutoruns = []autorun{
	{Path: `Software\Microsoft\Windows\CurrentVersion\Run`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows\CurrentVersion\RunOnceEx`, Category: "run_key", Mode: "subkey_values"},
	{Path: `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, Category: "run_key", Mode: "values"},
	{Path: `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, Category: "winlogon", Mode: "named", Names: []string{"Shell", "Userinit", "Taskman", "AppSetup"}, Split: "comma"},
	{Path: `Software\Microsoft\Windows NT\CurrentVersion\Windows`, Category: "appinit", Mode: "named", Names: []string{"AppInit_DLLs"}, Split: "list", DLL: true},
	{Path: `Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`, Category: "appinit", Mode: "named", Names: []string{"AppInit_DLLs"}, Split: "list", DLL: true},
	{Path: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`, Category: "appcert", Mode: "values", DLL: true},
	{Path: `SYSTEM\CurrentControlSet\Control\Session Manager`, Category: "boot_execute", Mode: "named", Names: []string{"BootExecute"}},
	{Path: `SYSTEM\CurrentControlSet\Control\Lsa`, Category: "lsa", Mode: "named", Names: []string{"Authentication Packages", "Notification Packages", "Security Packages"}, Split: "list", DLL: true},
	{Path: `SYSTEM\CurrentControlSet\Control\Lsa\OSConfig`, Category: "lsa", Mode: "named", Names: []string{"Security Packages"}, Split: "list", DLL: true},
	{Path: `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Category: "ifeo", Mode: "subkeys", Names: []string{"Debugger"}},
	{Path: `Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Category: "ifeo", Mode: "subkeys", Names: []string{"Debugger"}},
	{Path: `Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`, Category: "silent_exit", Mode: "subkeys", Names: []string{"MonitorProcess"}},
	{Path: `Software\Microsoft\Active Setup\Installed Components`, Category: "active_setup", Mode: "subkeys", Names: []string{"StubPath"}},
	{Path: `Software\WOW6432Node\Microsoft\Active Setup\Installed Components`, Category: "active_setup", Mode: "subkeys", Names: []string{"StubPath"}},
	{Path: `SYSTEM\CurrentControlSet\Control\Print\Monitors`, Category: "print_monitor", Mode: "subkeys", Names: []string{"Driver"}, DLL: true},
	{Path: `Software\Microsoft\Command Processor`, Category: "cmd_autorun", Mode: "named", Names: []string{"AutoRun"}},
	{Path: `Software\WOW6432Node\Microsoft\Command Processor`, Category: "cmd_autorun", Mode: "named", Names: []string{"AutoRun"}},
}

var userAutoruns = []autorun{
	{Path: `Software\Microsoft\Windows\CurrentVersion\Run`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, Category: "run_key", Mode: "values"},
	{Path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, Category: "winlogon", Mode: "named", Names: []string{"Shell"}, Split: "comma"},
	{Path: `Software\Microsoft\Windows NT\CurrentVersion\Windows`, Category: "windows_load", Mode: "named", Names: []string{"Load", "Run"}, Split: "list"},
	{Path: `Environment`, Category: "logon_script", Mode: "named", Names: []string{"UserInitMprLogonScript"}},
	{Path: `Software\Microsoft\Command Processor`, Category: "cmd_autorun", Mode: "named", Names: []string{"AutoRun"}},
}

var (
	userSID = regexp.MustCompile(`^S-1-(5-21|12-1)-[0-9-]+$`)
	// userVariable matches the per-user environment variables a user's
	// entries use; SYSTEM's own values would point at its profile.
	userVariable = regexp.MustCompile(`(?i)%(USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|HOMEPATH|HOMEDRIVE)%`)
	systemDir    = filepath.Join(os.Getenv("SystemRoot"), "System32")
	// maxSignatures limits work on a hostile report: at most this many
	// distinct programs are signature-checked.
	maxSignatures = 5000
)

// regStrings reads a string, expandable string or multi-string value.
func regStrings(k registry.Key, name string) []string {
	if s, _, e := k.GetStringValue(name); e == nil {
		return []string{s}
	}
	if s, _, e := k.GetStringsValue(name); e == nil {
		return s
	}
	return nil
}

func split(s, how string) []string {
	switch how {
	case "list":
		return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	case "comma":
		return strings.Split(s, ",")
	}
	return []string{s}
}

// expandFor expands environment variables; profile (a user's profile
// folder) supplies that user's own folders.
func expandFor(s, profile string) string {
	if profile != "" {
		s = userVariable.ReplaceAllStringFunc(s, func(v string) string {
			switch strings.ToUpper(strings.Trim(v, "%")) {
			case "USERPROFILE":
				return profile
			case "APPDATA":
				return filepath.Join(profile, `AppData\Roaming`)
			case "LOCALAPPDATA":
				return filepath.Join(profile, `AppData\Local`)
			case "TEMP", "TMP":
				return filepath.Join(profile, `AppData\Local\Temp`)
			case "HOMEPATH":
				return strings.TrimPrefix(profile, filepath.VolumeName(profile))
			case "HOMEDRIVE":
				return filepath.VolumeName(profile)
			}
			return v
		})
	}
	return expand(s)
}

// resolveImage finds the program file an autostart command starts; profile
// is the user's profile folder for a per-user entry.
func resolveImage(command, category string, dll bool, profile string) string {
	s := strings.TrimSpace(expandFor(command, profile))
	if s == "" {
		return ""
	}
	if dll {
		s = strings.Trim(s, `" `)
		if !strings.ContainsAny(s, `\/`) {
			if filepath.Ext(s) == "" {
				s += ".dll"
			}
			s = filepath.Join(systemDir, s)
		}
		if !filepath.IsAbs(s) {
			return ""
		}
		return s
	}
	if category == "boot_execute" {
		// "autocheck autochk *": the second word is the program in System32.
		if f := strings.Fields(s); len(f) >= 2 && strings.EqualFold(f[0], "autocheck") {
			return filepath.Join(systemDir, f[1]+".exe")
		}
	}
	image := strings.Trim(imagePath(s), `"`)
	if !strings.ContainsAny(image, `\/`) {
		for _, dir := range []string{systemDir, os.Getenv("SystemRoot")} {
			for _, name := range []string{image, image + ".exe"} {
				if i, e := os.Stat(filepath.Join(dir, name)); e == nil && i.Mode().IsRegular() {
					return filepath.Join(dir, name)
				}
			}
		}
		return ""
	}
	// A rundll32 entry runs the DLL named in its arguments.
	if strings.EqualFold(filepath.Base(image), "rundll32.exe") {
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s, `"`+image+`"`), image))
		if dll, _, _ := strings.Cut(rest, ","); dll != "" {
			if d := resolveImage(strings.Trim(dll, `" `), category, true, profile); d != "" {
				return d
			}
		}
	}
	// Anything else that is not a full path (a bare switch) is not a program.
	if !filepath.IsAbs(image) {
		return ""
	}
	return image
}

// hasArguments reports whether a command passes anything to its program.
func hasArguments(command, image, profile string) bool {
	s := strings.TrimSpace(expandFor(command, profile))
	if image == "" || s == "" {
		return false
	}
	rest := s
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			rest = s[end+2:]
		}
	} else if i := strings.Index(strings.ToLower(s), strings.ToLower(filepath.Base(image))); i >= 0 {
		rest = s[i+len(filepath.Base(image)):]
	} else if f := strings.Fields(s); len(f) > 0 {
		rest = strings.TrimSpace(strings.TrimPrefix(s, f[0]))
	}
	return strings.TrimSpace(rest) != ""
}

func entryFor(category, where, name, command, user, profile string, dll bool) protocol.PersistenceEntry {
	image := resolveImage(command, category, dll, profile)
	return protocol.PersistenceEntry{Category: category, Location: where, Name: name, Command: clip(command, 4096), User: user, Image: image, Arguments: !dll && hasArguments(command, image, profile)}
}

func readAutoruns(root registry.Key, rootName, user, profile string, list []autorun, add func(protocol.PersistenceEntry) bool) {
	for _, a := range list {
		k, e := registry.OpenKey(root, a.Path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if e != nil {
			continue
		}
		location := rootName + `\` + a.Path
		emit := func(where, name string, values []string) {
			for _, v := range values {
				for _, item := range split(v, a.Split) {
					if item = strings.TrimSpace(item); item == "" || item == `""` {
						continue
					}
					add(entryFor(a.Category, where, name, item, user, profile, a.DLL))
				}
			}
		}
		switch a.Mode {
		case "values":
			names, _ := k.ReadValueNames(-1)
			for _, name := range names {
				emit(location, name, regStrings(k, name))
			}
		case "named":
			for _, name := range a.Names {
				emit(location, name, regStrings(k, name))
			}
		case "subkeys", "subkey_values":
			subs, _ := k.ReadSubKeyNames(-1)
			for _, s := range subs {
				sk, e := registry.OpenKey(k, s, registry.QUERY_VALUE)
				if e != nil {
					continue
				}
				names := a.Names
				if a.Mode == "subkey_values" {
					names, _ = sk.ReadValueNames(-1)
				}
				for _, name := range names {
					emit(location+`\`+s, name, regStrings(sk, name))
				}
				sk.Close()
			}
		}
		k.Close()
	}
}

// profiles maps user SIDs to their profile folders.
func profiles() map[string]string {
	out := map[string]string{}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if e != nil {
		return out
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	for _, sid := range names {
		if !userSID.MatchString(sid) {
			continue
		}
		p, e := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if e != nil {
			continue
		}
		if image, _, e := p.GetStringValue("ProfileImagePath"); e == nil {
			if image, e = registry.ExpandString(image); e == nil && filepath.IsAbs(image) && !networkPath(image) {
				out[sid] = image
			}
		}
		p.Close()
	}
	return out
}

type startupFolder struct{ dir, user, profile string }

func startupFolders(users map[string]string, add func(protocol.PersistenceEntry) bool) {
	folders := []startupFolder{{dir: filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`)}}
	seen := map[string]bool{strings.ToLower(folders[0].dir): true}
	for sid, profile := range users {
		dirs := []string{filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)}
		// A redirected Startup folder (loaded hives only).
		if k, e := registry.OpenKey(registry.USERS, sid+`\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.QUERY_VALUE); e == nil {
			if v, _, e := k.GetStringValue("Startup"); e == nil {
				dirs = append(dirs, expandFor(v, profile))
			}
			k.Close()
		}
		for _, d := range dirs {
			if !seen[strings.ToLower(d)] && filepath.IsAbs(d) && !networkPath(d) {
				seen[strings.ToLower(d)] = true
				folders = append(folders, startupFolder{d, sid, profile})
			}
		}
	}
	for _, f := range folders {
		entries, e := os.ReadDir(f.dir)
		if e != nil {
			continue
		}
		for _, d := range entries {
			if !d.Type().IsRegular() || strings.EqualFold(d.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(f.dir, d.Name())
			entry := protocol.PersistenceEntry{Category: "startup_folder", Location: f.dir, Name: d.Name(), Command: full, User: f.user, Image: full}
			if strings.EqualFold(filepath.Ext(d.Name()), ".lnk") {
				entry.Image, entry.Detail = "", "shortcut (target read from the link; not verified against what Explorer starts)"
				if i, e := d.Info(); e == nil && i.Size() <= 64<<10 {
					if b, e := os.ReadFile(full); e == nil {
						if target, args, ok := shortcutTarget(b); ok {
							target = expandFor(target, f.profile)
							if !filepath.IsAbs(target) {
								target = filepath.Join(f.dir, target)
							}
							entry.Command, entry.Image, entry.Arguments = strings.TrimSpace(target+" "+args), target, strings.TrimSpace(args) != ""
						}
					}
				}
			}
			if !add(entry) {
				return
			}
		}
	}
}

// limitedBuffer keeps at most max bytes and then fails the write.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("output too large")
	}
	return b.Buffer.Write(p)
}

// wmiSubscriptions lists WMI event consumers in root\subscription with the
// filters bound to them.
func wmiSubscriptions(ctx context.Context, add func(protocol.PersistenceEntry) bool, n *notes) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	exe := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	script := `$ErrorActionPreference='SilentlyContinue'; $ns='root/subscription';` +
		`$c=@(Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer | % { [pscustomobject]@{Kind='CommandLineEventConsumer'; Name=[string]$_.Name; Command=[string]$(if ($_.CommandLineTemplate) {$_.CommandLineTemplate} else {$_.ExecutablePath}); Exe=[string]$_.ExecutablePath} }) + @(Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer | % { [pscustomobject]@{Kind='ActiveScriptEventConsumer'; Name=[string]$_.Name; Command=[string]$(if ($_.ScriptFileName) {$_.ScriptFileName} else {$_.ScriptText}); Exe=''} });` +
		`$b=@(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | % { [pscustomobject]@{Consumer=[string]$_.Consumer; Filter=[string]$_.Filter} });` +
		`$f=@(Get-CimInstance -Namespace $ns -ClassName __EventFilter | % { [pscustomobject]@{Name=[string]$_.Name; Query=[string]$_.Query} });` +
		`[pscustomobject]@{Consumers=$c; Bindings=$b; Filters=$f} | ConvertTo-Json -Depth 4 -Compress`
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	out := &limitedBuffer{max: 4 << 20}
	cmd.Stdout, cmd.WaitDelay = out, 5*time.Second
	if e := cmd.Run(); e != nil {
		n.add("WMI subscriptions could not be read")
		return
	}
	var v struct {
		Consumers []struct{ Kind, Name, Command, Exe string }
		Bindings  []struct{ Consumer, Filter string }
		Filters   []struct{ Name, Query string }
	}
	if json.Unmarshal(out.Bytes(), &v) != nil {
		n.add("WMI subscriptions could not be read")
		return
	}
	for _, c := range v.Consumers {
		detail := []string{}
		for _, b := range v.Bindings {
			if strings.Contains(b.Consumer, `"`+c.Name+`"`) {
				for _, f := range v.Filters {
					if strings.Contains(b.Filter, `"`+f.Name+`"`) {
						detail = append(detail, "filter "+f.Name+": "+f.Query)
					}
				}
			}
		}
		entry := protocol.PersistenceEntry{Category: "wmi", Location: `root\subscription\` + c.Kind, Name: c.Name, Command: clip(c.Command, 4096), Detail: clip(strings.Join(detail, "; "), 2048), Arguments: c.Kind == "ActiveScriptEventConsumer"}
		if c.Kind == "CommandLineEventConsumer" {
			entry.Image = resolveImage(c.Command, "wmi", false, "")
			entry.Arguments = hasArguments(c.Command, entry.Image, "")
			if exe := expand(c.Exe); exe != "" {
				entry.Image = ""
				if filepath.IsAbs(exe) {
					entry.Image = exe
				}
			}
		}
		if !add(entry) {
			return
		}
	}
}

// comServer finds the DLL or program a COM class runs in (scheduled task
// COM handlers); classes hosted through an AppID are not resolved.
func comServer(class string) string {
	for _, root := range []string{`Software\Classes\CLSID\`, `Software\WOW6432Node\Classes\CLSID\`} {
		for _, server := range []string{"InprocServer32", "LocalServer32"} {
			k, e := registry.OpenKey(registry.LOCAL_MACHINE, root+class+`\`+server, registry.QUERY_VALUE)
			if e != nil {
				continue
			}
			v, _, e := k.GetStringValue("")
			k.Close()
			if e == nil && v != "" {
				return resolveImage(v, "task", server == "InprocServer32", "")
			}
		}
	}
	return ""
}

func persistence(ctx context.Context, cache *HashCache, n *notes) ([]protocol.PersistenceEntry, error) {
	out := []protocol.PersistenceEntry{}
	add := func(e protocol.PersistenceEntry) bool {
		if len(out) >= maxItems {
			return false
		}
		out = append(out, e)
		return true
	}
	users := profiles()
	readAutoruns(registry.LOCAL_MACHINE, "HKLM", "", "", machineAutoruns, add)
	if loaded, e := registry.USERS.ReadSubKeyNames(-1); e == nil {
		for _, sid := range loaded {
			if !userSID.MatchString(sid) {
				continue
			}
			k, e := registry.OpenKey(registry.USERS, sid, registry.ENUMERATE_SUB_KEYS)
			if e != nil {
				continue
			}
			readAutoruns(k, `HKU\`+sid, sid, users[sid], userAutoruns, add)
			k.Close()
		}
	}
	if svcs, e := services(ctx, cache, n); e == nil {
		for _, d := range svcs {
			if d.StartType == "disabled" {
				continue
			}
			category := "service"
			if strings.Contains(d.Type, "driver") {
				category = "driver"
			}
			where := `HKLM\SYSTEM\CurrentControlSet\Services\` + d.Name
			image := d.Image
			if image == "" && category == "driver" {
				// A driver without an image path loads System32\drivers\<name>.sys.
				image = filepath.Join(systemDir, "drivers", d.Name+".sys")
			}
			add(protocol.PersistenceEntry{Category: category, Location: where, Name: d.Name, Command: d.BinaryPath, Image: image, Arguments: hasArguments(d.BinaryPath, image, ""), Detail: strings.TrimSpace(d.StartType + " start, " + d.State + " " + d.Account)})
			dll, at := d.ServiceDLL, where+`\Parameters`
			if dll == "" {
				// Some services keep ServiceDll in the service key itself.
				if k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+d.Name, registry.QUERY_VALUE); e == nil {
					if v, _, e := k.GetStringValue("ServiceDll"); e == nil && v != "" {
						dll, at = expand(v), where
					}
					k.Close()
				}
			}
			if dll != "" {
				add(protocol.PersistenceEntry{Category: "service_dll", Location: at, Name: d.Name, Command: dll, Image: resolveImage(dll, "service_dll", true, "")})
			}
		}
	} else {
		n.add("services could not be listed")
	}
	if ts, e := tasks(ctx, n); e == nil || len(ts) > 0 {
		for _, t := range ts {
			for _, a := range t.Actions {
				entry := protocol.PersistenceEntry{Category: "task", Location: t.Path, Name: filepath.Base(t.Path), User: t.UserID, Disabled: !t.Enabled, Detail: strings.Join(t.Triggers, ", ")}
				switch {
				case a.Command != "":
					command := strings.TrimSpace(a.Command + " " + a.Arguments)
					entry.Command, entry.Image, entry.Arguments = command, resolveImage(a.Command, "task", false, ""), strings.TrimSpace(a.Arguments) != ""
				case a.ClassID != "":
					entry.Command, entry.Image = "COM handler "+a.ClassID, comServer(a.ClassID)
				default:
					continue
				}
				add(entry)
			}
		}
	}
	startupFolders(users, add)
	wmiSubscriptions(ctx, add, n)
	if len(out) >= maxItems {
		n.add("persistence list truncated")
	}
	// Each program file is hashed (cached) and its signature checked once;
	// a report that reaches the time limit keeps what it has.
	signatures := map[string]*protocol.Signature{}
	for i := range out {
		if ctx.Err() != nil {
			n.add("the time limit was reached: later programs were not hashed or checked")
			break
		}
		e := &out[i]
		if e.Image == "" {
			continue
		}
		e.Image = clip(e.Image, 1024)
		if networkPath(e.Image) {
			e.HashNote = "network_path"
			continue
		}
		info, err := os.Stat(e.Image)
		if errors.Is(err, fs.ErrNotExist) {
			e.HashNote = "not_found"
			continue
		}
		e.SHA256, e.HashNote = cache.Hash(ctx, e.Image)
		if e.HashNote != "" || err != nil || info.Size() > maxHashBytes {
			continue
		}
		key := strings.ToLower(e.Image)
		s, ok := signatures[key]
		if !ok && len(signatures) < maxSignatures {
			s = Signature(e.Image)
			signatures[key] = s
		}
		e.Signature = s
	}
	return out, nil
}
