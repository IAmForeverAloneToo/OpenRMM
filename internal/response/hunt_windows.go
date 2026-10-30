package response

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

// huntSourcesFor are the Windows sources of an indicator hunt.
func huntSourcesFor(cache *HashCache, n *notes) huntSources {
	return huntSources{
		processes:   func(ctx context.Context) ([]protocol.ProcessDetail, error) { return processList(ctx, cache, n) },
		connections: func(ctx context.Context) ([]protocol.Connection, error) { return connections(ctx, n) },
		dns:         dnsCache,
		persistence: func(ctx context.Context) ([]protocol.PersistenceEntry, error) { return persistence(ctx, cache, n) },
		roots:       huntRoots,
		hash: func(ctx context.Context, path string, want hashSet) (fileHashes, string) {
			return hashFile(ctx, huntFiles, path, want)
		},
		mft: filetransfer.NTFSFiles,
	}
}

// huntRoots are the common locations: each user profile's
// Downloads, Desktop and AppData (which holds the user's Temp and Startup
// folders), ProgramData, the Windows Temp folder, the Public profile, and the
// files at the root of each fixed drive (not their subfolders).
func huntRoots() []huntRoot {
	var out []huntRoot
	users := profiles()
	dirs := make([]string, 0, len(users))
	for _, p := range users {
		dirs = append(dirs, p)
	}
	sort.Strings(dirs)
	for _, p := range dirs {
		for _, sub := range []string{"Downloads", "Desktop", "AppData"} {
			out = append(out, huntRoot{dir: filepath.Join(p, sub)})
		}
	}
	for _, d := range []string{os.Getenv("ProgramData"), filepath.Join(os.Getenv("SystemRoot"), "Temp"), os.Getenv("PUBLIC")} {
		if filepath.IsAbs(d) && !networkPath(d) {
			out = append(out, huntRoot{dir: d})
		}
	}
	mask, e := windows.GetLogicalDrives()
	if e != nil {
		return out
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, e := windows.UTF16PtrFromString(root)
		if e == nil && windows.GetDriveType(p) == windows.DRIVE_FIXED {
			out = append(out, huntRoot{dir: root, shallow: true})
		}
	}
	return out
}

// dnsCache reads the DNS client cache (names and record data) with a fixed
// PowerShell command.
func dnsCache(ctx context.Context) ([]dnsRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	exe := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	script := `$ErrorActionPreference='Stop'; @(Get-DnsClientCache | Select-Object -First 20000 | % { [pscustomobject]@{N=[string]$_.Entry; D=[string]$_.Data} }) | ConvertTo-Json -Compress`
	cmd := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	out := &limitedBuffer{max: 8 << 20}
	cmd.Stdout, cmd.WaitDelay = out, 5*time.Second
	if e := cmd.Run(); e != nil {
		return nil, e
	}
	text := strings.TrimSpace(out.String())
	if text == "" {
		return nil, nil
	}
	var list []struct{ N, D string }
	if strings.HasPrefix(text, "{") {
		text = "[" + text + "]"
	}
	if e := json.Unmarshal([]byte(text), &list); e != nil {
		return nil, e
	}
	records := make([]dnsRecord, 0, len(list))
	for _, r := range list {
		records = append(records, dnsRecord{name: clip(r.N, 255), data: clip(r.D, 255)})
	}
	return records, nil
}
