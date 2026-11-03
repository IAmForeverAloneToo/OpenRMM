package artefacts

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/lnk"
)

var (
	lnkTable = Def{Name: "lnk_files", Title: "Shortcuts (LNK)",
		Columns: []string{"SourceFile", "ShortcutModified", "TargetPath", "Arguments", "WorkingDir", "Name", "TargetCreated", "TargetModified", "TargetAccessed", "TargetSize", "DriveType", "VolumeSerial", "VolumeLabel", "NetworkPath", "MachineID", "MAC"},
		Times:   []string{"ShortcutModified", "TargetCreated", "TargetModified", "TargetAccessed"}}
	jumpTable = Def{Name: "jump_lists", Title: "Jump lists",
		Columns: []string{"SourceFile", "AppID", "Type", "Entry", "Path", "LastAccess", "Pinned", "AccessCount", "Hostname", "TargetPath", "Arguments", "TargetCreated", "TargetModified", "TargetAccessed", "VolumeSerial", "MachineID"},
		Times:   []string{"LastAccess", "TargetCreated", "TargetModified", "TargetAccessed"}}
)

func size(n uint32) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(n), 10)
}

var lnkParser = parser{
	table: lnkTable.Name,
	match: func(source, p string) bool { return source == "triage" && strings.HasSuffix(p, ".lnk") },
	max:   lnk.MaxFile,
	parse: func(_ context.Context, o *Output, f file) error {
		b, err := readAll(f, lnk.MaxFile)
		if err != nil {
			return err
		}
		l, err := lnk.Parse(b)
		if err != nil {
			return err
		}
		return o.Add(lnkTable, f.path, []string{f.path, Stamp(f.modified), l.TargetPath, l.Arguments, l.WorkingDir, l.Name, Stamp(l.Created), Stamp(l.Modified), Stamp(l.Accessed),
			size(l.Size), l.DriveType, l.VolumeSerial, l.VolumeLabel, l.NetworkPath, l.MachineID, l.MAC})
	},
}

var jumpListParser = parser{
	table: jumpTable.Name,
	match: func(source, p string) bool {
		return source == "triage" && (strings.HasSuffix(p, ".automaticdestinations-ms") || strings.HasSuffix(p, ".customdestinations-ms"))
	},
	max: lnk.MaxFile,
	parse: func(_ context.Context, o *Output, f file) error {
		b, err := readAll(f, lnk.MaxFile)
		if err != nil {
			return err
		}
		name := filepath.Base(strings.ReplaceAll(f.path, `\`, "/"))
		app, kind, _ := strings.Cut(name, ".")
		var entries []lnk.Entry
		if strings.EqualFold(kind, "automaticDestinations-ms") {
			kind = "automatic"
			if entries, err = lnk.Automatic(b); err != nil {
				return err
			}
		} else {
			kind = "custom"
			entries = lnk.Custom(b)
		}
		for _, e := range entries {
			if e.Err != nil {
				o.Fail(f.path, jumpTable.Name, e.Err)
				continue
			}
			pinned, count := "", ""
			if kind == "automatic" && e.Path != "" {
				pinned, count = strconv.FormatBool(e.Pinned), strconv.FormatUint(uint64(e.AccessCount), 10)
			}
			if err := o.Add(jumpTable, f.path, []string{f.path, app, kind, e.Stream, e.Path, Stamp(e.LastAccess), pinned, count, e.Hostname, e.TargetPath, e.Arguments,
				Stamp(e.Created), Stamp(e.Modified), Stamp(e.Accessed), e.VolumeSerial, e.MachineID}); err != nil {
				return err
			}
		}
		return nil
	},
}
