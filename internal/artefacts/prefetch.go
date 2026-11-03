package artefacts

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/prefetch"
)

var prefetchTable = Def{
	Name:    "prefetch",
	Title:   "Prefetch",
	Columns: []string{"SourceFile", "Executable", "ExecutablePath", "Hash", "Version", "RunCount", "LastRun", "PreviousRuns", "Volumes", "FileCount", "Files"},
	Times:   []string{"LastRun", "PreviousRuns"},
	Events:  []EventDef{{Time: "LastRun", What: "Program ran", Path: "ExecutablePath", Details: []string{"Executable", "RunCount"}}, {Time: "PreviousRuns", What: "Program ran", Path: "ExecutablePath", Details: []string{"Executable", "RunCount"}}},
}

var prefetchParser = parser{
	table: prefetchTable.Name,
	match: func(source, p string) bool {
		return source == "triage" && strings.HasSuffix(p, ".pf") && strings.Contains(p, `\prefetch\`)
	},
	max: prefetch.MaxFile,
	parse: func(_ context.Context, o *Output, f file) error {
		b, e := readAll(f, prefetch.MaxFile)
		if e != nil {
			return e
		}
		i, e := prefetch.Parse(b)
		if e != nil {
			return e
		}
		var last string
		var previous, volumes []string
		for k, t := range i.Runs {
			if k == 0 {
				last = Stamp(t)
			} else {
				previous = append(previous, Stamp(t))
			}
		}
		for _, v := range i.Volumes {
			volumes = append(volumes, fmt.Sprintf("%s serial %08X created %s", v.Device, v.Serial, Stamp(v.Created)))
		}
		return o.Add(prefetchTable, f.path, []string{
			f.path, i.Executable, i.Path(), fmt.Sprintf("%08X", i.Hash), strconv.Itoa(i.Version), strconv.FormatUint(uint64(i.RunCount), 10),
			last, strings.Join(previous, "|"), strings.Join(volumes, "|"), strconv.Itoa(len(i.Files)), strings.Join(i.Files, "|"),
		})
	},
}
