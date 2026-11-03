package artefacts

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/evtx"
)

var eventsTable = Def{Name: "event_logs", Title: "Event logs",
	Columns: []string{"TimeCreated", "Channel", "EventID", "Level", "Provider", "EventRecordID", "Computer", "UserID", "ProcessID", "ThreadID", "Task", "Opcode", "Keywords", "Data", "SourceFile"},
	Times:   []string{"TimeCreated"}}

// maxEventLog is the largest event log parsed.
const maxEventLog = 4 << 30

var levels = map[string]string{"0": "Information", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}

var eventLogParser = parser{
	table: eventsTable.Name,
	match: func(source, p string) bool {
		return source == "evtx" || source == "triage" && strings.HasSuffix(p, ".evtx") && strings.Contains(p, `\winevt\logs\`)
	},
	max: maxEventLog,
	parse: func(ctx context.Context, o *Output, f file) error {
		r, size, done, err := spool(o, f, maxEventLog)
		if err != nil {
			return err
		}
		defer done()
		n := 0
		st, err := evtx.Scan(r, size, func(e evtx.Event) error {
			if n++; n%10000 == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			s := e.System
			level := levels[s["Level"]]
			if level == "" {
				level = s["Level"]
			}
			var data []string
			for _, d := range e.Data {
				data = append(data, d.Name+"="+d.Value)
			}
			return o.Add(eventsTable, f.path, []string{s["TimeCreated"], s["Channel"], s["EventID"], level, s["Provider"], s["EventRecordID"], s["Computer"], s["UserID"],
				s["ProcessID"], s["ThreadID"], s["Task"], s["Opcode"], s["Keywords"], strings.Join(data, " | "), f.path})
		})
		if err != nil {
			return err
		}
		if st.BadChunks > 0 || st.BadRecords > 0 {
			o.Fail(f.path, eventsTable.Name, errors.New(plural(st.BadChunks, "damaged chunk")+" and "+plural(st.BadRecords, "damaged record")+" skipped"))
		}
		return nil
	},
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

// spool gives random access to a file: a single-file collection is read
// where it is; a package entry is unpacked into the temporary folder.
func spool(o *Output, f file, max int64) (io.ReaderAt, int64, func(), error) {
	rc, err := f.open()
	if err != nil {
		return nil, 0, nil, err
	}
	if ra, ok := rc.(*os.File); ok {
		return ra, f.size, func() { ra.Close() }, nil
	}
	defer rc.Close()
	tmp, err := os.CreateTemp(o.dir, "source-*")
	if err != nil {
		return nil, 0, nil, err
	}
	done := func() { tmp.Close(); os.Remove(tmp.Name()) }
	n, err := io.Copy(tmp, io.LimitReader(rc, max+1))
	if err != nil || n > max {
		done()
		if err == nil {
			err = errors.New("the file is larger than this parser reads")
		}
		return nil, 0, nil, err
	}
	return tmp, n, done, nil
}
