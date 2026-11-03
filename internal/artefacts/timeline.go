package artefacts

import (
	"bufio"
	"compress/flate"
	"container/heap"
	"encoding/csv"
	"io"
	"os"
	"slices"
	"strings"
)

// EventDef puts a table's rows on the combined timeline: the time column
// (a cell may hold several times separated by "|"), what happened ({Col}
// is replaced by that column's value), and the columns naming the item
// and describing it.
type EventDef struct {
	Time    string
	What    string
	Path    string
	Details []string
}

var timelineTable = Def{Name: "timeline", Title: "Combined timeline",
	Columns: []string{"Time", "Artifact", "Event", "Path", "Details", "SourceFile"}, Times: []string{"Time"}}

// runSize events are sorted in memory before they go to a run file.
var runSize = 200_000

// maxDetails bounds an event's details.
const maxDetails = 2000

// timeline collects events and sorts them through run files.
type timeline struct {
	rows [][]string
	runs []*os.File
}

// event adds the timeline events of a row.
func (o *Output) event(d Def, source string, row []string) error {
	for _, ev := range d.Events {
		at := slices.Index(d.Columns, ev.Time)
		if at < 0 || row[at] == "" {
			continue
		}
		what := ev.What
		for i, c := range d.Columns {
			if strings.Contains(what, "{") {
				what = strings.ReplaceAll(what, "{"+c+"}", row[i])
			}
		}
		path := ""
		if i := slices.Index(d.Columns, ev.Path); i >= 0 {
			path = row[i]
		}
		var details []string
		for _, c := range ev.Details {
			if i := slices.Index(d.Columns, c); i >= 0 && row[i] != "" {
				details = append(details, c+"="+row[i])
			}
		}
		text := strings.Join(details, "; ")
		if len(text) > maxDetails {
			text = text[:maxDetails] + "…"
		}
		for t := range strings.SplitSeq(row[at], "|") {
			if t == "" {
				continue
			}
			o.tl.rows = append(o.tl.rows, []string{t, d.Title, what, path, text, source})
			if len(o.tl.rows) >= runSize {
				if err := o.spill(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func byTime(a, b []string) int { return strings.Compare(a[0], b[0]) }

// spill sorts the events in memory into a compressed run file.
func (o *Output) spill() error {
	slices.SortStableFunc(o.tl.rows, byTime)
	f, err := os.CreateTemp(o.dir, "timeline-*")
	if err != nil {
		return err
	}
	o.tl.runs = append(o.tl.runs, f)
	buf := bufio.NewWriterSize(f, 1<<16)
	z, _ := flate.NewWriter(buf, flate.BestSpeed)
	w := csv.NewWriter(z)
	if err := w.WriteAll(o.tl.rows); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	o.tl.rows = o.tl.rows[:0]
	return nil
}

// cursor reads one sorted run.
type cursor struct {
	r   *csv.Reader
	row []string
	n   int
}

type cursors []*cursor

func (c cursors) Len() int { return len(c) }
func (c cursors) Less(i, j int) bool {
	if x := byTime(c[i].row, c[j].row); x != 0 {
		return x < 0
	}
	return c[i].n < c[j].n
}
func (c cursors) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c *cursors) Push(x any)   { *c = append(*c, x.(*cursor)) }
func (c *cursors) Pop() any {
	old := *c
	x := old[len(old)-1]
	*c = old[:len(old)-1]
	return x
}

// writeTimeline merges the runs and the events in memory, oldest first,
// into the timeline table.
func (o *Output) writeTimeline() error {
	if len(o.tl.runs) == 0 && len(o.tl.rows) == 0 {
		return nil
	}
	if err := o.spill(); err != nil {
		return err
	}
	h := &cursors{}
	for i, f := range o.tl.runs {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		c := &cursor{r: csv.NewReader(flate.NewReader(bufio.NewReaderSize(f, 1<<16))), n: i}
		c.r.ReuseRecord = false
		if row, err := c.r.Read(); err == nil {
			c.row = row
			heap.Push(h, c)
		} else if err != io.EOF {
			return err
		}
	}
	for h.Len() > 0 {
		c := (*h)[0]
		if err := o.add(timelineTable, c.row[5], c.row); err != nil {
			return err
		}
		row, err := c.r.Read()
		switch {
		case err == io.EOF:
			heap.Pop(h)
		case err != nil:
			return err
		default:
			c.row = row
			heap.Fix(h, 0)
		}
	}
	// The timeline is listed first.
	i := slices.Index(o.order, timelineTable.Name)
	o.order = append([]string{timelineTable.Name}, slices.Delete(o.order, i, i+1)...)
	return nil
}

func (o *Output) closeTimeline() {
	for _, f := range o.tl.runs {
		f.Close()
		os.Remove(f.Name())
	}
}
