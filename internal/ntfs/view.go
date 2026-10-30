package ntfs

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
)

// Filter selects timeline rows. Times are in the timeline's own format
// (2006-01-02 15:04:05.0000000, UTC), which sorts as text.
type Filter struct {
	// Contains matches the full path, case-insensitively.
	Contains string
	// From and To bound the time (inclusive): for $MFT any of the eight
	// timestamps, for the change journal the update time.
	From, To string
	// Deleted keeps $MFT records that are not in use and journal entries
	// with the FileDelete reason.
	Deleted bool
	// Reasons keeps journal entries with any of these reason names.
	Reasons []string
}

// Page is one page of matching rows.
type Page struct {
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
	Offset  int        `json:"offset"`
	// More reports that more rows match after this page.
	More bool `json:"more"`
}

// MaxPage is the most rows one page returns.
const MaxPage = 500

// QueryCSV reads a timeline (mft.csv or usn.csv) and returns the matching
// rows from offset on. It stops reading once the page is full, so early
// pages are quick even for millions of rows.
func QueryCSV(r io.Reader, f Filter, offset, limit int) (Page, error) {
	if offset < 0 || limit < 1 || limit > MaxPage {
		return Page{}, errors.New("invalid page")
	}
	c := csv.NewReader(r)
	c.ReuseRecord = true
	header, err := c.Read()
	if err != nil {
		return Page{}, ErrCorrupt
	}
	p := Page{Columns: append([]string(nil), header...), Rows: [][]string{}, Offset: offset}
	match, err := matcher(header, f)
	if err != nil {
		return Page{}, err
	}
	seen := 0
	for {
		row, err := c.Read()
		if err == io.EOF {
			return p, nil
		}
		if err != nil {
			return p, ErrCorrupt
		}
		if !match(row) {
			continue
		}
		if seen >= offset {
			if len(p.Rows) == limit {
				p.More = true
				return p, nil
			}
			p.Rows = append(p.Rows, append([]string(nil), row...))
		}
		seen++
	}
}

func matcher(header []string, f Filter) (func([]string) bool, error) {
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	usn := strings.Join(header, ",") == strings.Join(USNColumns, ",")
	if !usn && strings.Join(header, ",") != strings.Join(MFTColumns, ",") {
		return nil, ErrCorrupt
	}
	contains := strings.ToLower(f.Contains)
	var times []int
	if usn {
		times = []int{col["UpdateTimestamp"]}
	} else {
		for _, h := range []string{"Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30"} {
			times = append(times, col[h])
		}
	}
	name, parent := col["FileName"], col["ParentPath"]
	if usn {
		name = col["Name"]
	}
	inUse, reasons := col["InUse"], col["UpdateReasons"]
	for _, r := range f.Reasons {
		if ReasonBit(r) == 0 {
			return nil, errors.New("unknown reason")
		}
	}
	return func(row []string) bool {
		if contains != "" && !strings.Contains(strings.ToLower(Join(row[parent], row[name])), contains) {
			return false
		}
		if f.From != "" || f.To != "" {
			in := false
			for _, i := range times {
				t := row[i]
				if t != "" && (f.From == "" || t >= f.From) && (f.To == "" || t <= f.To) {
					in = true
					break
				}
			}
			if !in {
				return false
			}
		}
		if f.Deleted {
			if usn && !hasReason(row[reasons], "FileDelete") || !usn && row[inUse] != "false" {
				return false
			}
		}
		if usn && len(f.Reasons) > 0 {
			any := false
			for _, r := range f.Reasons {
				if hasReason(row[reasons], r) {
					any = true
					break
				}
			}
			if !any {
				return false
			}
		}
		return true
	}, nil
}

func hasReason(text, name string) bool {
	for _, r := range strings.Split(text, "|") {
		if strings.EqualFold(r, name) {
			return true
		}
	}
	return false
}
