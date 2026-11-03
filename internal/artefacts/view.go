package artefacts

import (
	"encoding/csv"
	"errors"
	"io"
	"slices"
	"strings"
)

// ErrCorrupt reports a table that does not read as CSV; ErrNoColumn a
// filter on a column the table does not have.
var (
	ErrCorrupt  = errors.New("the table cannot be read")
	ErrNoColumn = errors.New("the table has no such column")
)

// Filter selects rows. Times are in TimeLayout and bound (inclusively) any
// time in the table's time columns.
type Filter struct {
	// Contains matches any cell, case-insensitively.
	Contains string
	From, To string
	// Column and Equals keep rows whose cell in that column equals the
	// text, ignoring case (or one of its values separated by "|").
	Column, Equals string
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

// Query reads a table and returns the matching rows from offset on,
// stopping once the page is full. times names the table's time columns.
func Query(r io.Reader, times []string, f Filter, offset, limit int) (Page, error) {
	if offset < 0 || limit < 1 || limit > MaxPage {
		return Page{}, errors.New("invalid page")
	}
	c := csv.NewReader(r)
	c.ReuseRecord = true
	header, err := c.Read()
	if err != nil {
		return Page{}, ErrCorrupt
	}
	p := Page{Columns: slices.Clone(header), Rows: [][]string{}, Offset: offset}
	var cols []int
	for i, h := range header {
		if slices.Contains(times, h) {
			cols = append(cols, i)
		}
	}
	contains := strings.ToLower(f.Contains)
	column := -1
	if f.Column != "" {
		if column = slices.Index(header, f.Column); column < 0 {
			return Page{}, ErrNoColumn
		}
	}
	match := func(row []string) bool {
		if contains != "" && !slices.ContainsFunc(row, func(cell string) bool { return strings.Contains(strings.ToLower(cell), contains) }) {
			return false
		}
		if column >= 0 && !strings.EqualFold(row[column], f.Equals) && !slices.ContainsFunc(strings.Split(row[column], "|"), func(v string) bool { return strings.EqualFold(strings.TrimSpace(v), f.Equals) }) {
			return false
		}
		if f.From == "" && f.To == "" {
			return true
		}
		for _, i := range cols {
			for t := range strings.SplitSeq(row[i], "|") {
				if t != "" && (f.From == "" || t >= f.From) && (f.To == "" || t <= f.To) {
					return true
				}
			}
		}
		return false
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
			p.Rows = append(p.Rows, slices.Clone(row))
		}
		seen++
	}
}
