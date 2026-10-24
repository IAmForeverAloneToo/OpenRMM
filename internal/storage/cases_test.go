package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
)

// Case actions form a verifiable hash chain; the custody log and
// cases refuse change and deletion; closed cases accept no entries.
func TestCaseCustodyChainIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	c, e := s.CreateCase(ctx, "Suspicious logon on PC-1", "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"", " padded", strings.Repeat("x", 201), "bell\a"} {
		if _, e := s.CreateCase(ctx, bad, "owner", now); !errors.Is(e, ErrCase) {
			t.Fatalf("title %q accepted", bad)
		}
	}
	if e = s.AddCaseNote(ctx, c.ID, "owner", "Collected the logon events.\nNext: memory.", now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.SetCaseStatus(ctx, c.ID, "closed", "owner", "Benign: admin maintenance", now.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.AddCaseNote(ctx, c.ID, "owner", "late note", now.Add(3*time.Minute)); !errors.Is(e, ErrCase) {
		t.Fatal("note added to a closed case", e)
	}
	if e = s.SetCaseStatus(ctx, c.ID, "closed", "owner", "", now); !errors.Is(e, ErrCase) {
		t.Fatal("closed twice", e)
	}
	if e = s.SetCaseStatus(ctx, c.ID, "open", "owner", "New evidence", now.Add(4*time.Minute)); e != nil {
		t.Fatal(e)
	}

	d, e := s.CaseDetail(ctx, c.ID)
	if e != nil || !d.Verified || len(d.Entries) != 4 || d.Status != "open" || d.Entries[0].Action != "case_opened" || d.Entries[2].Details["reason"] != "Benign: admin maintenance" || d.Head != d.Entries[3].Hash {
		t.Fatalf("detail %+v %v", d, e)
	}
	_, records, _ := s.CaseRecords(ctx, c.ID)
	if head, e := custody.Verify(c.ID, records); e != nil || head != d.Head {
		t.Fatal("chain", e)
	}

	for _, q := range []string{"UPDATE custody_entries SET entry_json='x'", "DELETE FROM custody_entries", "DELETE FROM cases"} {
		if _, e := s.db.Exec(q); e == nil || !strings.Contains(e.Error(), "append-only") && !strings.Contains(e.Error(), "not deleted") {
			t.Fatalf("%s allowed: %v", q, e)
		}
	}
	// Tampering below the triggers (for example editing the file) is detected.
	if _, e = s.db.Exec("DROP TRIGGER custody_append_only_update"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE custody_entries SET entry_json=replace(entry_json,'logon events','nothing') WHERE sequence=2"); e != nil {
		t.Fatal(e)
	}
	if d, _ = s.CaseDetail(ctx, c.ID); d.Verified || !strings.Contains(d.Problem, "entry 2") {
		t.Fatal("tampering not detected", d.Problem)
	}
	if list, e := s.Cases(ctx); e != nil || len(list) != 1 || list[0].Entries != 4 {
		t.Fatal("list", list, e)
	}
}
