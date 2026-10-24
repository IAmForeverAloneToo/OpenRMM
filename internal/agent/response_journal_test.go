package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The response journal runs a job at most once across restarts.
func TestResponseJournal(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1800000000, 0)
	j, err := openJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, other := "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	if _, seen, err := j.begin(id, "evidence", true, now); seen || err != nil {
		t.Fatal("first begin", seen, err)
	}
	if _, _, err := j.begin(id, "isolation", true, now); err == nil {
		t.Fatal("a job ID reused for another kind was accepted")
	}
	if _, seen, err := j.begin(other, "isolation", false, now); seen || err != nil {
		t.Fatal(err)
	}
	// After a restart: the started evidence job resumes, the started
	// non-resumable job is refused, a finished job only returns its result.
	j, err = openJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e, seen, err := j.begin(id, "evidence", true, now); !seen || err != nil || e.State != "started" {
		t.Fatal("resume", e, seen, err)
	}
	if _, _, err := j.begin(other, "isolation", false, now); err == nil {
		t.Fatal("non-resumable job started twice")
	}
	if err := j.finish(id, map[string]string{"outcome": "ok"}, now); err != nil {
		t.Fatal(err)
	}
	j, _ = openJournal(dir)
	e, seen, err := j.begin(id, "evidence", true, now)
	var result map[string]string
	if !seen || err != nil || e.State != "finished" || json.Unmarshal(e.Result, &result) != nil || result["outcome"] != "ok" {
		t.Fatal("replay", e, seen, err)
	}
	// Entries older than the retention go at the next write.
	if _, _, err := j.begin("00000000000000000000000000000001", "evidence", true, now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if j, _ = openJournal(dir); len(j.entries) != 1 {
		t.Fatal("retention", len(j.entries))
	}
	// A damaged journal stops response work instead of risking a replay.
	if err := os.WriteFile(filepath.Join(dir, responseJournalFile), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(dir); err == nil {
		t.Fatal("damaged journal accepted")
	}
}
