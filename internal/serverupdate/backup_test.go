package serverupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// liveFixture adds the live-backup functions to the update fixture.
func liveFixture(t *testing.T) *fixture {
	f := newFixture(t)
	f.u.Backups.Snapshot = func(src, dst string) error { return copyFile(src, dst, 0600) }
	f.u.Backups.Inspect = func(string) (string, int, error) { return "installation-1", 51, nil }
	return f
}

// A live backup copies the database with Snapshot (never its WAL files),
// and an exported backup imports elsewhere unchanged.
func TestLiveBackupExportImport(t *testing.T) {
	f := liveFixture(t)
	os.WriteFile(filepath.Join(f.data, "openrmm.db-wal"), []byte("wal"), 0600)
	name := "nightly-20270115-030000"
	if e := f.u.Backups.CreateLive(name); e != nil {
		t.Fatal(e)
	}
	files, e := f.u.Backups.Verify(name)
	if e != nil || !slices.Contains(files, "data/openrmm.db") || slices.Contains(files, "data/openrmm.db-wal") || !slices.Contains(files, "secrets/admin-key.bin") {
		t.Fatal("live backup contents", files, e)
	}
	list, e := f.u.Backups.List()
	if e != nil || len(list) != 1 || !list[0].Live || list[0].Kind != "nightly" || list[0].InstanceID != "installation-1" || list[0].SchemaVersion != 51 || list[0].Size == 0 {
		t.Fatal("listing", list, e)
	}
	if e := f.u.Backups.CreateLive(name); e == nil {
		t.Fatal("existing backup replaced")
	}
	var archive bytes.Buffer
	if e := f.u.Backups.Export(name, &archive); e != nil {
		t.Fatal(e)
	}
	other := Backups{Dir: t.TempDir(), Sources: f.u.Backups.Sources, DB: "openrmm.db"}
	got, e := other.Import(bytes.NewReader(archive.Bytes()))
	if e != nil || got != name {
		t.Fatal("import", got, e)
	}
	if _, e := other.Verify(name); e != nil {
		t.Fatal(e)
	}
	if _, e := other.Import(bytes.NewReader(archive.Bytes())); e == nil || !strings.Contains(e.Error(), "already exists") {
		t.Fatal("import replaced an existing backup", e)
	}
	// Entries outside the backup's folder are refused and nothing is kept.
	var bad bytes.Buffer
	tw := tar.NewWriter(&bad)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "manual-20270115-030000/../../escape", Mode: 0600, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	if _, e := other.Import(bytes.NewReader(gzipped(t, bad.Bytes()))); e == nil {
		t.Fatal("escaping entry accepted")
	}
	if entries := backupDirs(other.Dir); len(entries) != 1 {
		t.Fatal("refused import left files", entries)
	}
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

// Each kind keeps its own number of backups; interrupted backups are
// removed once they are a day old.
func TestPruneKinds(t *testing.T) {
	f := liveFixture(t)
	for day := 1; day <= 9; day++ {
		if e := f.u.Backups.CreateLive(NewBackupName("nightly", time.Date(2027, 1, day, 3, 0, 0, 0, time.UTC))); e != nil {
			t.Fatal(e)
		}
	}
	for _, n := range []string{"update-20270101-000000-1", "update-20270102-000000-2", "update-20270103-000000-3", "manual-20270101-120000"} {
		if e := f.u.Backups.Create(n); e != nil {
			t.Fatal(e)
		}
	}
	old, fresh := filepath.Join(f.u.Backups.Dir, partPrefix+"nightly-20261231-030000"), filepath.Join(f.u.Backups.Dir, partPrefix+"manual-20270110-030000")
	os.Mkdir(old, 0700)
	os.Mkdir(fresh, 0700)
	os.Chtimes(old, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	if e := f.u.Backups.Prune(); e != nil {
		t.Fatal(e)
	}
	count := map[string]int{}
	list, _ := f.u.Backups.List()
	for _, b := range list {
		count[b.Kind]++
	}
	if count["nightly"] != 7 || count["update"] != 2 || count["manual"] != 1 || list[0].Name != "nightly-20270109-030000" {
		t.Fatal("pruned", count, list)
	}
	if _, e := os.Stat(old); e == nil {
		t.Fatal("old interrupted backup kept")
	}
	if _, e := os.Stat(fresh); e != nil {
		t.Fatal("a backup still being written was removed")
	}
}

// A restore keeps the replaced state as a safety backup, carries current
// revocations over and puts the previous state back when the restored
// database cannot be prepared.
func TestRestoreSafely(t *testing.T) {
	f := liveFixture(t)
	name := "manual-20270115-030000"
	if e := f.u.Backups.CreateLive(name); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("database v2"), 0600)
	var reconciled map[string]int64
	o := RestoreOptions{
		Now:     time.Date(2027, 1, 16, 9, 0, 0, 0, time.UTC),
		Revoked: func(string) (map[string]int64, error) { return map[string]int64{"dev-a": 50}, nil },
		Reconcile: func(db string, revoked map[string]int64) error {
			if f.read(db) != "database v1" {
				return errors.New("reconciled the wrong database")
			}
			reconciled = revoked
			return nil
		},
		Revocations: &Revocations{Format: 1, InstanceID: "installation-1", Revoked: map[string]int64{"dev-a": 40, "dev-b": 60}},
	}
	result, e := f.u.Backups.RestoreSafely(name, o)
	if e != nil || result.Carried != 1 || result.Safety != "pre-restore-20270116-090000" {
		t.Fatal(result, e)
	}
	if f.read(filepath.Join(f.data, "openrmm.db")) != "database v1" || reconciled["dev-a"] != 40 || reconciled["dev-b"] != 60 {
		t.Fatal("restore", f.read(filepath.Join(f.data, "openrmm.db")), reconciled)
	}
	if f.read(filepath.Join(f.u.Backups.Dir, result.Safety, "data", "openrmm.db")) != "database v2" {
		t.Fatal("safety backup does not hold the replaced state")
	}
	// A failure after the files were replaced puts the previous state back.
	os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("database v3"), 0600)
	o.Now = o.Now.Add(time.Hour)
	o.Reconcile = func(string, map[string]int64) error { return errors.New("schema newer than this build") }
	if _, e := f.u.Backups.RestoreSafely(name, o); e == nil || !strings.Contains(e.Error(), "put back") {
		t.Fatal("failed restore", e)
	}
	if f.read(filepath.Join(f.data, "openrmm.db")) != "database v3" {
		t.Fatal("previous state not put back")
	}
	o.Revocations.InstanceID = "installation-2"
	if _, e := f.u.Backups.RestoreSafely(name, o); e == nil || !strings.Contains(e.Error(), "another installation") {
		t.Fatal("revocations of another installation accepted", e)
	}
}

// The nightly backup runs once per scheduled slot, catches up after a missed
// slot, and a dashboard request takes a manual backup at once.
func TestNightlySchedule(t *testing.T) {
	f := liveFixture(t)
	ctx := context.Background()
	nightly := func() []string {
		var out []string
		list, _ := f.u.Backups.List()
		for _, b := range list {
			if b.Kind == "nightly" {
				out = append(out, b.Name)
			}
		}
		return out
	}
	f.now = time.Date(2027, 1, 15, 2, 0, 0, 0, time.UTC)
	// Nothing to back up before the server has created its database.
	inspect := f.u.Backups.Inspect
	f.u.Backups.Inspect = func(string) (string, int, error) { return "", 0, errors.New("no schema") }
	f.u.backups(ctx)
	if len(nightly()) != 0 || f.u.lastRun != nil {
		t.Fatal("backup attempted before the database exists")
	}
	f.u.Backups.Inspect = inspect
	f.u.backups(ctx) // missed the slot of the 14th (default 03:00): catch up
	f.now = f.now.Add(time.Hour)
	f.u.backups(ctx)
	f.now = f.now.Add(30 * time.Minute)
	f.u.backups(ctx)
	if got := nightly(); len(got) != 2 || got[0] != "nightly-20270115-030000" || got[1] != "nightly-20270115-020000" {
		t.Fatal("nightly backups", got)
	}
	if e := WriteSchedule(f.u.Dir, BackupSchedule{Enabled: false, Hour: 5}); e != nil {
		t.Fatal(e)
	}
	f.now = time.Date(2027, 1, 16, 6, 0, 0, 0, time.UTC)
	f.u.backups(ctx)
	if len(nightly()) != 2 {
		t.Fatal("disabled schedule ran")
	}
	if e := SubmitBackupRequest(f.u.Dir, BackupRequest{ID: "0123456789abcdef0123456789abcdef", RequestedBy: "owner", RequestedAt: f.now.Unix()}); e != nil {
		t.Fatal(e)
	}
	f.u.backups(ctx)
	r, e := ReadBackupReport(f.u.Dir)
	if e != nil || r.Last == nil || !r.Last.OK || r.Last.Kind != "manual" || r.Last.ID != "0123456789abcdef0123456789abcdef" || r.Schedule.Enabled || r.NextAt != 0 || len(r.Backups) != 3 {
		t.Fatal("report", r, e)
	}
	if _, e := os.Stat(filepath.Join(f.u.Dir, BackupRequestFile)); e == nil {
		t.Fatal("request left behind")
	}
	// A failed nightly backup is tried again after an hour, not at once.
	os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("corrupt"), 0600)
	WriteSchedule(f.u.Dir, BackupSchedule{Enabled: true, Hour: 5})
	f.u.backups(ctx)
	if r, _ = ReadBackupReport(f.u.Dir); r.Last == nil || r.Last.OK || r.Last.Kind != "nightly" || r.NextAt != time.Date(2027, 1, 17, 5, 0, 0, 0, time.UTC).Unix() {
		t.Fatal("failed run", r.Last)
	}
	started := r.Last.StartedAt
	f.now = f.now.Add(10 * time.Minute)
	f.u.backups(ctx)
	if r, _ = ReadBackupReport(f.u.Dir); r.Last.StartedAt != started {
		t.Fatal("failed backup retried at once")
	}
}

// Evidence exports are incremental by time, skip unfinished uploads, and
// imports check every file against the hash in its name.
func TestEvidenceExportImport(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	content := []byte("collected evidence")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	path := filepath.Join(src, "sha256", hash[:2], hash)
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, content, 0400)
	os.MkdirAll(filepath.Join(src, "incoming"), 0700)
	os.WriteFile(filepath.Join(src, "incoming", "job.part"), []byte("partial"), 0600)
	var all bytes.Buffer
	if n, e := ExportEvidence(src, 0, &all); e != nil || n != 1 {
		t.Fatal("export", n, e)
	}
	var none bytes.Buffer
	if n, e := ExportEvidence(src, time.Now().Add(time.Hour).Unix(), &none); e != nil || n != 0 {
		t.Fatal("incremental export", n, e)
	}
	if n, e := ExportEvidence(t.TempDir(), 0, &none); e != nil || n != 0 {
		t.Fatal("empty store", n, e)
	}
	for _, want := range [][2]int{{1, 0}, {0, 1}} {
		added, skipped, e := ImportEvidence(dst, bytes.NewReader(all.Bytes()))
		if e != nil || added != want[0] || skipped != want[1] {
			t.Fatal("import", added, skipped, e)
		}
	}
	if f, _ := os.ReadFile(filepath.Join(dst, "sha256", hash[:2], hash)); !bytes.Equal(f, content) {
		t.Fatal("imported content")
	}
	var forged bytes.Buffer
	tw := tar.NewWriter(&forged)
	name := "sha256/" + hash[:2] + "/" + hash[:63] + "0"
	if name == "sha256/"+hash[:2]+"/"+hash {
		name = "sha256/" + hash[:2] + "/" + hash[:63] + "1"
	}
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0400, Size: int64(len(content))})
	tw.Write(content)
	tw.Close()
	if _, _, e := ImportEvidence(dst, &forged); e == nil {
		t.Fatal("file not matching its hash accepted")
	}
	if _, e := os.Stat(filepath.Join(dst, filepath.FromSlash(name))); e == nil {
		t.Fatal("forged file kept")
	}
}
