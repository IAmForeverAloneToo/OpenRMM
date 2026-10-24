package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The update backup check accepts a database copy, does not
// change it, and refuses a damaged file.
func TestCheckFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	before, _ := os.ReadFile(path)
	if e = CheckFile(ctx, path); e != nil {
		t.Fatal(e)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("check changed the copy")
	}
	bad := filepath.Join(dir, "bad.db")
	os.WriteFile(bad, []byte("not a database at all, just text that is long enough"), 0600)
	if CheckFile(ctx, bad) == nil {
		t.Fatal("damaged file accepted")
	}
}

// A setup redone from the link never replaces a confirmed
// administrator.
func TestReplaceUnconfirmedAdministrator(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	admin := Administrator{Username: "owner", PasswordHash: "h", TOTPCipher: []byte("c")}
	if e = s.SetAdministrator(ctx, admin, nil, false, now); e != nil {
		t.Fatal(e)
	}
	if e = s.ReplaceUnconfirmedAdministrator(ctx, admin, nil, now); e != nil {
		t.Fatal("unconfirmed setup not replaced", e)
	}
	if _, e = s.db.Exec("UPDATE administrators SET mfa_confirmed=1"); e != nil {
		t.Fatal(e)
	}
	if e = s.ReplaceUnconfirmedAdministrator(ctx, admin, nil, now); e != ErrAlreadyConfigured {
		t.Fatal("confirmed administrator replaced", e)
	}
}
