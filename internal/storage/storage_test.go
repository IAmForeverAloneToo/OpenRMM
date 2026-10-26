package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoragePersistsAndMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private data", "server #1.db")
	ctx := context.Background()
	first, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := first.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.SchemaVersion != 51 || len(before.InstanceID) != 32 {
		t.Fatalf("unexpected state: %+v", before)
	}
	created, err := time.Parse(time.RFC3339Nano, before.CreatedAt)
	if err != nil || created.Location() != time.UTC {
		t.Fatalf("creation time must be UTC: %v", err)
	}
	if err := first.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, err := second.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("persistent state changed across reopen: before=%+v after=%+v", before, after)
	}
	var count int
	if err := second.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil || count != 51 {
		t.Fatalf("migration applied more than once: %d, %v", count, err)
	}
}

func TestStorageRejectsIncompatibleMigrationHistory(t *testing.T) {
	for _, test := range []struct{ name, query, message string }{
		{"newer", "INSERT INTO schema_migrations VALUES (52, '052_future.sql', 'future', '2026-10-16T00:00:00Z')", "newer"},
		{"modified", "UPDATE schema_migrations SET checksum = 'changed' WHERE version = 1", "does not match"},
		{"gap", "UPDATE schema_migrations SET version = 52 WHERE version = 1", "newer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "data", "server.db")
			store, err := Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(test.query); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if incompatible, err := Open(context.Background(), path); err == nil {
				incompatible.Close()
				t.Fatal("incompatible schema accepted")
			} else if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestStorageForeignKeysAndReadiness(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "data", "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	var foreignKeys int
	if err := store.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign keys disabled: %v", err)
	}
	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil || journalMode != "wal" {
		t.Fatalf("WAL disabled: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Ready(context.Background()); err == nil {
		t.Fatal("closed storage reports ready")
	}
}

func TestFailedMigrationIsRolledBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A conflicting pre-existing table causes the first migration to fail.
	if _, err := db.Exec("CREATE TABLE server_state (unexpected INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := migrate(context.Background(), db); err == nil {
		t.Fatal("conflicting schema accepted")
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='schema_migrations'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed migration left partial history: %d, %v", count, err)
	}
}
