// Package storage owns SQLite connections and versioned schema migrations.
package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Store struct {
	db         *sql.DB
	directory  string
	artifactMu sync.Mutex
	// The evidence directory and its total quota in bytes; set
	// once at start-up by UseEvidence.
	evidence      string
	evidenceQuota int64
	// Transcripts being stored (Close waits for them), the jobs
	// still recording, and a lock that serializes storing.
	transcripts  sync.WaitGroup
	recordingMu  sync.Mutex
	recording    map[string]bool
	transcriptMu sync.Mutex
}

// Info is available only through the local CLI, never the public health route.
type Info struct {
	SchemaVersion int    `json:"schema_version"`
	InstanceID    string `json:"instance_id"`
	CreatedAt     string `json:"created_at"`
}

func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("a database file path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("cannot resolve database path")
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(filepath.Dir(directory), 0700); err != nil {
		return nil, errors.New("cannot create storage parent directory")
	}
	if err := privatefs.CreateDirectory(directory); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("cannot create private storage directory")
	}
	// URI encoding prevents filenames containing '?' or '#' from becoming SQL
	// driver options. Windows drive paths use SQLite's file:///C:/... form.
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := &url.URL{Scheme: "file", Path: uriPath}
	query := uri.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, errors.New("cannot open server database")
	}
	// One connection bounds resource use and serializes writes for this prototype.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*Store, error) { _ = db.Close(); return nil, err }
	if err := db.PingContext(ctx); err != nil {
		return fail(errors.New("cannot connect to server database"))
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil || journalMode != "wal" {
		return fail(errors.New("cannot enable SQLite write-ahead logging"))
	}
	if err := migrate(ctx, db); err != nil {
		return fail(err)
	}
	return &Store{db: db, directory: directory}, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	files, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return errors.New("cannot read embedded migrations")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin database migration")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY CHECK (version > 0),
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )`); err != nil {
		return errors.New("cannot initialize migration history")
	}
	rows, err := tx.QueryContext(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return errors.New("cannot read migration history")
	}
	type applied struct {
		version        int
		name, checksum string
	}
	var history []applied
	for rows.Next() {
		var item applied
		if err := rows.Scan(&item.version, &item.name, &item.checksum); err != nil {
			_ = rows.Close()
			return errors.New("cannot decode migration history")
		}
		history = append(history, item)
	}
	iterationErr := rows.Err()
	_ = rows.Close()
	if iterationErr != nil {
		return errors.New("cannot read complete migration history")
	}
	if len(history) > len(files) {
		return errors.New("database schema is newer than this server; use a compatible build or restore a backup")
	}
	for _, item := range history {
		if item.version > len(files) {
			return errors.New("database schema is newer than this server; use a compatible build or restore a backup")
		}
	}
	for index, file := range files {
		version := index + 1
		if file.IsDir() || !strings.HasPrefix(file.Name(), fmt.Sprintf("%03d_", version)) {
			return errors.New("embedded migration sequence is invalid")
		}
		body, err := migrationFiles.ReadFile("migrations/" + file.Name())
		if err != nil {
			return errors.New("cannot read embedded migration")
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(body))
		if index < len(history) {
			item := history[index]
			if item.version > len(files) {
				return errors.New("database schema is newer than this server; use a compatible build or restore a backup")
			}
			if item.version != version || item.name != file.Name() || item.checksum != checksum {
				return errors.New("database migration history does not match this build")
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return errors.New("cannot apply database migration")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)", version, file.Name(), checksum, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("cannot record database migration")
		}
	}
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return errors.New("cannot generate server installation identity")
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO server_state (id, instance_id, created_at) VALUES (1, ?, ?)", hex.EncodeToString(identifier), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("cannot initialize server installation state")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("cannot commit database migration")
	}
	return nil
}

func (s *Store) Close() error {
	s.transcripts.Wait()
	return s.db.Close()
}
func (s *Store) Ready(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Info(ctx context.Context) (Info, error) {
	var info Info
	if err := s.db.QueryRowContext(ctx, "SELECT instance_id, created_at FROM server_state WHERE id = 1").Scan(&info.InstanceID, &info.CreatedAt); err != nil {
		return Info{}, errors.New("cannot read server installation state")
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&info.SchemaVersion); err != nil {
		return Info{}, errors.New("cannot read server schema version")
	}
	return info, nil
}
