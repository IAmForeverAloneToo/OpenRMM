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

// Store holds three pools on one database file (WAL):
//   - db, the writer: one connection, every commit synced to disk;
//   - tdb, the telemetry writer: one connection whose commits are not synced
//     (synchronous=NORMAL), for heartbeats and feature reports. A power cut or
//     operating system crash can lose its last commits (agents report again
//     within a minute); every commit of the writer, which shares the WAL file,
//     makes them durable. SQLite lets one of the two write at a time. Its
//     writes run in batches (see telemetry);
//   - rdb, readers: several read-only connections for hot reads (device
//     authentication, pending work, dashboard pages), which in WAL mode never
//     wait for a writer.
type Store struct {
	db  *sql.DB
	tdb *sql.DB
	rdb *sql.DB
	// cdb checkpoints the WAL (see checkpoint).
	cdb             *sql.DB
	stopCheckpoints chan struct{}
	checkpointsDone chan struct{}
	stopOnce        sync.Once
	// The telemetry batches (see telemetry).
	telemetryWrites chan telemetryWrite
	stopTelemetry   chan struct{}
	telemetryDone   chan struct{}
	stmts           statements
	directory       string
	artifactMu      sync.Mutex
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
	// pool opens connections with these settings (see Store).
	pool := func(conns int, txlock string, pragmas ...string) (*sql.DB, error) {
		uri := &url.URL{Scheme: "file", Path: uriPath}
		query := uri.Query()
		for _, p := range append([]string{"busy_timeout(5000)", "foreign_keys(ON)"}, pragmas...) {
			query.Add("_pragma", p)
		}
		query.Set("_txlock", txlock)
		uri.RawQuery = query.Encode()
		db, err := sql.Open("sqlite", uri.String())
		if err != nil {
			return nil, errors.New("cannot open server database")
		}
		db.SetMaxOpenConns(conns)
		db.SetMaxIdleConns(conns)
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, errors.New("cannot connect to server database")
		}
		return db, nil
	}
	// The writers never checkpoint the WAL themselves (a commit that does
	// would stall its request); the checkpointer does, in the background.
	db, err := pool(1, "immediate", "synchronous(FULL)", "wal_autocheckpoint(0)", "journal_size_limit(67108864)")
	if err != nil {
		return nil, err
	}
	var opened []*sql.DB
	fail := func(err error) (*Store, error) {
		for _, d := range append(opened, db) {
			_ = d.Close()
		}
		return nil, err
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil || journalMode != "wal" {
		return fail(errors.New("cannot enable SQLite write-ahead logging"))
	}
	if err := migrate(ctx, db); err != nil {
		return fail(err)
	}
	tdb, err := pool(1, "immediate", "synchronous(NORMAL)", "wal_autocheckpoint(0)", "journal_size_limit(67108864)")
	if err != nil {
		return fail(err)
	}
	opened = append(opened, tdb)
	rdb, err := pool(readers, "deferred", "query_only(1)")
	if err != nil {
		return fail(err)
	}
	opened = append(opened, rdb)
	cdb, err := pool(1, "deferred", "synchronous(FULL)", "journal_size_limit(67108864)")
	if err != nil {
		return fail(err)
	}
	s := &Store{db: db, tdb: tdb, rdb: rdb, cdb: cdb, directory: directory, stopCheckpoints: make(chan struct{}), checkpointsDone: make(chan struct{}),
		telemetryWrites: make(chan telemetryWrite), stopTelemetry: make(chan struct{}), telemetryDone: make(chan struct{})}
	go s.checkpoint()
	go s.writeTelemetry()
	return s, nil
}

// readers is the number of read-only connections.
const readers = 8

// checkpointEvery is how often the checkpointer copies the WAL into the
// database.
const checkpointEvery = time.Second

// restartFrames is the WAL length (pages) at which the checkpointer makes
// the WAL start over (about 40 MiB).
const restartFrames = 10000

// checkpoint copies committed WAL pages into the database every second, on
// its own connection. A passive checkpoint never waits for readers or
// writers. With readers always busy the WAL could still never start over
// (checkpoint starvation), so past restartFrames a restart checkpoint waits
// for the readers of the moment (milliseconds) and the WAL begins again;
// journal_size_limit then shrinks the file.
func (s *Store) checkpoint() {
	defer close(s.checkpointsDone)
	t := time.NewTicker(checkpointEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stopCheckpoints:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			var busy, frames, done int64
			if s.cdb.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &done) == nil && frames > restartFrames {
				_, _ = s.cdb.ExecContext(ctx, "PRAGMA wal_checkpoint(RESTART)")
			}
			cancel()
		}
	}
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
	// Close may be called more than once; the background work stops once.
	s.stopOnce.Do(func() {
		close(s.stopTelemetry)
		close(s.stopCheckpoints)
	})
	<-s.telemetryDone
	<-s.checkpointsDone
	s.stmts.close()
	// A last full checkpoint leaves the WAL empty.
	_, _ = s.cdb.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return errors.Join(s.cdb.Close(), s.rdb.Close(), s.tdb.Close(), s.db.Close())
}
func (s *Store) Ready(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Info(ctx context.Context) (Info, error) {
	var info Info
	if err := s.rdb.QueryRowContext(ctx, "SELECT instance_id, created_at FROM server_state WHERE id = 1").Scan(&info.InstanceID, &info.CreatedAt); err != nil {
		return Info{}, errors.New("cannot read server installation state")
	}
	if err := s.rdb.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&info.SchemaVersion); err != nil {
		return Info{}, errors.New("cannot read server schema version")
	}
	return info, nil
}
