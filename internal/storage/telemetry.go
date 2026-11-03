package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Telemetry writes (heartbeats and feature reports) arrive hundreds of times
// a second on a large fleet, and SQLite takes one writer at a time. They run
// in batches on the telemetry connection: the writes waiting when a batch
// starts commit together, each in its own savepoint so a failing write
// leaves the others intact. Their statements are prepared once on that
// connection; parsing SQL was most of a write's cost.

// maxTelemetryBatch bounds how many writes commit together.
const maxTelemetryBatch = 128

// errClosed is returned for writes that arrive after Close.
var errClosed = errors.New("storage is closed")

// execer runs statements: a transaction, or a write in a telemetry batch.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type telemetryWrite struct {
	ctx  context.Context
	fn   func(context.Context, *telemetryTx) error
	done chan error
}

// telemetryTx is a telemetry batch's transaction. Statements prepared on
// the telemetry connection are reused; others run unprepared and are
// prepared after the batch.
type telemetryTx struct {
	tx      *sql.Tx
	s       *Store
	missing map[string]bool
	// durable is set by a write that must reach the disk.
	durable bool
}

// durable marks a telemetry write that adds audit or custody entries: its
// batch commits with a full sync, as other writes do.
func durable(tx execer) {
	if t, ok := tx.(*telemetryTx); ok {
		t.durable = true
	}
}

func (t *telemetryTx) stmt(ctx context.Context, query string) *sql.Stmt {
	if st := t.s.stmts.lookup(t.s.tdb, query); st != nil {
		return t.tx.StmtContext(ctx, st)
	}
	t.missing[query] = true
	return nil
}

func (t *telemetryTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if st := t.stmt(ctx, query); st != nil {
		return st.ExecContext(ctx, args...)
	}
	return t.tx.ExecContext(ctx, query, args...)
}

func (t *telemetryTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if st := t.stmt(ctx, query); st != nil {
		return st.QueryContext(ctx, args...)
	}
	return t.tx.QueryContext(ctx, query, args...)
}

func (t *telemetryTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if st := t.stmt(ctx, query); st != nil {
		return st.QueryRowContext(ctx, args...)
	}
	return t.tx.QueryRowContext(ctx, query, args...)
}

// telemetry runs fn as one write of the next telemetry batch and returns its
// result once the batch has committed. fn runs on the batch's context, not
// the caller's: cancelling one request must not interrupt the others' writes.
func (s *Store) telemetry(ctx context.Context, fn func(context.Context, *telemetryTx) error) error {
	w := telemetryWrite{ctx: ctx, fn: fn, done: make(chan error, 1)}
	select {
	case s.telemetryWrites <- w:
	case <-s.stopTelemetry:
		return errClosed
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case e := <-w.done:
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}

// writeTelemetry runs the batches until Close.
func (s *Store) writeTelemetry() {
	defer close(s.telemetryDone)
	for {
		var batch []telemetryWrite
		select {
		case <-s.stopTelemetry:
			return
		case w := <-s.telemetryWrites:
			batch = append(batch, w)
		}
	more:
		for len(batch) < maxTelemetryBatch {
			select {
			case w := <-s.telemetryWrites:
				batch = append(batch, w)
			default:
				break more
			}
		}
		s.commitTelemetry(batch)
	}
}

func (s *Store) commitTelemetry(batch []telemetryWrite) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	missing := map[string]bool{}
	results, durable, e := s.runTelemetry(ctx, batch, missing)
	if e == nil && durable {
		// A write added audit or custody entries, which must reach the disk.
		// The sync level cannot change inside a transaction, so the batch
		// runs again with a full sync.
		if _, e = s.tdb.ExecContext(ctx, "PRAGMA synchronous=FULL"); e == nil {
			results, _, e = s.runTelemetry(ctx, batch, missing)
			if _, reset := s.tdb.ExecContext(ctx, "PRAGMA synchronous=NORMAL"); e == nil {
				e = reset
			}
		}
	}
	for i, w := range batch {
		if e != nil && (results == nil || results[i] == nil) {
			w.done <- e
		} else {
			w.done <- results[i]
		}
	}
	// The connection is free again: prepare what the batch ran unprepared.
	for query := range missing {
		_, _ = s.stmts.prepared(ctx, s.tdb, query)
	}
}

// runTelemetry runs a batch in one transaction, each write in a savepoint.
// It commits unless a write needs a full sync (durable) and none is set.
func (s *Store) runTelemetry(ctx context.Context, batch []telemetryWrite, missing map[string]bool) ([]error, bool, error) {
	var full int
	if e := s.tdb.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&full); e != nil {
		return nil, false, e
	}
	tx, e := s.tdb.BeginTx(ctx, nil)
	if e != nil {
		return nil, false, e
	}
	defer tx.Rollback()
	t := &telemetryTx{tx: tx, s: s, missing: missing}
	results := make([]error, len(batch))
	for i, w := range batch {
		if results[i] = w.ctx.Err(); results[i] != nil {
			continue
		}
		if _, e = t.ExecContext(ctx, "SAVEPOINT telemetry"); e != nil {
			return results, false, e
		}
		if results[i] = w.fn(ctx, t); results[i] != nil {
			_, e = t.ExecContext(ctx, "ROLLBACK TO telemetry")
		}
		if e == nil {
			_, e = t.ExecContext(ctx, "RELEASE telemetry")
		}
		if e != nil {
			return results, false, e
		}
	}
	// PRAGMA synchronous reads 2 for FULL.
	if t.durable && full < 2 {
		return results, true, nil
	}
	return results, false, tx.Commit()
}
