package storage

import (
	"context"
	"database/sql"
	"sync"
)

// Hot queries are prepared once and reused: parsing SQL on every request
// is most of their cost, and parallel readers parsing at once contend for
// SQLite's shared allocator lock. A *sql.Stmt is safe for concurrent use and
// keeps a prepared copy per connection.

// maxStatements bounds the cache (queries built from a set of kinds come in
// a bounded number of variants).
const maxStatements = 256

type statements struct {
	mu   sync.Mutex
	list map[*sql.DB]map[string]*sql.Stmt
	n    int
}

// prepared returns the cached statement for query on pool, preparing it on
// first use; with the cache full it returns nil and the caller runs the
// query unprepared.
func (c *statements) prepared(ctx context.Context, pool *sql.DB, query string) (*sql.Stmt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.list[pool][query]; st != nil {
		return st, nil
	}
	if c.n >= maxStatements {
		return nil, nil
	}
	st, err := pool.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	if c.list == nil {
		c.list = map[*sql.DB]map[string]*sql.Stmt{}
	}
	if c.list[pool] == nil {
		c.list[pool] = map[string]*sql.Stmt{}
	}
	c.list[pool][query] = st
	c.n++
	return st, nil
}

// lookup returns the cached statement for query on pool, or nil.
func (c *statements) lookup(pool *sql.DB, query string) *sql.Stmt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.list[pool][query]
}

func (c *statements) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.list {
		for _, st := range m {
			_ = st.Close()
		}
	}
	c.list, c.n = nil, 0
}

// queryRow runs a hot single-row read on the readers, prepared.
func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	if st, err := s.stmts.prepared(ctx, s.rdb, query); err == nil && st != nil {
		return st.QueryRowContext(ctx, args...)
	}
	return s.rdb.QueryRowContext(ctx, query, args...)
}

// query runs a hot read on the readers, prepared.
func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if st, err := s.stmts.prepared(ctx, s.rdb, query); err == nil && st != nil {
		return st.QueryContext(ctx, args...)
	}
	return s.rdb.QueryContext(ctx, query, args...)
}
