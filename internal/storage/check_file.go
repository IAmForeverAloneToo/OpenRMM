package storage

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
)

// CheckFile verifies a database copy without changing it (server update
// backups): a read-only connection runs SQLite's integrity check and checks
// that a schema is present.
func CheckFile(ctx context.Context, path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("invalid database path")
	}
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := &url.URL{Scheme: "file", Path: uriPath}
	query := uri.Query()
	query.Set("mode", "ro")
	query.Add("_pragma", "busy_timeout(5000)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return errors.New("cannot open the database copy")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var result string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil || result != "ok" {
		return errors.New("the database copy is damaged")
	}
	var version int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil || version < 1 {
		return errors.New("the database copy has no schema")
	}
	return nil
}
