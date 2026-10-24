package storage

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"sort"
	"time"
)

type WorkspaceOperation struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	At     int64  `json:"at"`
}
type WorkspaceActivity struct {
	Pending      int                  `json:"pending"`
	ActiveAlerts int                  `json:"active_alerts"`
	Recent       []WorkspaceOperation `json:"recent"`
}

// This read-only projection never dispatches, expires or retries work. Metadata
// is restricted independently of the page: file execution and owner-only job
// types are omitted when the current account lacks their feature permission.
func (s *Store) WorkspaceActivity(ctx context.Context, v Session, id string, now time.Time) (WorkspaceActivity, error) {
	out := WorkspaceActivity{Recent: []WorkspaceOperation{}}
	if !protocol.ValidID(id) {
		return out, ErrAuthentication
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if v.Technician != nil {
		guard, args := technicianScope(v, "d.id")
		args = append([]any{id}, args...)
		var allowed int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices d WHERE d.id=? AND ("+guard+")", args...).Scan(&allowed); e != nil {
			return out, e
		}
		if allowed != 1 {
			return out, ErrForbidden
		}
	}
	scope, args := technicianScope(v, "a.device_id")
	args = append([]any{id, now.Unix()}, args...)
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts a WHERE a.device_id=? AND a.status='active' AND a.opened_at<=? AND "+scope, args...).Scan(&out.ActiveAlerts); e != nil {
		return out, e
	}
	tables := []struct{ table, kind, extra string }{
		{"service_actions", "services", ""}, {"process_actions", "processes", ""},
		{"application_deployments", "applications", ""}, {"agent_upgrade_jobs", "agent-upgrades", ""},
	}
	if v.Can("events") {
		tables = append(tables, struct{ table, kind, extra string }{"event_log_queries", "events", ""})
	}
	if v.Can("files") {
		tables = append(tables, struct{ table, kind, extra string }{"file_jobs", "files", ""})
	}
	if v.Technician == nil {
		tables = append(tables, struct{ table, kind, extra string }{"update_jobs", "updates", ""}, struct{ table, kind, extra string }{"script_runs", "scripts", " AND NOT EXISTS(SELECT 1 FROM application_deployments p WHERE p.run_id=a.id)"})
	}
	for _, entry := range tables {
		scope, args := technicianScope(v, "a.device_id")
		args = append([]any{id, now.Unix()}, args...)
		where := " FROM " + entry.table + " a WHERE a.device_id=? AND a.created_at<=? AND (" + scope + ")" + entry.extra
		var pending int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*)"+where+" AND a.status IN('staged','queued','dispatched','running')", args...).Scan(&pending); e != nil {
			return out, e
		}
		out.Pending += pending
		rows, e := tx.QueryContext(ctx, "SELECT a.id,a.status,COALESCE(a.finished_at,a.dispatched_at,a.created_at)"+where+" ORDER BY COALESCE(a.finished_at,a.dispatched_at,a.created_at) DESC,a.id DESC LIMIT 10", args...)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			q := WorkspaceOperation{Kind: entry.kind}
			if e = rows.Scan(&q.ID, &q.Status, &q.At); e != nil {
				rows.Close()
				return out, e
			}
			out.Recent = append(out.Recent, q)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
	}
	sort.Slice(out.Recent, func(i, j int) bool {
		a, b := out.Recent[i], out.Recent[j]
		if a.At != b.At {
			return a.At > b.At
		}
		return a.Kind+a.ID > b.Kind+b.ID
	})
	if len(out.Recent) > 20 {
		out.Recent = out.Recent[:20]
	}
	return out, tx.Commit()
}
