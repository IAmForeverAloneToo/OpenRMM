package storage

import (
	"context"
	"sort"
	"time"
)

// FleetOperation is one recorded unit of device work, labelled for display.
type FleetOperation struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Actor    string `json:"actor"`
	At       int64  `json:"at"`
}

type FleetActivity struct {
	Running []FleetOperation `json:"running"`
	Recent  []FleetOperation `json:"recent"`
}

// FleetActivity is a read-only projection across the operation tables. It never
// dispatches, expires or retries work. Job kinds are included only when the
// current account holds the matching feature permission, so a technician sees
// neither owner-only job types nor event or file work they cannot perform.
func (s *Store) FleetActivity(ctx context.Context, v Session, now time.Time, limit int) (FleetActivity, error) {
	out := FleetActivity{Running: []FleetOperation{}, Recent: []FleetOperation{}}
	if limit < 1 || limit > 100 {
		limit = 20
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
		tables = append(tables,
			struct{ table, kind, extra string }{"update_jobs", "updates", ""},
			struct{ table, kind, extra string }{"script_runs", "scripts", " AND NOT EXISTS(SELECT 1 FROM application_deployments p WHERE p.run_id=a.id)"})
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	for _, entry := range tables {
		scope, args := technicianScope(v, "a.device_id")
		args = append([]any{now.Unix()}, args...)
		base := "SELECT a.id,a.status,a.device_id,d.hostname,a.actor,COALESCE(a.finished_at,a.dispatched_at,a.created_at) FROM " + entry.table +
			" a JOIN devices d ON d.id=a.device_id WHERE a.created_at<=? AND (" + scope + ")" + entry.extra
		for _, part := range []struct {
			where string
			into  *[]FleetOperation
		}{
			{" AND a.status IN('staged','queued','dispatched','running')", &out.Running},
			{" AND a.status NOT IN('staged','queued','dispatched','running')", &out.Recent},
		} {
			rows, e := tx.QueryContext(ctx, base+part.where+" ORDER BY COALESCE(a.finished_at,a.dispatched_at,a.created_at) DESC,a.id DESC LIMIT ?", append(args, limit)...)
			if e != nil {
				return out, e
			}
			for rows.Next() {
				q := FleetOperation{Kind: entry.kind}
				if e = rows.Scan(&q.ID, &q.Status, &q.DeviceID, &q.Hostname, &q.Actor, &q.At); e != nil {
					rows.Close()
					return out, e
				}
				*part.into = append(*part.into, q)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return out, e
			}
		}
	}
	for _, list := range []*[]FleetOperation{&out.Running, &out.Recent} {
		sort.Slice(*list, func(i, j int) bool {
			a, b := (*list)[i], (*list)[j]
			if a.At != b.At {
				return a.At > b.At
			}
			return a.Kind+a.ID > b.Kind+b.ID
		})
		if len(*list) > limit {
			*list = (*list)[:limit]
		}
	}
	return out, tx.Commit()
}
