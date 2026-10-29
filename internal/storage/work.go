package storage

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// workTables names where each kind of agent work waits to be dispatched.
var workTables = map[string]string{
	protocol.WorkFiles:     "file_jobs",
	protocol.WorkScripts:   "script_runs",
	protocol.WorkProcesses: "process_actions",
	protocol.WorkServices:  "service_actions",
	protocol.WorkEvents:    "event_log_queries",
	protocol.WorkUpdates:   "update_jobs",
	protocol.WorkUpgrades:  "agent_upgrade_jobs",
}

// PendingWork returns which of the given kinds have work queued for a device.
// It only reads: dispatch still happens through each kind's poll.
func (s *Store) PendingWork(ctx context.Context, device string, kinds []string) ([]string, error) {
	out := []string{}
	query, args := "", []any{}
	for _, k := range kinds {
		table, ok := workTables[k]
		if !ok {
			continue
		}
		if query != "" {
			query += " UNION ALL "
		}
		query += "SELECT ? WHERE EXISTS(SELECT 1 FROM " + table + " WHERE device_id=? AND status='queued')"
		args = append(args, k, device)
	}
	if query == "" {
		return out, nil
	}
	rows, e := s.db.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if e = rows.Scan(&k); e != nil {
			return nil, e
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
