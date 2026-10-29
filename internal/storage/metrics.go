package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"time"
)

// MetricBucketLimit is the least number of buckets kept per resolution
// across all devices; the bound grows with the fleet (metricLimit).
const MetricBucketLimit = 100000

// metricPerDevice is the buckets per device for each resolution: cpu, memory and disk
// over the retention (2 days of 5-minute buckets, 30 days of hourly ones).
var metricPerDevice = map[int64]int64{300: 3 * 2 * 288, 3600: 3 * 30 * 24}

// metricLimit bounds a resolution so every active device keeps its full
// retention, with a margin.
func metricLimit(ctx context.Context, tx *sql.Tx, step int64) (int64, error) {
	var devices int64
	if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL").Scan(&devices); e != nil {
		return 0, e
	}
	return max(MetricBucketLimit, devices*metricPerDevice[step]*11/10), nil
}

var ErrMetrics = errors.New("invalid metric history request")

type MetricWindow struct {
	Range string `json:"range"`
	From  int64  `json:"from"`
	Until int64  `json:"until"`
	Step  int64  `json:"step_seconds"`
}

func MetricsWindow(name string, now time.Time) (MetricWindow, error) {
	if name == "" {
		name = "24h"
	}
	duration, step := int64(86400), int64(300)
	switch name {
	case "24h":
	case "7d":
		duration, step = 7*86400, 3600
	case "30d":
		duration, step = 30*86400, 3600
	default:
		return MetricWindow{}, ErrMetrics
	}
	return MetricWindow{name, (now.Unix() - duration) / step * step, now.Unix(), step}, nil
}

type MetricBucket struct {
	DeviceID string   `json:"device_id"`
	Kind     string   `json:"kind"`
	At       int64    `json:"at"`
	Count    int64    `json:"valid_observations"`
	Unknown  int64    `json:"unavailable_reports"`
	Gaps     int64    `json:"detected_gaps"`
	Mean     *float64 `json:"mean_percent"`
	Min      *float64 `json:"min_percent"`
	Max      *float64 `json:"max_percent"`
	First    int64    `json:"first_at"`
	Last     int64    `json:"last_at"`
}

type MetricHistory struct {
	MetricWindow
	Buckets []MetricBucket `json:"buckets"`
}

// Called only inside the authenticated collector write transaction. Never use
// the retained latest snapshot: a failed report is an unavailable observation.
func captureMetric(ctx context.Context, tx *sql.Tx, id, kind, status string, raw json.RawMessage, now time.Time) error {
	var value any
	if status == "ok" {
		switch kind {
		case "cpu":
			var p protocol.CPU
			if json.Unmarshal(raw, &p) == nil && cpu.Valid(p) {
				value = p.UsagePercent
			}
		case "memory":
			var p protocol.Memory
			if json.Unmarshal(raw, &p) == nil && memory.Valid(p) {
				value = 100 * (1 - float64(p.AvailableBytes)/float64(p.TotalBytes))
			}
		case "disk_space":
			var p protocol.DiskSpace
			if json.Unmarshal(raw, &p) == nil && diskspace.Valid(p) {
				value = 100 * (1 - float64(p.AvailableBytes)/float64(p.TotalBytes))
			}
		default:
			return ErrMetrics
		}
	}
	at := now.Unix() / 60 * 60
	var previous int64
	e := tx.QueryRowContext(ctx, "SELECT last_at FROM metric_receipts WHERE device_id=? AND kind=?", id, kind).Scan(&previous)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil && at <= previous {
		return nil
	}
	gap := 0
	period := int64(60)
	if kind == "disk_space" {
		period = 300
	}
	if e == nil && at-previous > 2*period {
		gap = 1
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO metric_receipts VALUES(?,?,?) ON CONFLICT(device_id,kind) DO UPDATE SET last_at=excluded.last_at", id, kind, at); e != nil {
		return e
	}
	valid, unknown := 0, 1
	sum := 0.0
	if value != nil {
		valid, unknown = 1, 0
		sum = value.(float64)
	}
	// Old buckets are pruned by the housekeeping (PruneMetrics), not on
	// this write path, which runs for every report.
	for _, step := range []int64{300, 3600} {
		bucket := at / step * step
		if _, e = tx.ExecContext(ctx, `INSERT INTO metric_buckets(device_id,kind,step,bucket,valid_count,unknown_count,gap_count,sum_value,min_value,max_value,first_at,last_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,kind,step,bucket) DO UPDATE SET
		valid_count=valid_count+excluded.valid_count,unknown_count=unknown_count+excluded.unknown_count,gap_count=gap_count+excluded.gap_count,
		sum_value=sum_value+excluded.sum_value,
		min_value=CASE WHEN excluded.min_value IS NULL THEN min_value WHEN min_value IS NULL THEN excluded.min_value ELSE MIN(min_value,excluded.min_value) END,
		max_value=CASE WHEN excluded.max_value IS NULL THEN max_value WHEN max_value IS NULL THEN excluded.max_value ELSE MAX(max_value,excluded.max_value) END,
		last_at=excluded.last_at`, id, kind, step, bucket, valid, unknown, gap, sum, value, value, at, at); e != nil {
			return e
		}
	}
	return nil
}

func pruneMetricStep(ctx context.Context, tx *sql.Tx, step int64, now time.Time) error {
	age := int64(30 * 86400)
	if step == 300 {
		age = 2 * 86400
	}
	if _, e := tx.ExecContext(ctx, "DELETE FROM metric_buckets WHERE step=? AND bucket<?", step, (now.Unix()-age)/step*step); e != nil {
		return e
	}
	limit, e := metricLimit(ctx, tx, step)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `DELETE FROM metric_buckets WHERE (device_id,kind,step,bucket) IN
	(SELECT device_id,kind,step,bucket FROM metric_buckets WHERE step=? ORDER BY bucket,device_id,kind LIMIT (SELECT MAX(COUNT(*)-?,0) FROM metric_buckets WHERE step=?))`, step, limit, step)
	return e
}

func (s *Store) PruneMetrics(ctx context.Context, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, step := range []int64{300, 3600} {
		if e = pruneMetricStep(ctx, tx, step, now); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM metric_receipts WHERE last_at<?", now.Add(-30*24*time.Hour).Unix()); e != nil {
		return e
	}
	return tx.Commit()
}

func validMetricWindow(w MetricWindow) bool {
	if w.Until <= 0 {
		return false
	}
	want, e := MetricsWindow(w.Range, time.Unix(w.Until, 0))
	return e == nil && want == w
}

func scanMetric(row interface{ Scan(...any) error }) (MetricBucket, error) {
	var b MetricBucket
	e := row.Scan(&b.DeviceID, &b.Kind, &b.At, &b.Count, &b.Unknown, &b.Gaps, &b.Mean, &b.Min, &b.Max, &b.First, &b.Last)
	return b, e
}

// Callers must authorize current read scope before accessing history or exports.
func (s *Store) MetricHistory(ctx context.Context, id string, w MetricWindow) (MetricHistory, error) {
	return s.MetricHistoryForSession(ctx, Session{}, id, w)
}
func (s *Store) MetricHistoryForSession(ctx context.Context, v Session, id string, w MetricWindow) (MetricHistory, error) {
	out := MetricHistory{MetricWindow: w, Buckets: []MetricBucket{}}
	if !protocol.ValidID(id) || !validMetricWindow(w) {
		return out, ErrMetrics
	}
	scope, args := technicianScope(v, "metric_buckets.device_id")
	args = append([]any{id, w.Step, w.From, w.Until, w.Until}, args...)
	rows, e := s.db.QueryContext(ctx, `SELECT device_id,kind,bucket,valid_count,unknown_count,gap_count,sum_value/NULLIF(valid_count,0),min_value,max_value,first_at,last_at FROM metric_buckets
 WHERE device_id=? AND step=? AND bucket>=? AND bucket<=? AND last_at<=? AND (`+scope+`) ORDER BY kind,bucket LIMIT 2200`, args...)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		b, e := scanMetric(rows)
		if e != nil {
			return out, e
		}
		out.Buckets = append(out.Buckets, b)
	}
	return out, rows.Err()
}

// Summaries return one row per requested device/kind, including empty series.
func (s *Store) MetricSummaries(ctx context.Context, ids []string, w MetricWindow) ([]MetricBucket, error) {
	return s.MetricSummariesForSession(ctx, Session{}, ids, w)
}
func (s *Store) MetricSummariesForSession(ctx context.Context, v Session, ids []string, w MetricWindow) ([]MetricBucket, error) {
	if len(ids) > 1000 || !validMetricWindow(w) {
		return nil, ErrMetrics
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	scope, scopeArgs := technicianScope(v, "metric_buckets.device_id")
	if v.Technician != nil && len(ids) > 0 {
		args := []any{}
		for _, id := range ids {
			if !protocol.ValidID(id) {
				return nil, ErrMetrics
			}
			args = append(args, id)
		}
		allowedScope, accountArgs := technicianScope(v, "devices.id")
		args = append(args, accountArgs...)
		rows, e := tx.QueryContext(ctx, "SELECT id FROM devices WHERE id IN ("+strings.TrimRight(strings.Repeat("?,", len(ids)), ",")+") AND ("+allowedScope+")", args...)
		if e != nil {
			return nil, e
		}
		allowed := map[string]bool{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return nil, e
			}
			allowed[id] = true
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		filtered := []string{}
		for _, id := range ids {
			if allowed[id] {
				filtered = append(filtered, id)
			}
		}
		ids = filtered
	}
	out := []MetricBucket{}
	positions := map[string]int{}
	args := []any{w.Step, w.From, w.Until, w.Until}
	for _, id := range ids {
		if !protocol.ValidID(id) {
			return nil, ErrMetrics
		}
		for _, kind := range []string{"cpu", "memory", "disk_space"} {
			key := id + kind
			if _, ok := positions[key]; ok {
				return nil, ErrMetrics
			}
			positions[key] = len(out)
			out = append(out, MetricBucket{DeviceID: id, Kind: kind})
		}
		args = append(args, id)
	}
	if len(ids) == 0 {
		return out, tx.Commit()
	}
	query := `SELECT device_id,kind,MIN(bucket),SUM(valid_count),SUM(unknown_count),SUM(gap_count),SUM(sum_value)/NULLIF(SUM(valid_count),0),MIN(min_value),MAX(max_value),MIN(first_at),MAX(last_at) FROM metric_buckets WHERE step=? AND bucket>=? AND bucket<=? AND last_at<=? AND device_id IN (` + strings.TrimRight(strings.Repeat("?,", len(ids)), ",") + `) AND (` + scope + `) GROUP BY device_id,kind`
	args = append(args, scopeArgs...)
	rows, e := tx.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		b, e := scanMetric(rows)
		if e != nil {
			return nil, e
		}
		out[positions[b.DeviceID+b.Kind]] = b
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	return out, tx.Commit()
}
