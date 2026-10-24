package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Saved indicator lists: anyone with the response permission may create,
// change and delete them. A hunt copies the
// indicators, so changing a list never changes a hunt that used it.

const maxIOCLists = 200

var ErrIOCList = errors.New("indicator list unavailable; check the name and indicators")

type IOCList struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Indicators []protocol.Indicator `json:"indicators"`
	CreatedBy  string               `json:"created_by"`
	CreatedAt  int64                `json:"created_at"`
	UpdatedBy  string               `json:"updated_by"`
	UpdatedAt  int64                `json:"updated_at"`
}

func iocListValid(name string, list []protocol.Indicator) bool {
	return validText(name, 100, false) && utf8Text(name) && (protocol.HuntSpec{Indicators: list}).Valid()
}

func (s *Store) IOCLists(ctx context.Context) ([]IOCList, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,name,indicators_json,created_by,created_at,updated_by,updated_at FROM ioc_lists ORDER BY lower(name)`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []IOCList{}
	for rows.Next() {
		var l IOCList
		var raw string
		if e = rows.Scan(&l.ID, &l.Name, &raw, &l.CreatedBy, &l.CreatedAt, &l.UpdatedBy, &l.UpdatedAt); e != nil {
			return nil, e
		}
		if json.Unmarshal([]byte(raw), &l.Indicators) != nil {
			return nil, ErrIOCList
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) IOCList(ctx context.Context, id string) (IOCList, error) {
	var l IOCList
	var raw string
	e := s.db.QueryRowContext(ctx, `SELECT id,name,indicators_json,created_by,created_at,updated_by,updated_at FROM ioc_lists WHERE id=?`, id).Scan(&l.ID, &l.Name, &raw, &l.CreatedBy, &l.CreatedAt, &l.UpdatedBy, &l.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return l, ErrIOCList
	}
	if e != nil {
		return l, e
	}
	if json.Unmarshal([]byte(raw), &l.Indicators) != nil {
		return l, ErrIOCList
	}
	return l, nil
}

// SaveIOCList creates a list (id empty) or replaces one's name and
// indicators. Names are unique, ignoring case.
func (s *Store) SaveIOCList(ctx context.Context, id, name string, list []protocol.Indicator, actor string, now time.Time) (IOCList, error) {
	name = strings.TrimSpace(name)
	if !iocListValid(name, list) || id != "" && !protocol.ValidID(id) {
		return IOCList{}, ErrIOCList
	}
	raw, _ := json.Marshal(list)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return IOCList{}, e
	}
	defer tx.Rollback()
	event := "ioc_list_changed"
	if id == "" {
		var n int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ioc_lists`).Scan(&n); e != nil || n >= maxIOCLists {
			return IOCList{}, ErrIOCList
		}
		if id, e = evidenceID(); e != nil {
			return IOCList{}, e
		}
		event = "ioc_list_added"
		if _, e = tx.ExecContext(ctx, `INSERT INTO ioc_lists(id,name,indicators_json,created_by,created_at,updated_by,updated_at) VALUES(?,?,?,?,?,?,?)`, id, name, string(raw), actor, now.Unix(), actor, now.Unix()); e != nil {
			return IOCList{}, ErrIOCList
		}
	} else {
		r, e := tx.ExecContext(ctx, `UPDATE ioc_lists SET name=?,indicators_json=?,updated_by=?,updated_at=? WHERE id=?`, name, string(raw), actor, now.Unix(), id)
		if e != nil {
			return IOCList{}, ErrIOCList
		}
		if n, _ := r.RowsAffected(); n != 1 {
			return IOCList{}, ErrIOCList
		}
	}
	if e = auditDevice(ctx, tx, now, actor, event, id+":"+name+": "+strconv.Itoa(len(list))+" indicators", "success"); e != nil {
		return IOCList{}, e
	}
	if e = tx.Commit(); e != nil {
		return IOCList{}, e
	}
	return s.IOCList(ctx, id)
}

func (s *Store) DeleteIOCList(ctx context.Context, id, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var name string
	if e = tx.QueryRowContext(ctx, `SELECT name FROM ioc_lists WHERE id=?`, id).Scan(&name); e != nil {
		return ErrIOCList
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM ioc_lists WHERE id=?`, id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "ioc_list_deleted", id+":"+name, "success"); e != nil {
		return e
	}
	return tx.Commit()
}

// IOCListNamed finds a saved list by name (case-insensitive), for the live
// response hunt command.
func (s *Store) IOCListNamed(ctx context.Context, name string) (IOCList, error) {
	lists, e := s.IOCLists(ctx)
	if e != nil {
		return IOCList{}, e
	}
	for _, l := range lists {
		if strings.EqualFold(l.Name, strings.TrimSpace(name)) {
			return l, nil
		}
	}
	return IOCList{}, ErrIOCList
}
