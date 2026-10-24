package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Triage packages. A profile names artifact types; the built-in
// "Full triage" has all of them, and the owner adds others. Collecting one
// queues an evidence job of source "triage" (path: the profile name, query:
// its artifact types) for agents that report protocol.AbilityTriage.

var (
	ErrTriage = errors.New("triage profile unavailable")
	// ErrTriageUnsupported: the device's agent does not build triage packages.
	ErrTriageUnsupported = errors.New("the device's agent cannot collect triage packages; update it")
)

// FullTriage is the built-in profile's ID.
const FullTriage = "full"

// triageStartWindow allows for reading the whole package before its upload
// starts.
const triageStartWindow = 2 * time.Hour

type TriageProfile struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Items     []string `json:"items"`
	BuiltIn   bool     `json:"built_in"`
	CreatedBy string   `json:"created_by,omitempty"`
	CreatedAt int64    `json:"created_at,omitempty"`
}

func fullTriage() TriageProfile {
	items := []string{}
	for _, i := range protocol.TriageItems {
		items = append(items, i.Name)
	}
	return TriageProfile{ID: FullTriage, Name: "Full triage", Items: items, BuiltIn: true}
}

// TriageProfiles lists the built-in profile and the owner's (not withdrawn).
func (s *Store) TriageProfiles(ctx context.Context) ([]TriageProfile, error) {
	out := []TriageProfile{fullTriage()}
	rows, e := s.db.QueryContext(ctx, `SELECT id,name,items,created_by,created_at FROM triage_profiles WHERE withdrawn_at IS NULL ORDER BY lower(name)`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var p TriageProfile
		var items string
		if e = rows.Scan(&p.ID, &p.Name, &items, &p.CreatedBy, &p.CreatedAt); e != nil {
			return nil, e
		}
		var ok bool
		if p.Items, ok = protocol.ParseTriageQuery(items); ok {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// TriageProfileByID finds a profile that can be used.
func (s *Store) TriageProfileByID(ctx context.Context, id string) (TriageProfile, error) {
	if id == FullTriage {
		return fullTriage(), nil
	}
	var p TriageProfile
	var items string
	e := s.db.QueryRowContext(ctx, `SELECT id,name,items,created_by,created_at FROM triage_profiles WHERE id=? AND withdrawn_at IS NULL`, id).Scan(&p.ID, &p.Name, &items, &p.CreatedBy, &p.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return p, ErrTriage
	}
	if e != nil {
		return p, e
	}
	var ok bool
	if p.Items, ok = protocol.ParseTriageQuery(items); !ok {
		return p, ErrTriage
	}
	return p, nil
}

// TriageProfileNamed finds a profile by name (case-insensitive), for the
// live response triage command.
func (s *Store) TriageProfileNamed(ctx context.Context, name string) (TriageProfile, error) {
	profiles, e := s.TriageProfiles(ctx)
	if e != nil {
		return TriageProfile{}, e
	}
	for _, p := range profiles {
		if strings.EqualFold(p.Name, name) || strings.EqualFold(p.ID, name) {
			return p, nil
		}
	}
	return TriageProfile{}, ErrTriage
}

// AddTriageProfile records an owner-made profile; names are unique among
// profiles in use and differ from the built-in one.
func (s *Store) AddTriageProfile(ctx context.Context, name string, items []string, actor string, now time.Time) (TriageProfile, error) {
	name = strings.TrimSpace(name)
	// The name becomes part of the reported path, which must be plain text.
	if !validText(name, 100, false) || !utf8Text(name) || strings.EqualFold(name, fullTriage().Name) || strings.EqualFold(name, FullTriage) || !protocol.ValidTriageItems(items) {
		return TriageProfile{}, ErrTriage
	}
	id, e := evidenceID()
	if e != nil {
		return TriageProfile{}, e
	}
	p := TriageProfile{ID: id, Name: name, Items: []string{}, CreatedBy: actor, CreatedAt: now.Unix()}
	query := protocol.TriageQuery(items)
	p.Items, _ = protocol.ParseTriageQuery(query)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `INSERT INTO triage_profiles(id,name,items,created_by,created_at) VALUES(?,?,?,?,?)`, id, name, query, actor, now.Unix()); e != nil {
		return p, ErrTriage
	}
	if e = auditDevice(ctx, tx, now, actor, "triage_profile_added", id+":"+query, "success"); e != nil {
		return p, e
	}
	return p, tx.Commit()
}

// WithdrawTriageProfile stops a profile from being used; packages already
// collected keep its name.
func (s *Store) WithdrawTriageProfile(ctx context.Context, id, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE triage_profiles SET withdrawn_at=? WHERE id=? AND withdrawn_at IS NULL`, now.Unix(), id)
	if e != nil {
		return e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return ErrTriage
	}
	if e = auditDevice(ctx, tx, now, actor, "triage_profile_withdrawn", id, "success"); e != nil {
		return e
	}
	return tx.Commit()
}

// QueueTriage asks a device for a triage package of the profile, into a case
// or (with a live response session) LiveCase.
func (s *Store) QueueTriage(ctx context.Context, caseID, deviceID, session string, p TriageProfile, actor string, now time.Time) (string, error) {
	if !protocol.ValidTriageItems(p.Items) || !validText(p.Name, 100, false) || session != "" && !protocol.ValidID(session) || session == "" && caseID == LiveCase {
		return "", ErrEvidence
	}
	var active int
	if e := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL`, deviceID).Scan(&active); e != nil || active != 1 {
		return "", ErrEvidence
	}
	if !s.HasAbility(ctx, deviceID, protocol.AbilityTriage) {
		return "", ErrTriageUnsupported
	}
	return s.queueJob(ctx, caseID, deviceID, "triage", p.Name, protocol.TriageQuery(p.Items), "", session, actor, now)
}
