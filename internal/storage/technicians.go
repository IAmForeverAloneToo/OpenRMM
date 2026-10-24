package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var ErrTechnician = errors.New("technician settings changed or are unavailable; reload and review again")
var ErrForbidden = errors.New("access is not permitted")

type TechnicianAccess struct {
	AllDevices bool     `json:"all_devices"`
	Devices    []string `json:"devices"`
	Groups     []string `json:"groups"`
	Events     bool     `json:"events"`
	Services   bool     `json:"services"`
	Processes  bool     `json:"processes"`
	Desktop    bool     `json:"desktop"`
	Files      bool     `json:"files"`
	// Response covers cases, the custody log and response actions (on
	// devices the technician can access). All cases are visible.
	Response bool `json:"response"`
}

func (a TechnicianAccess) Allows(kind string) bool {
	switch kind {
	case "read":
		return true
	case "events":
		return a.Events
	case "services":
		return a.Services
	case "processes":
		return a.Processes
	case "desktop":
		return a.Desktop
	case "files":
		return a.Files
	case "response":
		return a.Response
	}
	return false
}

type Technician struct {
	ID              string           `json:"id"`
	Username        string           `json:"username"`
	Enabled         bool             `json:"enabled"`
	Confirmed       bool             `json:"confirmed"`
	Revision        int64            `json:"revision"`
	Access          TechnicianAccess `json:"access"`
	CreatedAt       int64            `json:"created_at"`
	PasswordHash    string           `json:"-"`
	TOTPCipher      []byte           `json:"-"`
	LastStep        int64            `json:"-"`
	InvitationHash  *string          `json:"-"`
	InvitationUntil *int64           `json:"-"`
}
type TechnicianChange struct {
	Action, ID, Username string
	Revision             int64
	Enabled              bool
	Access               TechnicianAccess
}

const technicianColumns = "id,username,enabled,confirmed,revision,access_json,created_at,password_hash,totp_cipher,last_totp_step,invitation_hash,invitation_until"

func scanTechnician(row interface{ Scan(...any) error }) (Technician, error) {
	var t Technician
	var raw string
	e := row.Scan(&t.ID, &t.Username, &t.Enabled, &t.Confirmed, &t.Revision, &raw, &t.CreatedAt, &t.PasswordHash, &t.TOTPCipher, &t.LastStep, &t.InvitationHash, &t.InvitationUntil)
	if e == nil && json.Unmarshal([]byte(raw), &t.Access) != nil {
		e = ErrTechnician
	}
	return t, e
}
func (s *Store) Technicians(ctx context.Context) ([]Technician, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT "+technicianColumns+" FROM technicians ORDER BY username")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []Technician{}
	for rows.Next() {
		t, e := scanTechnician(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, t)
	}
	return result, rows.Err()
}
func (s *Store) TechnicianByName(ctx context.Context, name string) (Technician, error) {
	return scanTechnician(s.db.QueryRowContext(ctx, "SELECT "+technicianColumns+" FROM technicians WHERE username=?", name))
}
func (s *Store) TechnicianInvitation(ctx context.Context, hash string, now time.Time) (Technician, error) {
	return scanTechnician(s.db.QueryRowContext(ctx, "SELECT "+technicianColumns+" FROM technicians WHERE invitation_hash=? AND invitation_until>? AND enabled=1 AND confirmed=0", hash, now.Unix()))
}
func technicianName(name string) bool {
	if len(name) < 3 || len(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	for i, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return false
		}
	}
	return true
}
func validateTechnicianAccess(ctx context.Context, tx *sql.Tx, a TechnicianAccess) error {
	if len(a.Devices) > 100 || len(a.Groups) > 100 {
		return ErrTechnician
	}
	seen := map[string]bool{}
	for _, id := range a.Devices {
		if !protocol.ValidID(id) || seen[id] {
			return ErrTechnician
		}
		seen[id] = true
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=?", id).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return ErrTechnician
		}
	}
	seen = map[string]bool{}
	for _, id := range a.Groups {
		if !ValidOrganizationID(id) || seen[id] {
			return ErrTechnician
		}
		seen[id] = true
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM device_groups WHERE id=?", id).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return ErrTechnician
		}
	}
	return nil
}

// Review fingerprints bind the old account, proposed permissions and current
// organization revision. The bearer invitation is generated only after apply.
func (s *Store) ChangeTechnician(ctx context.Context, c TechnicianChange, actor, digest, inviteHash string, now time.Time) (string, error) {
	if actor == "" || !protocol.ValidID(c.ID) || !technicianName(c.Username) {
		return "", ErrTechnician
	}
	if (c.Action == "create" || c.Action == "reset") && !c.Enabled {
		return "", ErrTechnician
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	if e = validateTechnicianAccess(ctx, tx, c.Access); e != nil {
		return "", e
	}
	var owner string
	if e = tx.QueryRowContext(ctx, "SELECT username FROM administrators WHERE id=1").Scan(&owner); e != nil {
		return "", e
	}
	if owner == c.Username {
		return "", ErrTechnician
	}
	old, e := scanTechnician(tx.QueryRowContext(ctx, "SELECT "+technicianColumns+" FROM technicians WHERE id=?", c.ID))
	if c.Action == "create" {
		if !errors.Is(e, sql.ErrNoRows) || c.Revision != 0 {
			return "", ErrTechnician
		}
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM technicians WHERE username=?", c.Username).Scan(&n); e != nil {
			return "", e
		}
		if n != 0 {
			return "", ErrTechnician
		}
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM technicians").Scan(&n); e != nil {
			return "", e
		}
		if n >= 100 {
			return "", ErrTechnician
		}
	} else if (c.Action != "save" && c.Action != "reset") || e != nil || old.Revision != c.Revision || old.Username != c.Username {
		return "", ErrTechnician
	}
	var organizationRevision int64
	if e = tx.QueryRowContext(ctx, "SELECT revision FROM organization_state WHERE id=1").Scan(&organizationRevision); e != nil {
		return "", e
	}
	raw, _ := json.Marshal(struct {
		Before       Technician
		Change       TechnicianChange
		Organization int64
	}{old, c, organizationRevision})
	sum := sha256.Sum256(raw)
	expected := hex.EncodeToString(sum[:])
	if digest == "" {
		return expected, nil
	}
	if digest != expected {
		return "", ErrTechnician
	}
	access, _ := json.Marshal(c.Access)
	if c.Action == "create" {
		if !c.Enabled || len(inviteHash) != 64 {
			return "", ErrTechnician
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO technicians(id,username,enabled,access_json,invitation_hash,invitation_until,created_at) VALUES(?,?,1,?,?,?,?)", c.ID, c.Username, string(access), inviteHash, now.Add(30*time.Minute).Unix(), now.Unix())
	} else {
		_, e = tx.ExecContext(ctx, "UPDATE technicians SET enabled=?,access_json=?,revision=revision+1 WHERE id=?", c.Enabled, string(access), c.ID)
		if e == nil && c.Action == "reset" {
			if !c.Enabled || len(inviteHash) != 64 {
				return "", ErrTechnician
			}
			_, e = tx.ExecContext(ctx, "UPDATE technicians SET confirmed=0,password_hash='',totp_cipher=X'',last_totp_step=-1,invitation_hash=?,invitation_until=? WHERE id=?", inviteHash, now.Add(30*time.Minute).Unix(), c.ID)
			if e == nil {
				_, e = tx.ExecContext(ctx, "DELETE FROM technician_recovery_codes WHERE technician_id=?", c.ID)
			}
		}
		if e == nil && !c.Enabled {
			_, e = tx.ExecContext(ctx, "UPDATE technicians SET invitation_hash=NULL,invitation_until=NULL WHERE id=?", c.ID)
		}
		if e == nil {
			_, e = tx.ExecContext(ctx, "DELETE FROM sessions WHERE technician_id=?", c.ID)
		}
		if e == nil {
			e = cancelTechnicianWork(ctx, tx, "technician:"+c.ID, "", now)
		}
	}
	if e != nil {
		return "", ErrTechnician
	}
	if e = auditDevice(ctx, tx, now, actor, "technician_"+c.Action, c.ID, "reviewed"); e != nil {
		return "", e
	}
	return expected, tx.Commit()
}

// BeginTechnicianActivation consumes an invitation exactly once: the one-time
// confirmation token that replaces it cannot start activation again (the row
// already has a password), so it is only accepted by ConfirmTechnicianActivation.
func (s *Store) BeginTechnicianActivation(ctx context.Context, id, invite, confirm, password string, cipher []byte, codes []string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE technicians SET password_hash=?,totp_cipher=?,invitation_hash=? WHERE id=? AND invitation_hash=? AND invitation_until>? AND enabled=1 AND confirmed=0 AND password_hash=''`, password, cipher, confirm, id, invite, now.Unix())
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrAuthentication
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM technician_recovery_codes WHERE technician_id=?", id); e != nil {
		return e
	}
	for _, code := range codes {
		if _, e = tx.ExecContext(ctx, "INSERT INTO technician_recovery_codes VALUES(?,?)", code, id); e != nil {
			return e
		}
	}
	if e = auditDevice(ctx, tx, now, "technician:"+id, "technician_activation_started", id, "pending_mfa"); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) ConfirmTechnicianActivation(ctx context.Context, id, confirm string, step int64, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE technicians SET confirmed=1,last_totp_step=?,invitation_hash=NULL,invitation_until=NULL WHERE id=? AND invitation_hash=? AND invitation_until>? AND enabled=1 AND confirmed=0 AND password_hash<>'' AND last_totp_step<?`, step, id, confirm, now.Unix(), step)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrAuthentication
	}
	if e = auditDevice(ctx, tx, now, "technician:"+id, "technician_mfa_confirmed", id, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) CompleteTechnicianLogin(ctx context.Context, id string, version, step int64, recovery string, v Session, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	t, e := scanTechnician(tx.QueryRowContext(ctx, "SELECT "+technicianColumns+" FROM technicians WHERE id=?", id))
	if e != nil || !t.Enabled || !t.Confirmed || t.Revision != version {
		return ErrAuthentication
	}
	var r sql.Result
	if recovery != "" {
		r, e = tx.ExecContext(ctx, "DELETE FROM technician_recovery_codes WHERE technician_id=? AND code_hash=?", id, recovery)
	} else {
		r, e = tx.ExecContext(ctx, "UPDATE technicians SET last_totp_step=? WHERE id=? AND last_totp_step<?", step, id, step)
	}
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrAuthentication
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=? OR last_seen_at<=?", now.Unix(), now.Add(-30*time.Minute).Unix()); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash IN(SELECT token_hash FROM sessions WHERE technician_id=? ORDER BY created_at DESC,token_hash LIMIT -1 OFFSET 15)`, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO sessions(token_hash,administrator_id,csrf_token,credential_version,created_at,expires_at,last_seen_at,technician_id) VALUES(?,1,?,?,?,?,?,?)", v.TokenHash, v.CSRF, version, v.CreatedAt, v.ExpiresAt, v.LastSeenAt, id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, "technician:"+id, "login", id, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
func technicianSession(ctx context.Context, db *sql.DB, hash string, now time.Time) (Session, error) {
	var v Session
	var id string
	e := db.QueryRowContext(ctx, `SELECT s.token_hash,t.id,t.username,s.csrf_token,s.credential_version,s.created_at,s.expires_at,s.last_seen_at FROM sessions s JOIN technicians t ON t.id=s.technician_id WHERE s.token_hash=? AND s.credential_version=t.revision AND t.enabled=1 AND t.confirmed=1 AND s.expires_at>? AND s.last_seen_at>?`, hash, now.Unix(), now.Add(-30*time.Minute).Unix()).Scan(&v.TokenHash, &id, &v.Username, &v.CSRF, &v.Version, &v.CreatedAt, &v.ExpiresAt, &v.LastSeenAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrAuthentication
	}
	if e != nil {
		return v, e
	}
	t, e := scanTechnician(db.QueryRowContext(ctx, "SELECT "+technicianColumns+" FROM technicians WHERE id=? AND revision=? AND enabled=1 AND confirmed=1", id, v.Version))
	if e != nil {
		return v, ErrAuthentication
	}
	v.Technician = &t
	return v, nil
}
func (v Session) Actor() string {
	if v.Technician != nil {
		return "technician:" + v.Technician.ID
	}
	return v.Username
}
func (v Session) Can(kind string) bool {
	return v.Technician == nil || v.Technician.Access.Allows(kind)
}
func technicianDevice(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, t Technician, id, kind string) error {
	if !t.Enabled || !t.Confirmed || !t.Access.Allows(kind) || !protocol.ValidID(id) {
		return ErrForbidden
	}
	var group string
	e := q.QueryRowContext(ctx, "SELECT COALESCE(o.group_id,'') FROM devices d LEFT JOIN device_organization o ON o.device_id=d.id WHERE d.id=? AND d.revoked_at IS NULL", id).Scan(&group)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrForbidden
	}
	if e != nil {
		return e
	}
	if t.Access.Includes(OrganizedDevice{ID: id, GroupID: group}) {
		return nil
	}
	return ErrForbidden
}
func (s *Store) AuthorizeDevice(ctx context.Context, v Session, id, kind string) error {
	if v.Technician == nil {
		return nil
	}
	return technicianDevice(ctx, s.db, *v.Technician, id, kind)
}

// Queue and dispatch checks use the immutable account ID, never a reused name.
func authorizeActor(ctx context.Context, tx *sql.Tx, actor, id, kind string) error {
	if !strings.HasPrefix(actor, "technician:") {
		return nil
	}
	t, e := scanTechnician(tx.QueryRowContext(ctx, "SELECT "+technicianColumns+" FROM technicians WHERE id=?", strings.TrimPrefix(actor, "technician:")))
	if errors.Is(e, sql.ErrNoRows) {
		return ErrForbidden
	}
	if e != nil {
		return e
	}
	return technicianDevice(ctx, tx, t, id, kind)
}

// Column names come only from fixed storage queries. Apply scope before LIMIT
// so another group's busy history cannot displace permitted incidents/notices.
func technicianScope(v Session, column string) (string, []any) {
	if v.Technician == nil {
		return "1=1", nil
	}
	return `EXISTS(SELECT 1 FROM technicians scoped_account JOIN devices scoped_device ON scoped_device.id=` + column + `
 LEFT JOIN device_organization scoped_org ON scoped_org.device_id=scoped_device.id
 WHERE scoped_account.id=? AND scoped_account.revision=? AND scoped_account.enabled=1 AND scoped_account.confirmed=1 AND scoped_device.revoked_at IS NULL
 AND(json_extract(scoped_account.access_json,'$.all_devices')=1
 OR EXISTS(SELECT 1 FROM json_each(scoped_account.access_json,'$.devices') WHERE value=scoped_device.id)
 OR EXISTS(SELECT 1 FROM json_each(scoped_account.access_json,'$.groups') WHERE value=scoped_org.group_id)))`, []any{v.Technician.ID, v.Version}
}

func cancelTechnicianWork(ctx context.Context, tx *sql.Tx, actor, device string, now time.Time) error {
	var total int64
	for _, table := range []string{"service_actions", "process_actions", "event_log_queries"} {
		result, e := tx.ExecContext(ctx, "UPDATE "+table+" SET status='cancelled',finished_at=? WHERE actor=? AND status='queued' AND(?='' OR device_id=?)", now.Unix(), actor, device, device)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		total += n
	}
	if total > 0 {
		return auditDevice(ctx, tx, now, "server", "technician_work_cancelled", actor+":"+device, "authorization_changed")
	}
	return nil
}
func (a TechnicianAccess) Includes(d OrganizedDevice) bool {
	if a.AllDevices {
		return true
	}
	for _, id := range a.Devices {
		if id == d.ID {
			return true
		}
	}
	for _, g := range a.Groups {
		if g == d.GroupID {
			return true
		}
	}
	return false
}
func cancelLostGroupWork(ctx context.Context, tx *sql.Tx, before, after Organization, now time.Time) error {
	changed := []int{}
	for i, d := range before.Devices {
		if d.GroupID != after.Devices[i].GroupID {
			changed = append(changed, i)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+technicianColumns+" FROM technicians")
	if e != nil {
		return e
	}
	people := []Technician{}
	for rows.Next() {
		t, err := scanTechnician(rows)
		if err != nil {
			e = err
			break
		}
		people = append(people, t)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	for _, t := range people {
		for _, i := range changed {
			if t.Access.Includes(before.Devices[i]) && !t.Access.Includes(after.Devices[i]) {
				if e = cancelTechnicianWork(ctx, tx, "technician:"+t.ID, before.Devices[i].ID, now); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
