package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/yara"
)

// YARA rule sets: the owner adds, changes and withdraws them; responders
// use them in hunts and scans, which copy the rules they run. Each save is
// a new version, checked by the same engine the agents run.

const (
	maxYaraSets = 200
	// MaxYaraSource bounds a rule set: it travels to every device scanned.
	MaxYaraSource = 1 << 20
	// keepYaraVersions earlier versions are kept per set.
	keepYaraVersions = 20
)

var (
	ErrYaraSet = errors.New("rule set unavailable; check the name, or it was withdrawn")
	// ErrYaraRules wraps a compile error of the rules themselves.
	ErrYaraRules = errors.New("the rules do not compile")
)

type YaraRuleSet struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   int    `json:"version"`
	Rules     int    `json:"rules"`
	SHA256    string `json:"sha256"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	UpdatedBy string `json:"updated_by"`
	UpdatedAt int64  `json:"updated_at"`
	// Source is included when one set is read.
	Source string `json:"source,omitempty"`
}

// CheckYara compiles rules and returns how many there are.
func CheckYara(source string) (int, error) {
	if len(source) > MaxYaraSource || !ruleText(source) {
		return 0, fmt.Errorf("%w: the rules must be UTF-8 text of at most 1 MiB", ErrYaraRules)
	}
	rs, err := yara.Compile(source)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrYaraRules, err)
	}
	return rs.Len(), nil
}

// ruleText is valid UTF-8 whose only control characters are tabs and line
// breaks.
func ruleText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

const yaraSetColumns = `s.id,s.name,s.version,v.rules,v.sha256,s.created_by,s.created_at,s.updated_by,s.updated_at`

func scanYaraSet(row interface{ Scan(...any) error }, withSource bool) (YaraRuleSet, error) {
	var r YaraRuleSet
	dest := []any{&r.ID, &r.Name, &r.Version, &r.Rules, &r.SHA256, &r.CreatedBy, &r.CreatedAt, &r.UpdatedBy, &r.UpdatedAt}
	if withSource {
		dest = append(dest, &r.Source)
	}
	return r, row.Scan(dest...)
}

// YaraRuleSets lists the sets in use, without their rules.
func (s *Store) YaraRuleSets(ctx context.Context) ([]YaraRuleSet, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+yaraSetColumns+` FROM yara_rule_sets s JOIN yara_rule_versions v ON v.set_id=s.id AND v.version=s.version WHERE s.withdrawn_at IS NULL ORDER BY lower(s.name)`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []YaraRuleSet{}
	for rows.Next() {
		r, e := scanYaraSet(rows, false)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// YaraRuleSet reads a set in use with its current rules.
func (s *Store) YaraRuleSet(ctx context.Context, id string) (YaraRuleSet, error) {
	r, e := scanYaraSet(s.db.QueryRowContext(ctx, `SELECT `+yaraSetColumns+`,v.source FROM yara_rule_sets s JOIN yara_rule_versions v ON v.set_id=s.id AND v.version=s.version WHERE s.id=? AND s.withdrawn_at IS NULL`, id), true)
	if errors.Is(e, sql.ErrNoRows) {
		return r, ErrYaraSet
	}
	return r, e
}

// YaraRuleSetNamed finds a set in use by name (case ignored), for the
// console.
func (s *Store) YaraRuleSetNamed(ctx context.Context, name string) (YaraRuleSet, error) {
	var id string
	if e := s.db.QueryRowContext(ctx, `SELECT id FROM yara_rule_sets WHERE lower(name)=lower(?) AND withdrawn_at IS NULL`, strings.TrimSpace(name)).Scan(&id); e != nil {
		return YaraRuleSet{}, ErrYaraSet
	}
	return s.YaraRuleSet(ctx, id)
}

// SaveYaraRuleSet adds a set (id empty) or saves a new version of one.
// Rules that do not compile are refused with ErrYaraRules and the reason.
func (s *Store) SaveYaraRuleSet(ctx context.Context, id, name, source, actor string, now time.Time) (YaraRuleSet, error) {
	name = strings.TrimSpace(name)
	if !validText(name, 100, false) || !utf8Text(name) || id != "" && !protocol.ValidID(id) {
		return YaraRuleSet{}, ErrYaraSet
	}
	count, err := CheckYara(source)
	if err != nil {
		return YaraRuleSet{}, err
	}
	sum := sha256.Sum256([]byte(source))
	hash := hex.EncodeToString(sum[:])
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return YaraRuleSet{}, e
	}
	defer tx.Rollback()
	var clash string
	if e = tx.QueryRowContext(ctx, `SELECT id FROM yara_rule_sets WHERE lower(name)=lower(?) AND withdrawn_at IS NULL AND id!=?`, name, id).Scan(&clash); e == nil {
		return YaraRuleSet{}, ErrYaraSet
	}
	version, event := 1, "yara_rule_set_added"
	if id == "" {
		var n int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM yara_rule_sets WHERE withdrawn_at IS NULL`).Scan(&n); e != nil || n >= maxYaraSets {
			return YaraRuleSet{}, ErrYaraSet
		}
		if id, e = evidenceID(); e != nil {
			return YaraRuleSet{}, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO yara_rule_sets(id,name,version,created_by,created_at,updated_by,updated_at) VALUES(?,?,1,?,?,?,?)`, id, name, actor, now.Unix(), actor, now.Unix()); e != nil {
			return YaraRuleSet{}, e
		}
	} else {
		if e = tx.QueryRowContext(ctx, `SELECT version+1 FROM yara_rule_sets WHERE id=? AND withdrawn_at IS NULL`, id).Scan(&version); e != nil {
			return YaraRuleSet{}, ErrYaraSet
		}
		event = "yara_rule_set_changed"
		if _, e = tx.ExecContext(ctx, `UPDATE yara_rule_sets SET name=?,version=?,updated_by=?,updated_at=? WHERE id=?`, name, version, actor, now.Unix(), id); e != nil {
			return YaraRuleSet{}, e
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO yara_rule_versions(set_id,version,source,sha256,rules,created_by,created_at) VALUES(?,?,?,?,?,?,?)`, id, version, source, hash, count, actor, now.Unix()); e != nil {
		return YaraRuleSet{}, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM yara_rule_versions WHERE set_id=? AND version<=?`, id, version-keepYaraVersions); e != nil {
		return YaraRuleSet{}, e
	}
	detail := id + ":" + name + ": version " + strconv.Itoa(version) + ", " + strconv.Itoa(count) + " rules, sha256 " + hash
	if e = auditDevice(ctx, tx, now, actor, event, detail, "success"); e != nil {
		return YaraRuleSet{}, e
	}
	if e = tx.Commit(); e != nil {
		return YaraRuleSet{}, e
	}
	return s.YaraRuleSet(ctx, id)
}

// KeepYaraSource checks rules and stores them once by hash for the jobs
// that run them; it returns the hash and the number of rules.
func (s *Store) KeepYaraSource(ctx context.Context, source string, now time.Time) (string, int, error) {
	n, err := CheckYara(source)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256([]byte(source))
	hash := hex.EncodeToString(sum[:])
	if _, e := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO yara_sources(sha256,source,created_at) VALUES(?,?,?)`, hash, source, now.Unix()); e != nil {
		return "", 0, e
	}
	return hash, n, nil
}

// withRules adds a YARA hunt's rules to an action handed to a device.
func withRules(ctx context.Context, tx *sql.Tx, a protocol.ResponseAction) (protocol.ResponseAction, error) {
	if a.Hunt == nil || a.Hunt.Yara == nil {
		return a, nil
	}
	h, y := *a.Hunt, *a.Hunt.Yara
	if e := tx.QueryRowContext(ctx, `SELECT source FROM yara_sources WHERE sha256=?`, y.SHA256).Scan(&y.Rules); e != nil {
		return a, errors.New("the rules of a YARA scan are missing")
	}
	h.Yara = &y
	a.Hunt = &h
	return a, nil
}

// WithdrawYaraRuleSet takes a set out of use; its versions are kept.
func (s *Store) WithdrawYaraRuleSet(ctx context.Context, id, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var name string
	if e = tx.QueryRowContext(ctx, `SELECT name FROM yara_rule_sets WHERE id=? AND withdrawn_at IS NULL`, id).Scan(&name); e != nil {
		return ErrYaraSet
	}
	if _, e = tx.ExecContext(ctx, `UPDATE yara_rule_sets SET withdrawn_at=?,updated_by=?,updated_at=? WHERE id=?`, now.Unix(), actor, now.Unix(), id); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "yara_rule_set_withdrawn", id+":"+name, "success"); e != nil {
		return e
	}
	return tx.Commit()
}
