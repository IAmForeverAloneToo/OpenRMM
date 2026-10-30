package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"os"
	"path/filepath"
	"time"
)

var ErrAgentUpgrade = errors.New("agent release or reviewed targets unavailable/changed")

type AgentRelease struct {
	ID        string                      `json:"id"`
	Release   protocol.SignedAgentRelease `json:"release"`
	PublicKey string                      `json:"public_key"`
	CreatedAt int64                       `json:"created_at"`
	Actor     string                      `json:"actor"`
	Withdrawn bool                        `json:"withdrawn"`
}

const agentReleaseColumns = "id,signed_json,public_key,created_at,actor,withdrawn"

func scanAgentRelease(row interface{ Scan(...any) error }) (AgentRelease, error) {
	var r AgentRelease
	var raw string
	e := row.Scan(&r.ID, &raw, &r.PublicKey, &r.CreatedAt, &r.Actor, &r.Withdrawn)
	if e == nil && (agentupdate.Decode([]byte(raw), &r.Release) != nil || !agentupdate.Verify(r.Release, r.PublicKey) || agentupdate.ReleaseID(r.Release) != r.ID) {
		e = ErrAgentUpgrade
	}
	return r, e
}
func (s *Store) agentArtifactRoot() (*os.Root, error) {
	p := filepath.Join(s.directory, "agent-releases")
	e := privatefs.CreateDirectory(p)
	if e != nil && !errors.Is(e, os.ErrExist) {
		return nil, e
	}
	i, e := os.Lstat(p)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return nil, ErrAgentUpgrade
	}
	return os.OpenRoot(p)
}
func (s *Store) NewAgentReleaseTemp() (*os.File, error) {
	root, e := s.agentArtifactRoot()
	if e != nil {
		return nil, e
	}
	root.Close()
	return os.CreateTemp(filepath.Join(s.directory, "agent-releases"), ".upload-*")
}
func (s *Store) AgentReleases(ctx context.Context) ([]AgentRelease, int64, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, 0, e
	}
	defer tx.Rollback()
	var revision int64
	if e = tx.QueryRowContext(ctx, "SELECT revision FROM agent_release_state WHERE id=1").Scan(&revision); e != nil {
		return nil, 0, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases ORDER BY created_at DESC,id LIMIT 200")
	if e != nil {
		return nil, 0, e
	}
	items := []AgentRelease{}
	for rows.Next() {
		r, e := scanAgentRelease(rows)
		if e != nil {
			rows.Close()
			return nil, 0, e
		}
		items = append(items, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, 0, e
	}
	return items, revision, tx.Commit()
}
func (s *Store) AgentRelease(ctx context.Context, id string) (AgentRelease, error) {
	if !agentupdate.Hash(id) {
		return AgentRelease{}, ErrAgentUpgrade
	}
	return scanAgentRelease(s.db.QueryRowContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases WHERE id=?", id))
}

// The caller spools an entire bounded multipart request privately before commit.
// Orphan artifact files are harmless without a reviewed catalog row and digest.
func (s *Store) AddAgentRelease(ctx context.Context, r protocol.SignedAgentRelease, public, temp, actor string, now time.Time) error {
	return s.addAgentRelease(ctx, r, public, temp, actor, false, now)
}

// BundledReleaseActor records releases imported from the server build itself.
const BundledReleaseActor = "system:server-build"

// ImportBundledAgentRelease adds the release carried by the server build. It
// needs no administrator session (the build is the trust root, and the
// signature, hash and PE checks are the same as for uploads) and is a no-op
// when that exact release is already in the library, including withdrawn.
func (s *Store) ImportBundledAgentRelease(ctx context.Context, r protocol.SignedAgentRelease, public, temp string, now time.Time) (bool, error) {
	var existing int
	if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_releases WHERE id=?", agentupdate.ReleaseID(r)).Scan(&existing); e != nil {
		return false, e
	}
	if existing != 0 {
		return false, nil
	}
	return true, s.addAgentRelease(ctx, r, public, temp, BundledReleaseActor, true, now)
}

func (s *Store) addAgentRelease(ctx context.Context, r protocol.SignedAgentRelease, public, temp, actor string, bundled bool, now time.Time) error {
	s.artifactMu.Lock()
	defer s.artifactMu.Unlock()
	if !agentupdate.Verify(r, public) || !agentupdate.Fresh(r.Manifest, now) || agentupdate.Inspect(temp, r.Manifest) != nil {
		return ErrAgentUpgrade
	}
	root, e := s.agentArtifactRoot()
	if e != nil {
		return e
	}
	defer root.Close()
	if filepath.Dir(temp) != root.Name() {
		return ErrAgentUpgrade
	}
	id := agentupdate.ReleaseID(r)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if !bundled {
		if e = ownerTx(ctx, tx, actor); e != nil {
			return e
		}
	}
	var existing int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_releases WHERE id=?", id).Scan(&existing); e != nil {
		return e
	}
	if existing != 0 {
		return ErrAgentUpgrade
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM agent_releases WHERE withdrawn=1 AND id NOT IN(SELECT release_id FROM agent_upgrade_jobs)"); e != nil {
		return e
	}
	var active, total int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN withdrawn=0 THEN 1 ELSE 0 END),0) FROM agent_releases").Scan(&total, &active); e != nil {
		return e
	}
	// A bundled release makes room by withdrawing
	// the oldest older releases the server imported itself that no queued or
	// running device job and no ring rollout uses. Uploaded releases stay.
	var retired []string
	created, committed := false, false
	for bundled && active >= 8 {
		var old string
		e = tx.QueryRowContext(ctx, `SELECT id FROM agent_releases WHERE withdrawn=0 AND actor=? AND sequence<?
			AND id NOT IN (SELECT release_id FROM agent_upgrade_jobs WHERE status IN ('queued','dispatched'))
			AND id NOT IN (SELECT release_id FROM agent_ring_policy)
			ORDER BY sequence,created_at LIMIT 1`, BundledReleaseActor, r.Manifest.Sequence).Scan(&old)
		if errors.Is(e, sql.ErrNoRows) {
			break
		}
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE agent_releases SET withdrawn=1 WHERE id=?", old); e != nil {
			return e
		}
		if e = auditDevice(ctx, tx, now, BundledReleaseActor, "agent_release_withdrawn", old, "retired"); e != nil {
			return e
		}
		retired = append(retired, old)
		active--
	}
	if active >= 8 || total >= 200 {
		return ErrAgentUpgrade
	}
	defer func() {
		if committed {
			for _, old := range retired {
				_ = root.Remove(old + ".exe")
			}
		}
	}()
	// Link commits without replacing an existing artifact. An orphan from a
	// failed catalog commit is reused only after exact signed digest verification.
	defer func() {
		if created && !committed {
			_ = root.Remove(id + ".exe")
		}
	}()
	dest := id + ".exe"
	if e = root.Link(filepath.Base(temp), dest); e != nil {
		if !errors.Is(e, os.ErrExist) {
			return e
		}
		if agentupdate.Inspect(filepath.Join(root.Name(), dest), r.Manifest) != nil {
			return ErrAgentUpgrade
		}
	}
	if e == nil {
		created = true
	}
	raw, _ := json.Marshal(r)
	if _, e = tx.ExecContext(ctx, "INSERT INTO agent_releases(id,signed_json,public_key,key_id,sequence,created_at,actor)VALUES(?,?,?,?,?,?,?)", id, string(raw), public, r.Manifest.KeyID, r.Manifest.Sequence, now.Unix(), actor); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_release_state SET revision=revision+1 WHERE id=1"); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "agent_release_added", id, r.Manifest.Hash+":"+r.Manifest.KeyID); e != nil {
		return e
	}
	e = tx.Commit()
	committed = e == nil
	return e
}
func (s *Store) WithdrawAgentRelease(ctx context.Context, id, actor string, now time.Time) error {
	s.artifactMu.Lock()
	defer s.artifactMu.Unlock()
	if !agentupdate.Hash(id) {
		return ErrAgentUpgrade
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = ownerTx(ctx, tx, actor); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_upgrade_jobs WHERE release_id=? AND status='dispatched'", id).Scan(&n); e != nil {
		return e
	}
	if n != 0 {
		return ErrAgentUpgrade
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_upgrade_jobs SET status='cancelled',finished_at=? WHERE release_id=? AND status='queued'", now.Unix(), id); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, "UPDATE agent_releases SET withdrawn=1 WHERE id=? AND withdrawn=0", id)
	if e != nil {
		return e
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrAgentUpgrade
	}
	if _, e = tx.ExecContext(ctx, "UPDATE agent_release_state SET revision=revision+1 WHERE id=1"); e != nil {
		return e
	}
	if e = auditDevice(ctx, tx, now, actor, "agent_release_withdrawn", id, "withdrawn"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	root, e := s.agentArtifactRoot()
	if e != nil {
		return e
	}
	defer root.Close()
	e = root.Remove(id + ".exe")
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
func (s *Store) AgentReleaseArtifact(ctx context.Context, device, fp, job string, now time.Time) (AgentRelease, *os.File, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return AgentRelease{}, nil, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return AgentRelease{}, nil, e
	}
	var release string
	e = tx.QueryRowContext(ctx, "SELECT release_id FROM agent_upgrade_jobs WHERE id=? AND device_id=? AND status='dispatched' AND expires_at>?", job, device, now.Unix()).Scan(&release)
	if e != nil {
		return AgentRelease{}, nil, ErrAgentUpgrade
	}
	r, e := scanAgentRelease(tx.QueryRowContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases WHERE id=? AND withdrawn=0", release))
	if e != nil {
		return r, nil, ErrAgentUpgrade
	}
	root, e := s.agentArtifactRoot()
	if e != nil {
		return r, nil, e
	}
	defer root.Close()
	f, e := root.Open(release + ".exe")
	if e != nil {
		return r, nil, e
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Size() != r.Release.Manifest.Size {
		f.Close()
		return r, nil, ErrAgentUpgrade
	}
	if e = tx.Commit(); e != nil {
		f.Close()
		return r, nil, e
	}
	return r, f, nil
}

// InstallerRelease opens the MSI of the newest usable release for an
// installer download. It returns nil when that release is not an
// MSI or none is available.
func (s *Store) InstallerRelease(ctx context.Context, now time.Time) (*AgentRelease, *os.File, error) {
	r, e := s.LatestAgentRelease(ctx, now)
	if e != nil || r == nil || !agentupdate.MSI(r.Release.Manifest) {
		return nil, nil, e
	}
	root, e := s.agentArtifactRoot()
	if e != nil {
		return nil, nil, e
	}
	defer root.Close()
	f, e := root.Open(r.ID + ".exe")
	if e != nil {
		return nil, nil, e
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Size() != r.Release.Manifest.Size {
		f.Close()
		return nil, nil, ErrAgentUpgrade
	}
	return r, f, nil
}

// Keep a corrupt or half-uploaded file out of the immutable catalog.
func SpoolAgentRelease(dst *os.File, src io.Reader) error {
	n, e := io.Copy(dst, io.LimitReader(src, agentupdate.MaxArtifact+1))
	if e != nil || n > agentupdate.MaxArtifact {
		return ErrAgentUpgrade
	}
	return dst.Sync()
}
