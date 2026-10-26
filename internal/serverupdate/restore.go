package serverupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RestoreOptions are the parts of a restore that need the database code.
type RestoreOptions struct {
	// Revoked reads the revoked devices from the current database, so they
	// stay revoked after an older backup is restored.
	Revoked func(db string) (map[string]int64, error)
	// Reconcile migrates the restored database and applies the restore
	// changes (revocations, credentials, queued work).
	Reconcile func(db string, revoked map[string]int64) error
	// Revocations is an optional reviewed list for the same installation,
	// for a restore after the current server was lost.
	Revocations *Revocations
	// SkipSafety restores without a safety backup of the current state (for
	// example when the current database is damaged).
	SkipSafety bool
	Now        time.Time
}

// Revocations is the reviewed revocation list format.
type Revocations struct {
	Format     int              `json:"format"`
	InstanceID string           `json:"instance_id"`
	CapturedAt string           `json:"captured_at"`
	Revoked    map[string]int64 `json:"revoked"`
}

// RestoreResult reports what a restore did.
type RestoreResult struct {
	Safety  string // the safety backup of the replaced state
	Carried int    // revoked devices carried over
}

// RestoreSafely replaces the server state with a backup while the server is
// stopped: it verifies the backup, takes a safety backup of the current
// state, carries current revocations over, restores and reconciles. If the
// restored database cannot be prepared, the safety backup is put back.
func (b Backups) RestoreSafely(name string, o RestoreOptions) (RestoreResult, error) {
	var result RestoreResult
	if _, e := b.Verify(name); e != nil {
		return result, e
	}
	var target BackupInfo
	_ = readJSON(filepath.Join(b.Dir, name, metaFile), &target, 4096)
	if b.Inspect != nil {
		if id, _, e := b.Inspect(filepath.Join(b.Dir, name, "data", filepath.FromSlash(b.DB))); e == nil {
			target.InstanceID = id
		}
	}
	revoked := map[string]int64{}
	add := func(m map[string]int64) {
		for id, at := range m {
			if old, ok := revoked[id]; !ok || at < old {
				revoked[id] = at
			}
		}
	}
	if r := o.Revocations; r != nil {
		if r.Format != 1 || r.InstanceID == "" || r.InstanceID != target.InstanceID {
			return result, errors.New("the revocation list is for another installation")
		}
		add(r.Revoked)
	}
	current := filepath.Join(b.Sources["data"], filepath.FromSlash(b.DB))
	if _, e := os.Stat(current); e == nil {
		// Devices revoked on this installation since the backup stay revoked.
		// A backup of another installation (a move to a new machine) shares
		// no devices with the current one.
		sameInstallation := true
		if b.Inspect != nil {
			if id, _, e := b.Inspect(current); e == nil && target.InstanceID != "" && id != target.InstanceID {
				sameInstallation = false
			}
		}
		if sameInstallation && o.Revoked != nil {
			m, e := o.Revoked(current)
			if e != nil && !o.SkipSafety {
				return result, errors.New("the revoked devices could not be read from the current database; restore with --skip-safety-backup and a reviewed --revocations list")
			}
			result.Carried = len(m)
			add(m)
		}
		if !o.SkipSafety {
			result.Safety = NewBackupName("pre-restore", o.Now)
			if e := b.Create(result.Safety); e != nil {
				return result, fmt.Errorf("the safety backup of the current state failed (%v); fix the cause or restore with --skip-safety-backup", e)
			}
		}
	}
	if e := b.Restore(name); e != nil {
		return result, b.undo(result.Safety, fmt.Errorf("the backup could not be restored: %w", e))
	}
	if o.Reconcile != nil {
		if e := o.Reconcile(current, revoked); e != nil {
			return result, b.undo(result.Safety, fmt.Errorf("the restored database could not be prepared: %w", e))
		}
	}
	_ = b.Prune()
	return result, nil
}

// undo puts the safety backup back after a failed restore.
func (b Backups) undo(safety string, cause error) error {
	if safety == "" {
		return cause
	}
	if e := b.Restore(safety); e != nil {
		return fmt.Errorf("%w; putting the previous state back also failed, restore backup %s", cause, safety)
	}
	return fmt.Errorf("%w; the previous state was put back", cause)
}
