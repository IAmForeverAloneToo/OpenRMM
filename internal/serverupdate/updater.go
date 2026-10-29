package serverupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Updater runs in the sidecar container. It is the only part with Docker
// access; it never takes instructions it has not verified: the release must
// carry a valid signature from a trusted key and a sequence above the last
// one installed.
type Updater struct {
	Dir      string // exchange volume shared with the server
	Engine   Engine
	Backups  Backups
	Project  string
	Service  string
	Trust    Current
	Now      func() time.Time
	Health   time.Duration // how long the new version may take to become healthy
	Poll     time.Duration
	Logf     func(msg string, args ...any)
	Interval time.Duration
	// Self is this updater's own container (its host name); empty turns
	// self-updates off (self.go).
	Self     string
	Handover time.Duration // how long a new updater may take to take over

	running, lastRun *BackupRun // backups (schedule.go)
	refreshDue       bool       // compare this updater's image with the server's
}

// The journal lives in the backup volume, which only the updater mounts: the
// server must not be able to lower the high-water mark or point a rollback
// at other containers or folders.
const stateFile = "updater-state.json"

// InstalledRepository is the local tag recording the image the updater last
// installed for a Compose project, so the install command keeps it.
func InstalledRepository(project string) string { return "openrmm-installed-" + project }

// journal survives an updater restart, so an interrupted update is rolled
// back instead of left half-done.
type journal struct {
	HighWater int64   `json:"high_water"`
	Active    *active `json:"active,omitempty"`
	// SelfFailed is an image a new updater did not start from; the
	// updater does not try it again.
	SelfFailed string `json:"self_failed,omitempty"`
}

type active struct {
	Request  string `json:"request"`
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	Previous string `json:"previous"` // container ID of the version being replaced
	Name     string `json:"name"`
	New      string `json:"new,omitempty"`
	Backup   string `json:"backup,omitempty"`
	// Committed: the new version is healthy and recorded; only the previous
	// container remains to be removed.
	Committed bool `json:"committed,omitempty"`
}

var backupName = regexp.MustCompile(`^update-[0-9]{8}-[0-9]{6}-[0-9]{1,5}$`)

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) logf(msg string, args ...any) {
	if u.Logf != nil {
		u.Logf(msg, args...)
	}
}

func (u *Updater) statePath() string { return filepath.Join(u.Backups.Dir, stateFile) }

// load fails closed: a journal that exists but cannot be read stops updates.
func (u *Updater) load() (journal, error) {
	var j journal
	e := readJSON(u.statePath(), &j, 8192)
	switch {
	case errors.Is(e, os.ErrNotExist):
		return journal{}, nil
	case e != nil || j.HighWater < 0:
		return journal{}, errors.New("the updater journal is unreadable")
	case j.Active != nil && (j.Active.Backup != "" && !backupName.MatchString(j.Active.Backup) || j.Active.Previous == "" || j.Active.Name == ""):
		return journal{}, errors.New("the updater journal is invalid")
	}
	return j, nil
}

func (u *Updater) save(j journal) error { return writeJSON(u.statePath(), j) }

func (u *Updater) status(id, phase, version string, sequence int64, detail, backup string) {
	now := u.now().Unix()
	s := Status{ID: id, Phase: phase, Version: version, Sequence: sequence, Detail: detail, Backup: backup, UpdatedAt: now, Alive: now, Updater: UpdaterRevision, Build: u.Trust.Version}
	if e := writeJSON(filepath.Join(u.Dir, StatusFile), s); e != nil {
		u.logf("cannot write the update status", "error", e.Error())
	}
}

// alive refreshes the heartbeat in the status so the server can tell that
// an updater is running.
func (u *Updater) alive() {
	s, e := ReadStatus(u.Dir)
	if e != nil {
		u.status("", "idle", "", 0, "", "")
		return
	}
	s.Alive, s.Build = u.now().Unix(), u.Trust.Version
	if e = writeJSON(filepath.Join(u.Dir, StatusFile), s); e != nil {
		u.logf("cannot write the update status", "error", e.Error())
	}
}

// owned reports whether a container belongs to the managed service.
func (u *Updater) owned(c Container) bool { return c.Project == u.Project && c.Service == u.Service }

// Run serves requests until the context ends.
func (u *Updater) Run(ctx context.Context) {
	if !u.takeOver(ctx) {
		// Too late to take over: the previous updater keeps running and
		// removes this container.
		u.logf("the previous updater is still in charge; waiting to be removed")
		<-ctx.Done()
		return
	}
	j, e := u.load()
	switch {
	case e != nil:
		u.logf("updates are stopped", "error", e.Error())
		u.status("", PhaseFailed, "", 0, "The updater journal is damaged; updates are stopped until it is repaired.", "")
	case j.Active != nil:
		u.logf("an update was interrupted; recovering", "version", j.Active.Version)
		u.recover(ctx, &j)
	default:
		// A status left mid-way by a restart before any change was made.
		if s, e := ReadStatus(u.Dir); e != nil {
			u.status("", "idle", "", 0, "", "")
		} else if !Done(s.Phase) && s.Phase != "idle" {
			u.status(s.ID, PhaseFailed, s.Version, s.Sequence, "The updater restarted before the update began; nothing was changed.", "")
		}
	}
	if r, e := ReadBackupReport(u.Dir); e == nil {
		u.lastRun = r.Last
	}
	interval := u.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	beat := time.Time{}
	for {
		u.Once(ctx)
		if u.refreshDue {
			u.refreshDue = false
			if u.refresh(ctx) {
				return // replaced by a new updater
			}
		}
		if u.Backups.Snapshot != nil {
			u.backups(ctx)
		}
		if time.Since(beat) >= time.Minute {
			u.alive()
			u.report()
			beat = time.Now()
			u.refreshDue = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// Once handles a waiting request, if any.
func (u *Updater) Once(ctx context.Context) {
	path := filepath.Join(u.Dir, RequestFile)
	var r Request
	e := readJSON(path, &r, 128*1024)
	if errors.Is(e, os.ErrNotExist) {
		return
	}
	_ = os.Remove(path)
	if e != nil || !validRequest(r) {
		id := ""
		if validRequest(Request{ID: r.ID, RequestedAt: 1}) {
			id = r.ID
		}
		u.status(id, PhaseFailed, "", 0, "The update request was malformed.", "")
		return
	}
	u.apply(ctx, r)
}

// imageMatches accepts the signed image under either image store: the
// classic store reports the config digest, the containerd store the
// manifest (or index) digest.
func imageMatches(id string, m Manifest) bool {
	return id == m.ImageID || m.Digest != "" && id == m.Digest
}

func (u *Updater) apply(ctx context.Context, r Request) {
	m := r.Release.Manifest
	fail := func(detail string) { u.status(r.ID, PhaseFailed, m.Version, m.Sequence, detail, "") }
	j, e := u.load()
	if e != nil {
		fail("The updater journal is damaged; updates are stopped until it is repaired.")
		return
	}
	floor := max(j.HighWater, u.Trust.Sequence)
	switch {
	case !Verify(r.Release, u.Trust.Keys):
		fail("The release is not signed by a trusted key.")
		return
	case !Fresh(m, u.now()):
		fail("The release has expired or is not yet valid.")
		return
	case m.Sequence <= floor:
		fail("This release is not newer than the installed one.")
		return
	}
	u.status(r.ID, PhaseAccepted, m.Version, m.Sequence, "", "")
	c, e := u.Engine.Find(ctx, u.Project, u.Service)
	if errors.Is(e, ErrNotFound) {
		fail("The server container was not found.")
		return
	} else if e != nil {
		u.logf("cannot ask Docker for the server container", "error", e.Error())
		fail("The Docker Engine could not be reached.")
		return
	}
	u.status(r.ID, PhasePulling, m.Version, m.Sequence, "", "")
	target, e := u.image(ctx, m)
	if e != nil {
		u.logf("image unavailable", "error", e.Error())
		fail(e.Error())
		return
	}
	// A previous version left behind by an earlier update would block the
	// rename below; remove it when it is stopped and ours.
	if old, e := u.Engine.Inspect(ctx, c.Name+previousSuffix); e == nil && old.ID != c.ID {
		if !u.owned(old) || old.Running {
			fail("A container named " + c.Name + previousSuffix + " is in the way; remove it and try again.")
			return
		}
		if e = u.Engine.Remove(ctx, old.ID); e != nil {
			fail("A leftover previous version could not be removed; remove it and try again.")
			return
		}
	}
	// From here on the journal records each step for recovery.
	j.Active = &active{Request: r.ID, Version: m.Version, Sequence: m.Sequence, Previous: c.ID, Name: c.Name}
	if e = u.save(j); e != nil {
		fail("The updater cannot record its progress.")
		return
	}
	u.status(r.ID, PhaseBackingUp, m.Version, m.Sequence, "", "")
	if e = u.Engine.Stop(ctx, c.ID); e != nil {
		u.logf("cannot stop the server", "error", e.Error())
		u.restart(ctx, &j, r, "The server could not be stopped for the backup.")
		return
	}
	backup := fmt.Sprintf("update-%s-%d", u.now().UTC().Format("20060102-150405"), m.Sequence)
	if e = u.Backups.Create(backup); e != nil {
		u.logf("backup failed", "error", e.Error())
		_ = os.RemoveAll(filepath.Join(u.Backups.Dir, backup))
		u.restart(ctx, &j, r, "The backup could not be completed or verified; the server was restarted unchanged.")
		return
	}
	j.Active.Backup = backup
	if e = u.save(j); e != nil {
		u.restart(ctx, &j, r, "The updater cannot record its progress; the server was restarted unchanged.")
		return
	}
	u.status(r.ID, PhaseStarting, m.Version, m.Sequence, "", backup)
	if e = u.Engine.Rename(ctx, c.ID, c.Name+previousSuffix); e != nil {
		u.logf("rename failed", "error", e.Error())
		u.restart(ctx, &j, r, "The server container could not be prepared for the update; the server was restarted unchanged.")
		return
	}
	id, e := u.Engine.Clone(ctx, c, target, c.Name)
	if e == nil {
		j.Active.New = id
		if e = u.save(j); e == nil {
			e = u.Engine.Start(ctx, id)
		}
	}
	if e == nil {
		e = waitHealthy(ctx, u.Engine, id, u.health(), u.poll())
	}
	if e == nil {
		if n, e2 := u.Engine.Inspect(ctx, id); e2 != nil || !imageMatches(n.ImageID, m) {
			e = errors.New("the new container does not run the signed image")
		}
	}
	if e != nil {
		u.logf("the new version failed; rolling back", "error", e.Error())
		u.rollback(ctx, &j, "The new version did not become healthy; the previous version and its data were restored.")
		return
	}
	// Commit before removing the previous version: a crash after this point
	// keeps the new version.
	j.HighWater, j.Active.Committed = m.Sequence, true
	if e = u.save(j); e != nil {
		u.logf("cannot record the installed release", "error", e.Error())
	}
	u.finish(ctx, &j)
}

// finish removes the previous version of a committed update.
func (u *Updater) finish(ctx context.Context, j *journal) {
	a := j.Active
	if e := u.Engine.Remove(ctx, a.Previous); e != nil && !errors.Is(e, ErrNotFound) {
		u.logf("cannot remove the previous container", "error", e.Error())
	}
	if n, e := u.Engine.Inspect(ctx, a.New); e == nil {
		if e = u.Engine.Tag(ctx, n.ImageID, InstalledRepository(u.Project), "current"); e != nil {
			u.logf("cannot record the installed image", "error", e.Error())
		}
	}
	j.Active = nil
	if e := u.save(*j); e != nil {
		u.logf("cannot record the installed release", "error", e.Error())
	}
	if e := u.Backups.Prune(); e != nil {
		u.logf("cannot prune old backups", "error", e.Error())
	}
	u.status(a.Request, PhaseSucceeded, a.Version, a.Sequence, "", a.Backup)
	u.logf("server updated", "version", a.Version, "sequence", a.Sequence)
	u.refreshDue = true
}

// recover completes or rolls back an update interrupted by a restart.
func (u *Updater) recover(ctx context.Context, j *journal) {
	a := j.Active
	if a.Committed {
		u.finish(ctx, j)
		return
	}
	// The previous version is gone only if the update had completed.
	if _, e := u.Engine.Inspect(ctx, a.Previous); errors.Is(e, ErrNotFound) && a.New != "" {
		if n, e := u.Engine.Inspect(ctx, a.New); e == nil && u.owned(n) {
			if !n.Running {
				_ = u.Engine.Start(ctx, n.ID)
			}
			j.HighWater = max(j.HighWater, a.Sequence)
			u.finish(ctx, j)
			return
		}
	}
	u.rollback(ctx, j, "The update was interrupted (the updater restarted); the previous version and its data were restored.")
}

// image makes the signed image available locally and checks its ID.
func (u *Updater) image(ctx context.Context, m Manifest) (string, error) {
	ref := m.ImageID
	if m.Digest != "" {
		ref = m.Image + "@" + m.Digest
	}
	id, e := u.Engine.ImageID(ctx, ref)
	if errors.Is(e, ErrNotFound) && m.Digest != "" {
		if e = u.Engine.Pull(ctx, ref); e != nil {
			return "", errors.New("The new server image could not be downloaded.")
		}
		id, e = u.Engine.ImageID(ctx, ref)
	}
	switch {
	case errors.Is(e, ErrNotFound):
		return "", errors.New("The new server image is not available.")
	case e != nil:
		return "", errors.New("The Docker Engine could not be asked about the new image.")
	case !imageMatches(id, m):
		return "", errors.New("The downloaded image does not match the signed release.")
	}
	// A readable name for the install command and docker ps; the container
	// is checked against the signed image once it runs.
	tag := strings.ReplaceAll(m.Version, "+", "-")
	if e = u.Engine.Tag(ctx, id, m.Image, tag); e == nil {
		return m.Image + ":" + tag, nil
	}
	return id, nil
}

// restart brings the unchanged server back after a failure before the swap.
func (u *Updater) restart(ctx context.Context, j *journal, r Request, detail string) {
	m := r.Release.Manifest
	if e := u.Engine.Start(ctx, j.Active.Previous); e != nil {
		detail += " Starting the server again also failed; start it with the install command."
	}
	j.Active = nil
	_ = u.save(*j)
	u.status(r.ID, PhaseFailed, m.Version, m.Sequence, detail, "")
}

// rollback removes the new container, restores the backup and starts the
// previous container. It tolerates steps that never happened and acts only
// on containers of the managed service.
func (u *Updater) rollback(ctx context.Context, j *journal, detail string) {
	a := j.Active
	fail := func(d string) {
		u.status(a.Request, PhaseFailed, a.Version, a.Sequence, d, a.Backup)
		j.Active = nil
		if e := u.save(*j); e != nil {
			u.logf("cannot record the rollback", "error", e.Error())
		}
	}
	previous, e := u.Engine.Inspect(ctx, a.Previous)
	if e != nil || !u.owned(previous) {
		fail("Rolling back failed: the previous version's container is missing. Run the install command to start the server.")
		return
	}
	if a.New != "" {
		if n, e := u.Engine.Inspect(ctx, a.New); e == nil && u.owned(n) && n.ID != previous.ID {
			_ = u.Engine.Stop(ctx, n.ID)
			if e := u.Engine.Remove(ctx, n.ID); e != nil {
				u.logf("cannot remove the new container", "error", e.Error())
			}
		}
	} else if c, e := u.Engine.Find(ctx, u.Project, u.Service); e == nil && c.ID != previous.ID && u.owned(c) {
		_ = u.Engine.Stop(ctx, c.ID)
		_ = u.Engine.Remove(ctx, c.ID)
	}
	_ = u.Engine.Stop(ctx, previous.ID)
	if a.Backup != "" {
		if e := u.Backups.Restore(a.Backup); e != nil {
			u.logf("restore failed", "error", e.Error())
			fail("Rolling back failed: the data could not be restored from backup " + a.Backup + ". Restore it before starting the server.")
			return
		}
	}
	if previous.Name != a.Name {
		if e := u.Engine.Rename(ctx, previous.ID, a.Name); e != nil {
			u.logf("cannot rename the previous container", "error", e.Error())
		}
	}
	phase := PhaseRolledBack
	if e := u.Engine.Start(ctx, previous.ID); e == nil {
		if e = waitHealthy(ctx, u.Engine, previous.ID, u.health(), u.poll()); e != nil {
			detail += " The previous version has not become healthy yet; check the server log."
		}
	} else {
		phase, detail = PhaseFailed, detail+" The previous version could not be started; run the install command."
	}
	u.status(a.Request, phase, a.Version, a.Sequence, detail, a.Backup)
	j.Active = nil
	if e := u.save(*j); e != nil {
		u.logf("cannot record the rollback", "error", e.Error())
	}
}

func (u *Updater) health() time.Duration {
	if u.Health > 0 {
		return u.Health
	}
	return 5 * time.Minute
}

func (u *Updater) poll() time.Duration {
	if u.Poll > 0 {
		return u.Poll
	}
	return 3 * time.Second
}
