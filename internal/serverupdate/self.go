package serverupdate

import (
	"context"
	"errors"
	"strings"
	"time"
)

// The updater follows the server's image, so fixes to updates, backups and
// rollbacks reach installations that are only updated from the dashboard.
// After the server moved to another image (an update, or found at start),
// the running updater creates a copy of its own container with that image
// under a temporary name and starts it. The copy stops and removes its
// predecessor and takes the original name. A copy that has not taken over
// in time is removed, and that image is not tried again.
//
// The two never act at once: the predecessor waits without doing anything
// until it is stopped, and a copy that is older than three quarters of that
// wait no longer takes over (the predecessor removes it instead).

// nextSuffix names the copy until it has taken over.
const nextSuffix = "-next"

func (u *Updater) handover() time.Duration {
	if u.Handover > 0 {
		return u.Handover
	}
	return 2 * time.Minute
}

// me returns this updater's container, or false if it cannot be told apart
// from the server's (no self-updates then).
func (u *Updater) me(ctx context.Context) (Container, bool) {
	if u.Self == "" {
		return Container{}, false
	}
	c, e := u.Engine.Inspect(ctx, u.Self)
	if e != nil || c.Project != u.Project || c.Service == "" || c.Service == u.Service {
		return Container{}, false
	}
	return c, true
}

// sibling reports whether c is another container of this updater's service.
func sibling(me, c Container) bool {
	return c.ID != me.ID && c.Project == me.Project && c.Service == me.Service
}

// takeOver runs first in every updater. In a copy it stops and removes the
// predecessor and takes its name; it returns false if this copy came too
// late and must stay idle.
func (u *Updater) takeOver(ctx context.Context) bool {
	me, ok := u.me(ctx)
	if !ok {
		return true
	}
	name, copied := strings.CutSuffix(me.Name, nextSuffix)
	if !copied {
		return true
	}
	prev, e := u.Engine.Inspect(ctx, name)
	switch {
	case errors.Is(e, ErrNotFound):
	case e != nil, !sibling(me, prev):
		return false
	case prev.Running && u.now().Sub(me.Created) > u.handover()*3/4:
		return false
	default:
		if e = u.Engine.Stop(ctx, prev.ID); e != nil {
			u.logf("cannot stop the previous updater", "error", e.Error())
			return false
		}
		if e = u.Engine.Remove(ctx, prev.ID); e != nil {
			u.logf("cannot remove the previous updater", "error", e.Error())
		}
	}
	if e = u.Engine.Rename(ctx, me.ID, name); e != nil {
		u.logf("cannot take the updater's name", "error", e.Error())
	}
	u.logf("took over from the previous updater")
	return true
}

// refresh replaces this updater with one running the server's image when
// they differ. It returns true if this updater must stop: the copy took over
// (or the updater is shutting down while it waited).
func (u *Updater) refresh(ctx context.Context) bool {
	me, ok := u.me(ctx)
	if !ok || strings.HasSuffix(me.Name, nextSuffix) {
		return false
	}
	j, e := u.load()
	if e != nil || j.Active != nil {
		return false
	}
	server, e := u.Engine.Find(ctx, u.Project, u.Service)
	if e != nil || !u.owned(server) || !server.Running || server.Health != "healthy" && server.Health != "" ||
		server.ImageID == "" || server.ImageID == me.ImageID || server.ImageID == j.SelfFailed {
		return false
	}
	name := me.Name + nextSuffix
	// A copy left behind by an interrupted handover.
	if old, e := u.Engine.Inspect(ctx, name); e == nil {
		if !sibling(me, old) {
			return false
		}
		if e = u.Engine.Remove(ctx, old.ID); e != nil {
			u.logf("cannot remove a leftover updater copy", "error", e.Error())
			return false
		}
	}
	// The server's readable image name when it still names the same image.
	image := server.ImageID
	if id, e := u.Engine.ImageID(ctx, server.Image); e == nil && id == server.ImageID {
		image = server.Image
	}
	id, e := u.Engine.Clone(ctx, me, image, name)
	if e != nil {
		u.logf("cannot create the new updater", "error", e.Error())
		return false
	}
	if n, e := u.Engine.Inspect(ctx, id); e == nil && n.ImageID == server.ImageID {
		u.logf("starting the updater from the server's image", "image", image)
		if e = u.Engine.Start(ctx, id); e == nil {
			// The copy stops this container when it takes over.
			select {
			case <-ctx.Done():
				return true
			case <-time.After(u.handover()):
			}
		}
	}
	if e = u.Engine.Remove(ctx, id); e != nil && !errors.Is(e, ErrNotFound) {
		u.logf("cannot remove the new updater", "error", e.Error())
	}
	j, e = u.load()
	if e == nil && j.Active == nil {
		j.SelfFailed = server.ImageID
		if e = u.save(j); e != nil {
			u.logf("cannot record the failed updater image", "error", e.Error())
		}
	}
	u.logf("the new updater did not take over; this one keeps running", "image", image)
	return false
}
