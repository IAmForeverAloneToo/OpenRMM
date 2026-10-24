// Package response runs structured response actions on the device:
// read-only snapshots of processes, network connections, services,
// scheduled tasks and a registry key, and killing a process or tree. Each
// produces a protocol.ActionResult that the agent uploads as case evidence.
package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Limits on what one action reports.
const (
	maxNotes     = 100
	maxItems     = 20000
	maxHashBytes = 512 << 20 // images over 512 MB are not hashed
)

// ErrUnsupported is returned off Windows.
var ErrUnsupported = errors.New("response actions are available on Windows only")

// ActionTime bounds one action, including hashing (the server waits up to 30
// minutes for its result to start uploading).
const ActionTime = 20 * time.Minute

// Run executes a validated action.
func Run(ctx context.Context, a protocol.ResponseAction, cache *HashCache) (protocol.ActionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, ActionTime)
	defer cancel()
	r := protocol.ActionResult{Format: protocol.ActionFormat, Version: 1, Action: a, DeviceTime: stamp(time.Now())}
	if !a.Valid() {
		return r, errors.New("invalid action")
	}
	n := &notes{}
	var e error
	switch a.Kind {
	case "processes":
		r.Processes, e = processList(ctx, cache, n)
	case "connections":
		r.Connections, e = connections(ctx, n)
	case "services":
		r.Services, e = services(ctx, cache, n)
	case "tasks":
		r.Tasks, e = tasks(ctx, n)
	case "registry":
		r.Registry, e = registryKey(a.Key, n)
	case "persistence":
		r.Persistence, e = persistence(ctx, cache, n)
	case "hunt":
		src := huntSourcesFor(cache, n)
		if src.roots == nil {
			e = ErrUnsupported
			break
		}
		h := hunt(ctx, *a.Hunt, src, n)
		r.Hunt = &h
	case "kill":
		// Hashed fresh: the evidence must describe the file as it is now.
		var truncated bool
		r.Killed, truncated = processes.Kill(ctx, a, func(p string) (string, string) { return cache.Fresh(ctx, p) })
		if truncated {
			n.add("the process tree has more than 1,024 processes; the rest was left running")
		}
	}
	r.Notes = n.list
	return r, e
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

type notes struct{ list []string }

func (n *notes) add(s string) {
	if len(n.list) < maxNotes {
		n.list = append(n.list, s)
	} else if len(n.list) == maxNotes {
		n.list = append(n.list, "(more notes omitted)")
	}
}

// hashBuffers are reused read buffers: a hunt hashes many files.
const hashBuffer = 256 << 10

var hashBuffers = sync.Pool{New: func() any { return new([hashBuffer]byte) }}

// HashCache keeps image hashes for the agent's lifetime, so repeated
// process lists are fast. An entry is used only for the same file (volume
// and file number), size, modification and change time.
type HashCache struct {
	mu sync.Mutex
	m  map[string]cached
	// limit bounds the entries (0: 50,000); the cache is emptied when full.
	limit int
}

// huntFiles caches the hashes of files an indicator hunt reads,
// apart from the process image cache.
var huntFiles = &HashCache{limit: 100000}

type cached struct {
	size     int64
	modified time.Time
	identity string
	hash     string
}

// Hash returns the SHA-256 of a file, from the cache when it is unchanged,
// or "" and a note: too_large or unreadable.
func (c *HashCache) Hash(ctx context.Context, path string) (string, string) {
	return c.hash(ctx, path, true)
}

// Fresh hashes a file without the cache (used before a kill).
func (c *HashCache) Fresh(ctx context.Context, path string) (string, string) {
	return c.hash(ctx, path, false)
}

func (c *HashCache) hash(ctx context.Context, path string, useCache bool) (string, string) {
	if path == "" {
		return "", "unreadable"
	}
	// Files on other computers are never opened as SYSTEM (see networkPath).
	if networkPath(path) {
		return "", "network_path"
	}
	f, e := os.Open(path)
	if e != nil {
		return "", "unreadable"
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() {
		return "", "unreadable"
	}
	if i.Size() > maxHashBytes {
		return "", "too_large"
	}
	key := cached{size: i.Size(), modified: i.ModTime(), identity: fileIdentity(f)}
	if useCache && key.identity != "" {
		c.mu.Lock()
		v, ok := c.m[path]
		c.mu.Unlock()
		if ok && v.size == key.size && v.modified.Equal(key.modified) && v.identity == key.identity {
			return v.hash, ""
		}
	}
	h := sha256.New()
	buf := hashBuffers.Get().(*[hashBuffer]byte)
	defer hashBuffers.Put(buf)
	for {
		if ctx.Err() != nil {
			return "", "unreadable"
		}
		n, e := f.Read(buf[:])
		h.Write(buf[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", "unreadable"
		}
	}
	key.hash = hex.EncodeToString(h.Sum(nil))
	if key.identity != "" {
		c.mu.Lock()
		limit := c.limit
		if limit == 0 {
			limit = 50000
		}
		if c.m == nil || len(c.m) > limit {
			c.m = map[string]cached{}
		}
		c.m[path] = key
		c.mu.Unlock()
	}
	return key.hash, ""
}
