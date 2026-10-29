package serverupdate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Container is what the updater needs to know about the server container.
type Container struct {
	ID           string
	Name         string
	Image        string // the configured reference
	ImageID      string
	Running      bool
	Health       string // healthy, unhealthy, starting, or "" without a check
	RestartCount int
	Created      time.Time
	// Project and Service are the Compose labels.
	Project string
	Service string
	inspect map[string]json.RawMessage
}

// Engine is the part of the Docker Engine API the updater uses.
type Engine interface {
	Find(ctx context.Context, project, service string) (Container, error)
	Inspect(ctx context.Context, id string) (Container, error)
	ImageID(ctx context.Context, ref string) (string, error)
	Pull(ctx context.Context, ref string) error
	Stop(ctx context.Context, id string) error
	Start(ctx context.Context, id string) error
	Tag(ctx context.Context, image, repo, tag string) error
	Rename(ctx context.Context, id, name string) error
	Remove(ctx context.Context, id string) error
	// Clone creates a stopped copy of a container with another image.
	Clone(ctx context.Context, c Container, image, name string) (string, error)
}

// Docker talks to the Docker Engine API over its Unix socket with the
// standard library only.
type Docker struct {
	client *http.Client
}

// apiVersion is empty: the Engine then answers with its own current API
// version. Pinning an old one fails on newer engines, which drop support
// for old versions; the fields used here are stable across versions.
const apiVersion = ""

// NewDocker connects to the Engine socket.
func NewDocker(socket string) *Docker {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &Docker{client: &http.Client{Transport: tr}}
}

// ErrNotFound is a missing container or image.
var ErrNotFound = errors.New("not found")

// callTimeout bounds every Engine call but the pull, so a hung daemon cannot
// stall the updater for good.
const callTimeout = 2 * time.Minute

func (d *Docker) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		rd = bytes.NewReader(b)
	}
	u := "http://docker" + apiVersion + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, e := http.NewRequestWithContext(ctx, method, u, rd)
	if e != nil {
		return e
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, e := d.client.Do(req)
	if e != nil {
		return errors.New("cannot reach the Docker Engine")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if res.StatusCode == http.StatusNotModified {
		return nil
	}
	if res.StatusCode >= 300 {
		var m struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&m)
		return fmt.Errorf("docker %s %s: %d %s", method, path, res.StatusCode, clip(m.Message))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
}

func clip(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
}

func (d *Docker) Find(ctx context.Context, project, service string) (Container, error) {
	f, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + project, "com.docker.compose.service=" + service}})
	var list []struct {
		ID      string   `json:"Id"`
		Names   []string `json:"Names"`
		Created int64    `json:"Created"`
	}
	if e := d.do(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(f)}}, nil, &list); e != nil {
		return Container{}, e
	}
	if len(list) == 0 {
		return Container{}, ErrNotFound
	}
	// Prefer a container whose name is not a kept previous version.
	best := list[0]
	for _, c := range list {
		if len(c.Names) > 0 && !strings.HasSuffix(c.Names[0], previousSuffix) && (len(best.Names) == 0 || strings.HasSuffix(best.Names[0], previousSuffix) || c.Created > best.Created) {
			best = c
		}
	}
	return d.Inspect(ctx, best.ID)
}

// previousSuffix names the container kept during an update.
const previousSuffix = "-previous"

func (d *Docker) Inspect(ctx context.Context, id string) (Container, error) {
	var raw map[string]json.RawMessage
	if e := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &raw); e != nil {
		return Container{}, e
	}
	var v struct {
		ID           string    `json:"Id"`
		Name         string    `json:"Name"`
		Image        string    `json:"Image"`
		RestartCount int       `json:"RestartCount"`
		Created      time.Time `json:"Created"`
		Config       struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		State struct {
			Running bool `json:"Running"`
			Health  *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	b, _ := json.Marshal(raw)
	if e := json.Unmarshal(b, &v); e != nil {
		return Container{}, e
	}
	c := Container{ID: v.ID, Name: strings.TrimPrefix(v.Name, "/"), Image: v.Config.Image, ImageID: v.Image, Running: v.State.Running, RestartCount: v.RestartCount, Created: v.Created,
		Project: v.Config.Labels["com.docker.compose.project"], Service: v.Config.Labels["com.docker.compose.service"], inspect: raw}
	if v.State.Health != nil {
		c.Health = v.State.Health.Status
	}
	return c, nil
}

func (d *Docker) ImageID(ctx context.Context, ref string) (string, error) {
	var v struct {
		ID string `json:"Id"`
	}
	if e := d.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, &v); e != nil {
		return "", e
	}
	return v.ID, nil
}

// Pull downloads an image; ref is repository@sha256:digest.
func (d *Docker) Pull(ctx context.Context, ref string) error {
	repo, dig, ok := strings.Cut(ref, "@")
	if !ok {
		return errors.New("pull needs a digest reference")
	}
	u := "http://docker" + apiVersion + "/images/create?" + url.Values{"fromImage": {repo}, "tag": {dig}}.Encode()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if e != nil {
		return e
	}
	res, e := d.client.Do(req)
	if e != nil {
		return errors.New("cannot reach the Docker Engine")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("image pull refused: %d", res.StatusCode)
	}
	// The pull streams progress lines; an error arrives as one of them.
	sc := bufio.NewScanner(io.LimitReader(res.Body, 64<<20))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var line struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Error != "" {
			return fmt.Errorf("image pull failed: %s", clip(line.Error))
		}
	}
	return sc.Err()
}

func (d *Docker) Stop(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop", url.Values{"t": {"20"}}, nil, nil)
}

func (d *Docker) Start(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

func (d *Docker) Tag(ctx context.Context, image, repo, tag string) error {
	return d.do(ctx, http.MethodPost, "/images/"+image+"/tag", url.Values{"repo": {repo}, "tag": {tag}}, nil, nil)
}

func (d *Docker) Rename(ctx context.Context, id, name string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/rename", url.Values{"name": {name}}, nil, nil)
}

func (d *Docker) Remove(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), url.Values{"force": {"1"}}, nil, nil)
}

// Clone keeps the container's host settings (ports, volumes, limits,
// restart policy, security options) and what Compose set on it
// (environment, labels, health check, the updater's entry point);
// everything the old image only defaulted (entry point, user, its
// environment and labels, ...) comes from the new image instead.
func (d *Docker) Clone(ctx context.Context, c Container, image, name string) (string, error) {
	var config map[string]json.RawMessage
	if e := json.Unmarshal(c.inspect["Config"], &config); e != nil {
		return "", errors.New("cannot read the container settings")
	}
	var old struct {
		Config map[string]json.RawMessage `json:"Config"`
	}
	if e := d.do(ctx, http.MethodGet, "/images/"+c.ImageID+"/json", nil, nil, &old); e != nil {
		return "", errors.New("cannot read the previous image's settings")
	}
	stripDefaults(config, old.Config)
	for _, k := range []string{"Hostname", "Image"} {
		delete(config, k)
	}
	body := map[string]any{}
	for k, v := range config {
		body[k] = v
	}
	body["Image"] = image
	body["HostConfig"] = c.inspect["HostConfig"]
	var network struct {
		Networks map[string]struct {
			Aliases []string `json:"Aliases"`
		} `json:"Networks"`
	}
	_ = json.Unmarshal(c.inspect["NetworkSettings"], &network)
	endpoints := map[string]any{}
	short := c.ID
	if len(short) > 12 {
		short = short[:12]
	}
	for net, n := range network.Networks {
		aliases := []string{}
		for _, a := range n.Aliases {
			if a != short && a != c.ID {
				aliases = append(aliases, a)
			}
		}
		endpoints[net] = map[string]any{"Aliases": aliases}
	}
	body["NetworkingConfig"] = map[string]any{"EndpointsConfig": endpoints}
	var out struct {
		ID string `json:"Id"`
	}
	if e := d.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, &out); e != nil {
		return "", e
	}
	return out.ID, nil
}

// stripDefaults removes from a container's settings what equals the image's
// own defaults: the environment and labels entries the image set, and other
// fields that are identical.
func stripDefaults(config, image map[string]json.RawMessage) {
	for k, v := range image {
		switch k {
		case "Env":
			var have, def []string
			_ = json.Unmarshal(config[k], &have)
			_ = json.Unmarshal(v, &def)
			keep := []string{}
			for _, e := range have {
				if !slices.Contains(def, e) {
					keep = append(keep, e)
				}
			}
			config[k], _ = json.Marshal(keep)
		case "Labels":
			var have, def map[string]string
			_ = json.Unmarshal(config[k], &have)
			_ = json.Unmarshal(v, &def)
			for name, value := range def {
				if have[name] == value {
					delete(have, name)
				}
			}
			config[k], _ = json.Marshal(have)
		default:
			if cur, ok := config[k]; ok && bytes.Equal(compact(cur), compact(v)) {
				delete(config, k)
			}
		}
	}
}

func compact(b json.RawMessage) []byte {
	var out bytes.Buffer
	if json.Compact(&out, b) != nil {
		return b
	}
	return out.Bytes()
}

// waitHealthy waits until the container reports healthy (or runs, without a
// health check) and fails early when it keeps restarting.
func waitHealthy(ctx context.Context, en Engine, id string, timeout time.Duration, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, e := en.Inspect(ctx, id)
		if e == nil {
			switch {
			case c.Health == "healthy", c.Health == "" && c.Running:
				return nil
			case c.Health == "unhealthy", c.RestartCount >= 2:
				return errors.New("the new version did not become healthy")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
	return errors.New("the new version did not become healthy in time")
}
