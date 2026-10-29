package serverupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
)

const (
	oldImage = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	newImage = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

type fakeEngine struct {
	containers map[string]*Container
	images     map[string]string // ref → image ID
	healthy    map[string]bool   // image ID → becomes healthy
	onStart    func(imageID string)
	next       int
}

func (f *fakeEngine) Find(_ context.Context, _, _ string) (Container, error) {
	for _, c := range f.containers {
		if !strings.HasSuffix(c.Name, previousSuffix) {
			return *c, nil
		}
	}
	return Container{}, ErrNotFound
}
func (f *fakeEngine) Inspect(_ context.Context, id string) (Container, error) {
	if c, ok := f.containers[id]; ok {
		return *c, nil
	}
	for _, c := range f.containers {
		if c.Name == id {
			return *c, nil
		}
	}
	return Container{}, ErrNotFound
}
func (f *fakeEngine) ImageID(_ context.Context, ref string) (string, error) {
	if id, ok := f.images[ref]; ok {
		return id, nil
	}
	return "", ErrNotFound
}
func (f *fakeEngine) Pull(context.Context, string) error { return errors.New("offline") }
func (f *fakeEngine) Tag(_ context.Context, image, repo, tag string) error {
	f.images[repo+":"+tag] = image
	return nil
}
func (f *fakeEngine) Stop(_ context.Context, id string) error {
	if c, ok := f.containers[id]; ok {
		c.Running, c.Health = false, ""
	}
	return nil
}
func (f *fakeEngine) Start(_ context.Context, id string) error {
	c, ok := f.containers[id]
	if !ok {
		return ErrNotFound
	}
	c.Running = true
	c.Health = "unhealthy"
	if f.healthy[c.ImageID] {
		c.Health = "healthy"
	}
	if f.onStart != nil {
		f.onStart(c.ImageID)
	}
	return nil
}
func (f *fakeEngine) Rename(_ context.Context, id, name string) error {
	for _, c := range f.containers {
		if c.Name == name && c.ID != id {
			return errors.New("name in use")
		}
	}
	f.containers[id].Name = name
	return nil
}
func (f *fakeEngine) Remove(_ context.Context, id string) error {
	if _, ok := f.containers[id]; !ok {
		return ErrNotFound
	}
	delete(f.containers, id)
	return nil
}
func (f *fakeEngine) Clone(_ context.Context, c Container, image, name string) (string, error) {
	f.next++
	id := "new" + string(rune('0'+f.next))
	f.containers[id] = &Container{ID: id, Name: name, Image: image, ImageID: f.images[image], Project: c.Project, Service: c.Service}
	return id, nil
}

type fixture struct {
	t       *testing.T
	u       *Updater
	engine  *fakeEngine
	priv    ed25519.PrivateKey
	data    string
	secrets string
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	pub, priv, _ := ed25519.GenerateKey(nil)
	root := t.TempDir()
	f := &fixture{t: t, priv: priv, now: time.Unix(1800000000, 0)}
	f.data, f.secrets = filepath.Join(root, "data"), filepath.Join(root, "secrets")
	for _, d := range []string{f.data, f.secrets, filepath.Join(root, "backups"), filepath.Join(root, "exchange"), filepath.Join(f.data, "agent-releases")} {
		if e := os.MkdirAll(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("database v1"), 0600)
	os.WriteFile(filepath.Join(f.data, "agent-releases", "a.exe"), []byte("agent"), 0600)
	os.WriteFile(filepath.Join(f.secrets, "admin-key.bin"), []byte("key"), 0600)
	f.engine = &fakeEngine{
		containers: map[string]*Container{"old": {ID: "old", Name: "openrmm-server-1", ImageID: oldImage, Running: true, Health: "healthy", Project: "openrmm", Service: "server"}},
		images:     map[string]string{oldImage: oldImage, newImage: newImage},
		healthy:    map[string]bool{oldImage: true, newImage: true},
	}
	f.u = &Updater{
		Dir:     filepath.Join(root, "exchange"),
		Engine:  f.engine,
		Project: "openrmm",
		Service: "server",
		Backups: Backups{Dir: filepath.Join(root, "backups"), Sources: map[string]string{"data": f.data, "secrets": f.secrets}, DB: "openrmm.db", Keep: 2,
			CheckDB: func(p string) error {
				if b, e := os.ReadFile(p); e != nil || !strings.HasPrefix(string(b), "database") {
					return errors.New("corrupt")
				}
				return nil
			}},
		Trust:  Current{Version: "1.0.0", Sequence: 10, Keys: []string{hex.EncodeToString(pub)}},
		Now:    func() time.Time { return f.now },
		Health: 200 * time.Millisecond,
		Poll:   10 * time.Millisecond,
	}
	return f
}

func (f *fixture) release(seq int64, image string) Release {
	m := Manifest{Product: Product, Version: "1.1.0+build", Sequence: seq, Image: "ghcr.io/example/openrmm-server", ImageID: image, Notes: "Fixes.",
		KeyID: agentupdate.Digest(f.priv.Public().(ed25519.PublicKey)), Issued: f.now.Add(-time.Hour).Unix(), Expires: f.now.Add(30 * 24 * time.Hour).Unix()}
	return Sign(f.priv, m)
}

func (f *fixture) run(r Release) Status {
	f.t.Helper()
	if e := SubmitRequest(f.u.Dir, Request{ID: "0123456789abcdef0123456789abcdef", Release: r, RequestedBy: "owner", RequestedAt: f.now.Unix()}, f.now); e != nil {
		f.t.Fatal(e)
	}
	f.u.Once(context.Background())
	s, e := ReadStatus(f.u.Dir)
	if e != nil {
		f.t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(f.u.Dir, RequestFile)); e == nil {
		f.t.Fatal("request left behind")
	}
	return s
}

func (f *fixture) read(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// A signed release replaces the image after a verified backup;
// the previous container is removed and the sequence recorded.
func TestUpdateSucceeds(t *testing.T) {
	f := newFixture(t)
	s := f.run(f.release(11, newImage))
	if s.Phase != PhaseSucceeded || s.Backup == "" {
		t.Fatal(s)
	}
	if len(f.engine.containers) != 1 {
		t.Fatal("previous container kept", f.engine.containers)
	}
	for _, c := range f.engine.containers {
		if c.ImageID != newImage || !c.Running || c.Name != "openrmm-server-1" || c.Image != "ghcr.io/example/openrmm-server:1.1.0-build" {
			t.Fatal(c)
		}
	}
	if _, e := f.u.Backups.Verify(s.Backup); e != nil {
		t.Fatal(e)
	}
	if j, _ := f.u.load(); j.HighWater != 11 || j.Active != nil {
		t.Fatal(j)
	}
	if f.engine.images[InstalledRepository("openrmm")+":current"] != newImage {
		t.Fatal("installed image not recorded", f.engine.images)
	}
	// The same release again is refused (replay).
	if s = f.run(f.release(11, newImage)); s.Phase != PhaseFailed || !strings.Contains(s.Detail, "not newer") {
		t.Fatal(s)
	}
}

// A new version that never becomes healthy is removed, the data it changed
// is restored from the backup and the previous version runs again.
func TestUpdateRollsBack(t *testing.T) {
	f := newFixture(t)
	f.engine.healthy[newImage] = false
	f.engine.onStart = func(id string) {
		if id == newImage {
			os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("database migrated by v2"), 0600)
			os.WriteFile(filepath.Join(f.data, "new-file"), []byte("x"), 0600)
		}
	}
	s := f.run(f.release(11, newImage))
	if s.Phase != PhaseRolledBack {
		t.Fatal(s)
	}
	c := f.engine.containers["old"]
	if len(f.engine.containers) != 1 || c == nil || !c.Running || c.Name != "openrmm-server-1" {
		t.Fatal(f.engine.containers)
	}
	if got := f.read(filepath.Join(f.data, "openrmm.db")); got != "database v1" {
		t.Fatal("data not restored", got)
	}
	if _, e := os.Stat(filepath.Join(f.data, "new-file")); e == nil {
		t.Fatal("new file left")
	}
	if f.read(filepath.Join(f.data, "agent-releases", "a.exe")) != "agent" || f.read(filepath.Join(f.secrets, "admin-key.bin")) != "key" {
		t.Fatal("restore incomplete")
	}
	if j, _ := f.u.load(); j.HighWater != 0 || j.Active != nil {
		t.Fatal(j)
	}
}

// Releases that are unsigned, older, expired or for another image are
// refused before anything changes.
func TestUpdateRefuses(t *testing.T) {
	f := newFixture(t)
	forged := f.release(11, newImage)
	forged.Manifest.Notes = "changed"
	expired := f.release(12, newImage)
	expired.Manifest.Expires = f.now.Add(-time.Minute).Unix()
	expired = Sign(f.priv, expired.Manifest)
	mismatch := f.release(13, newImage)
	f.engine.images[newImage] = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	for _, c := range []struct {
		r    Release
		want string
	}{
		{forged, "not signed"},
		{f.release(10, newImage), "not newer"},
		{expired, "expired"},
		{mismatch, "does not match"},
	} {
		if s := f.run(c.r); s.Phase != PhaseFailed || !strings.Contains(s.Detail, c.want) {
			t.Fatal(c.want, s)
		}
	}
	if c := f.engine.containers["old"]; len(f.engine.containers) != 1 || !c.Running || c.ImageID != oldImage {
		t.Fatal("server changed", f.engine.containers)
	}
	if entries := backupDirs(f.u.Backups.Dir); len(entries) != 0 {
		t.Fatal("backup taken for a refused release")
	}
}

// A backup that fails its check stops the update and restarts the server.
func TestUpdateBackupFailure(t *testing.T) {
	f := newFixture(t)
	os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("corrupt"), 0600)
	s := f.run(f.release(11, newImage))
	if s.Phase != PhaseFailed || !strings.Contains(s.Detail, "backup") {
		t.Fatal(s)
	}
	if c := f.engine.containers["old"]; !c.Running || c.ImageID != oldImage {
		t.Fatal("server not restarted")
	}
	if entries := backupDirs(f.u.Backups.Dir); len(entries) != 0 {
		t.Fatal("partial backup kept")
	}
}

// An update interrupted after the swap is rolled back when the updater
// starts again.
func TestUpdateInterrupted(t *testing.T) {
	f := newFixture(t)
	if e := f.u.Backups.Create("update-20260101-000000-1"); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(f.data, "openrmm.db"), []byte("database half migrated"), 0600)
	f.engine.containers["old"].Name, f.engine.containers["old"].Running = "openrmm-server-1"+previousSuffix, false
	f.engine.containers["new1"] = &Container{ID: "new1", Name: "openrmm-server-1", ImageID: newImage, Running: true, Project: "openrmm", Service: "server"}
	j := journal{Active: &active{Request: "0123456789abcdef0123456789abcdef", Version: "1.1.0", Sequence: 11, Previous: "old", Name: "openrmm-server-1", New: "new1", Backup: "update-20260101-000000-1"}}
	if e := f.u.save(j); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.u.Run(ctx)
	s, _ := ReadStatus(f.u.Dir)
	if s.Phase != PhaseRolledBack || !strings.Contains(s.Detail, "interrupted") {
		t.Fatal(s)
	}
	if c := f.engine.containers["old"]; len(f.engine.containers) != 1 || !c.Running || c.Name != "openrmm-server-1" {
		t.Fatal(f.engine.containers)
	}
	if f.read(filepath.Join(f.data, "openrmm.db")) != "database v1" {
		t.Fatal("not restored")
	}
}

func TestBackupPrune(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"update-20260101-000000-1", "update-20260101-000000-2", "update-20260101-000000-3"} {
		if e := f.u.Backups.Create(n); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(f.u.Backups.Dir, "update-20260101-000000-3", "data", "openrmm.db"), []byte("tampered"), 0600)
	if _, e := f.u.Backups.Verify("update-20260101-000000-3"); e == nil || f.u.Backups.Restore("update-20260101-000000-3") == nil {
		t.Fatal("changed backup accepted")
	}
	if f.read(filepath.Join(f.data, "openrmm.db")) != "database v1" {
		t.Fatal("refused restore touched the data")
	}
	if e := f.u.Backups.Prune(); e != nil {
		t.Fatal(e)
	}
	if entries := backupDirs(f.u.Backups.Dir); len(entries) != 2 || entries[0] != "update-20260101-000000-2" {
		t.Fatal(entries)
	}
}

// The check reads the signed file of the latest GitHub release and makes
// no request while the repository is the placeholder.
func TestChecker(t *testing.T) {
	f := newFixture(t)
	signed, _ := json.Marshal(f.release(11, newImage))
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "OpenRMM-server-update-check" || r.URL.RawQuery != "" {
			t.Error("unexpected request", r.URL)
		}
		switch r.URL.Path {
		case "/repos/example/openrmm/releases/latest":
			json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.1.0", "assets": []map[string]any{
				{"name": "other.zip", "browser_download_url": srv.URL + "/other", "size": 10},
				{"name": AssetName, "browser_download_url": srv.URL + "/asset", "size": len(signed)},
			}})
		case "/asset":
			w.Write(signed)
		case "/repos/example/redirect/releases/latest":
			json.NewEncoder(w).Encode(map[string]any{"assets": []map[string]any{{"name": AssetName, "browser_download_url": srv.URL + "/away", "size": 10}}})
		case "/away":
			http.Redirect(w, r, "https://elsewhere.example/x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	ctx := context.Background()
	if _, e := (Checker{Client: srv.Client(), Repo: placeholder}).Latest(ctx); !errors.Is(e, ErrNotConfigured) {
		t.Fatal("placeholder repository checked", e)
	}
	r, e := Checker{Client: srv.Client(), Repo: "example/openrmm"}.Latest(ctx)
	if e != nil || !f.u.Trust.Newer(r, f.now) {
		t.Fatal(r, e)
	}
	if _, e = (Checker{Client: srv.Client(), Repo: "example/redirect"}).Latest(ctx); e == nil {
		t.Fatal("redirect to another host followed")
	}
	// No full release yet (GitHub's latest ignores pre-releases): reported
	// as such, not as a failure.
	if _, e = (Checker{Client: srv.Client(), Repo: "example/missing"}).Latest(ctx); !errors.Is(e, ErrNoRelease) {
		t.Fatal("missing release not reported as none published", e)
	}
}

func TestExchange(t *testing.T) {
	f := newFixture(t)
	req := Request{ID: "0123456789abcdef0123456789abcdef", Release: f.release(11, newImage), RequestedBy: "owner", RequestedAt: f.now.Unix()}
	if e := SubmitRequest(f.u.Dir, req, f.now); e != nil {
		t.Fatal(e)
	}
	if e := SubmitRequest(f.u.Dir, req, f.now); !errors.Is(e, ErrBusy) {
		t.Fatal("second request accepted", e)
	}
	os.Remove(filepath.Join(f.u.Dir, RequestFile))
	f.u.status(req.ID, PhaseStarting, "1.1.0", 11, "", "")
	if e := SubmitRequest(f.u.Dir, req, f.now); !errors.Is(e, ErrBusy) {
		t.Fatal("request accepted while running", e)
	}
	if e := SubmitRequest(f.u.Dir, req, f.now.Add(time.Hour)); e != nil {
		t.Fatal("stale status blocks", e)
	}
	if !Valid(req.Release.Manifest) || ImageRef(req.Release.Manifest) != "ghcr.io/example/openrmm-server@"+newImage {
		t.Fatal("manifest")
	}
	bad := req.Release.Manifest
	bad.Image = "ghcr.io/Example/x:latest"
	if Valid(bad) {
		t.Fatal("tagged image name accepted")
	}
}

func backupDirs(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// The journal is kept out of the exchange volume and fails
// closed; a crash after the commit keeps the new version; a leftover previous
// version is removed first; journal containers outside the service are not
// touched; the containerd image store's digests match.
func TestUpdaterJournal(t *testing.T) {
	f := newFixture(t)
	// A journal written into the exchange volume (by the server) is ignored.
	os.WriteFile(filepath.Join(f.u.Dir, stateFile), []byte(`{"high_water":0}`), 0600)
	os.WriteFile(f.u.statePath(), []byte(`{"high_water":12}`), 0600)
	if s := f.run(f.release(12, newImage)); s.Phase != PhaseFailed || !strings.Contains(s.Detail, "not newer") {
		t.Fatal(s)
	}
	// A damaged journal stops updates.
	os.WriteFile(f.u.statePath(), []byte(`{"high_water":`), 0600)
	if s := f.run(f.release(13, newImage)); s.Phase != PhaseFailed || !strings.Contains(s.Detail, "journal") {
		t.Fatal(s)
	}
	// A backup name outside the pattern is refused.
	os.WriteFile(f.u.statePath(), []byte(`{"high_water":0,"active":{"request":"0123456789abcdef0123456789abcdef","version":"x","sequence":11,"previous":"old","name":"openrmm-server-1","backup":"../exchange/x"}}`), 0600)
	if _, e := f.u.load(); e == nil {
		t.Fatal("path in journal accepted")
	}
	// A journal pointing at a container of another service leaves it alone.
	f.engine.containers["other"] = &Container{ID: "other", Name: "database", ImageID: oldImage, Running: false, Project: "else", Service: "db"}
	f.u.save(journal{Active: &active{Request: "0123456789abcdef0123456789abcdef", Version: "x", Sequence: 11, Previous: "other", Name: "openrmm-server-1", New: "old"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.u.Run(ctx)
	if c := f.engine.containers["other"]; c == nil || c.Running || c.Name != "database" {
		t.Fatal("foreign container touched", c)
	}
	if c := f.engine.containers["old"]; c == nil || !c.Running {
		t.Fatal("server container removed")
	}
}

func TestUpdaterRecoversCommitted(t *testing.T) {
	f := newFixture(t)
	f.engine.containers["old"].Name, f.engine.containers["old"].Running = "openrmm-server-1"+previousSuffix, false
	f.engine.containers["new1"] = &Container{ID: "new1", Name: "openrmm-server-1", ImageID: newImage, Running: true, Health: "healthy", Project: "openrmm", Service: "server"}
	f.u.save(journal{HighWater: 11, Active: &active{Request: "0123456789abcdef0123456789abcdef", Version: "1.1.0", Sequence: 11, Previous: "old", Name: "openrmm-server-1", New: "new1", Backup: "update-20260101-000000-11", Committed: true}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.u.Run(ctx)
	if s, _ := ReadStatus(f.u.Dir); s.Phase != PhaseSucceeded {
		t.Fatal(s)
	}
	if len(f.engine.containers) != 1 || f.engine.containers["new1"] == nil || !f.engine.containers["new1"].Running {
		t.Fatal(f.engine.containers)
	}
	// Previous already removed but not committed: the new version is kept.
	g := newFixture(t)
	delete(g.engine.containers, "old")
	g.engine.containers["new1"] = &Container{ID: "new1", Name: "openrmm-server-1", ImageID: newImage, Running: true, Health: "healthy", Project: "openrmm", Service: "server"}
	g.u.save(journal{Active: &active{Request: "0123456789abcdef0123456789abcdef", Version: "1.1.0", Sequence: 11, Previous: "old", Name: "openrmm-server-1", New: "new1"}})
	g.u.Run(ctx)
	if j, _ := g.u.load(); j.HighWater != 11 || g.engine.containers["new1"] == nil {
		t.Fatal("new version dropped", j, g.engine.containers)
	}
}

func TestUpdaterLeftoverAndDigest(t *testing.T) {
	f := newFixture(t)
	f.engine.containers["stale"] = &Container{ID: "stale", Name: "openrmm-server-1" + previousSuffix, ImageID: oldImage, Project: "openrmm", Service: "server"}
	r := f.release(11, newImage)
	// containerd image store: the engine reports the manifest digest.
	digest := "sha256:" + strings.Repeat("4", 64)
	r.Manifest.Digest = digest
	r = Sign(f.priv, r.Manifest)
	f.engine.images = map[string]string{oldImage: oldImage, "ghcr.io/example/openrmm-server@" + digest: digest}
	f.engine.healthy[digest] = true
	if s := f.run(r); s.Phase != PhaseSucceeded {
		t.Fatal(s)
	}
	if _, ok := f.engine.containers["stale"]; ok {
		t.Fatal("leftover previous version kept")
	}
	// A running container in the way stops the update.
	g := newFixture(t)
	g.engine.containers["busy"] = &Container{ID: "busy", Name: "openrmm-server-1" + previousSuffix, ImageID: oldImage, Running: true, Project: "openrmm", Service: "server"}
	if s := g.run(g.release(11, newImage)); s.Phase != PhaseFailed || !strings.Contains(s.Detail, "in the way") {
		t.Fatal(s)
	}
}

func TestUpdaterStatus(t *testing.T) {
	f := newFixture(t)
	os.WriteFile(filepath.Join(f.u.Dir, RequestFile), []byte(`{"id":"0123456789abcdef0123456789abcdef","release":{}}`), 0600)
	f.u.Once(context.Background())
	if s, _ := ReadStatus(f.u.Dir); s.Phase != PhaseFailed || s.ID != "0123456789abcdef0123456789abcdef" {
		t.Fatal("malformed request not answered with its id", s)
	}
	f.u.status("0123456789abcdef0123456789abcdef", PhasePulling, "1.1.0", 11, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.u.Run(ctx)
	s, _ := ReadStatus(f.u.Dir)
	if s.Phase != PhaseFailed || !strings.Contains(s.Detail, "nothing was changed") || !s.Present(f.now) {
		t.Fatal(s)
	}
	if s.Present(f.now.Add(10 * time.Minute)) {
		t.Fatal("stale updater counted as present")
	}
}

func TestStripDefaults(t *testing.T) {
	config := map[string]json.RawMessage{
		"Env":         json.RawMessage(`["PATH=/bin","OLD_DEFAULT=1","OPENRMM_SERVER_LISTEN=0.0.0.0:8443"]`),
		"Labels":      json.RawMessage(`{"org.opencontainers.image.version":"1.0","com.docker.compose.project":"openrmm"}`),
		"StopSignal":  json.RawMessage(`"SIGTERM"`),
		"Healthcheck": json.RawMessage(`{"Test":["CMD","/openrmm-server","-health"]}`),
	}
	image := map[string]json.RawMessage{
		"Env":        json.RawMessage(`["PATH=/bin","OLD_DEFAULT=1"]`),
		"Labels":     json.RawMessage(`{"org.opencontainers.image.version":"1.0"}`),
		"StopSignal": json.RawMessage(`"SIGTERM"`),
	}
	stripDefaults(config, image)
	b, _ := json.Marshal(config)
	got := string(b)
	if strings.Contains(got, "OLD_DEFAULT") || strings.Contains(got, "image.version") || strings.Contains(got, "StopSignal") || !strings.Contains(got, "OPENRMM_SERVER_LISTEN") || !strings.Contains(got, "compose.project") || !strings.Contains(got, "-health") {
		t.Fatal(got)
	}
}
