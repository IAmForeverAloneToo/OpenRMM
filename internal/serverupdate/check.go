package serverupdate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
)

// Repository is the GitHub repository whose releases the server checks.
//
// A build whose repository is the placeholder makes no request.
const Repository = "IAmForeverAloneToo/OpenRMM"

const placeholder = "OWNER/REPO"

// Configured reports whether this build names its release repository.
func Configured() bool { return Repository != placeholder }

// AssetName is the signed release file attached to each GitHub release.
const AssetName = "openrmm-server-release.json"

// ErrNotConfigured means the build has no release repository yet.
var ErrNotConfigured = errors.New("this build has no release repository configured")

// apiBase is replaced in tests.
var apiBase = "https://api.github.com"

// Checker fetches the latest signed release. The request carries no device
// or user data: only the repository path and a generic user agent.
type Checker struct {
	Client *http.Client
	Repo   string
}

func (c Checker) repo() string {
	if c.Repo != "" {
		return c.Repo
	}
	return Repository
}

// allowedHost limits where release data may come from, including redirects
// (GitHub serves release assets from its content hosts).
func allowedHost(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	base, _ := url.Parse(apiBase)
	return h == base.Hostname() || h == "github.com" || strings.HasSuffix(h, ".githubusercontent.com")
}

func (c Checker) client() *http.Client {
	base := c.Client
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	cl := *base
	cl.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !allowedHost(r.URL) {
			return errors.New("release redirect not allowed")
		}
		return nil
	}
	return &cl
}

func (c Checker) get(ctx context.Context, cl *http.Client, raw string, accept string, limit int64) ([]byte, error) {
	u, e := url.Parse(raw)
	if e != nil || !allowedHost(u) {
		return nil, errors.New("release address not allowed")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "OpenRMM-server-update-check")
	res, e := cl.Do(req)
	if e != nil {
		return nil, errors.New("the release service could not be reached")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, errors.New("no published release was found")
	}
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("the release service answered with an error")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("the release data is too large")
	}
	return b, nil
}

// Latest returns the signed release of the repository's latest GitHub
// release. The caller verifies it.
func (c Checker) Latest(ctx context.Context) (Release, error) {
	repo := c.repo()
	if repo == placeholder || !validRepo(repo) {
		return Release{}, ErrNotConfigured
	}
	cl := c.client()
	b, e := c.get(ctx, cl, apiBase+"/repos/"+repo+"/releases/latest", "application/vnd.github+json", 1<<20)
	if e != nil {
		return Release{}, e
	}
	var latest struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if json.Unmarshal(b, &latest) != nil {
		return Release{}, errors.New("the release service answered with unreadable data")
	}
	for _, a := range latest.Assets {
		if a.Name != AssetName {
			continue
		}
		if a.Size <= 0 || a.Size > 64*1024 {
			return Release{}, errors.New("the signed release file has an unexpected size")
		}
		raw, e := c.get(ctx, cl, a.URL, "application/octet-stream", 64*1024)
		if e != nil {
			return Release{}, e
		}
		var r Release
		if agentupdate.Decode(raw, &r) != nil {
			return Release{}, errors.New("the signed release file is malformed")
		}
		return r, nil
	}
	return Release{}, errors.New("the latest release has no signed server release file")
}

func validRepo(s string) bool {
	owner, name, ok := strings.Cut(s, "/")
	if !ok || len(owner) == 0 || len(owner) > 39 || len(name) == 0 || len(name) > 100 {
		return false
	}
	for _, r := range owner + name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return name != "." && name != ".."
}
