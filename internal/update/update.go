// Package update checks for a newer release and, when asked, replaces this
// binary with it.
//
// An updater is a remote-code-execution channel pointed at the machine that
// watches somebody's cameras and doors. It is the last place to accept "it
// came over HTTPS so it is probably fine", so nothing here trusts the
// download:
//
//   - The asset's SHA-256 must match the entry in SHA256SUMS. Both come from
//     the release, so on its own this proves only that the pair is
//     self-consistent -- it catches corruption and a truncated download, not
//     an attacker who can serve both files.
//
//   - On Windows, the replacement must carry a VALID Authenticode signature,
//     and its signer must be the same publisher that signed the binary
//     currently running. That is the load-bearing check: it chains to a real
//     certificate authority, and it pins the new file to whoever signed the
//     one the operator already chose to trust. Nothing is hardcoded, so it
//     keeps working when the certificate is renewed and stops working the
//     moment the publisher changes.
//
//   - Anything that fails leaves the installed binary untouched. There is no
//     "install it anyway".
//
// On platforms with no Authenticode the publisher check cannot be made, and
// this package says so rather than implying a guarantee it is not providing.
// See CanVerifyPublisher.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the only place a release is ever fetched from.
//
// A constant, not a setting. An updater whose source can be pointed elsewhere
// by editing a config file is a persistence mechanism: anybody who can write
// that file could aim the next update at their own build, and the operator
// would see a perfectly normal "update available".
const Repo = "suburbazine/Unifi-Notification-Matrix"

const (
	// SumsName is the checksum manifest published with every release.
	SumsName = "SHA256SUMS"

	// maxAsset bounds a download. The binaries are ~16MB; this is room for
	// growth and still refuses to fill a disk on a machine whose job is to be
	// running when something happens.
	maxAsset = 128 << 20

	// maxSums bounds the manifest, which is a few hundred bytes.
	maxSums = 1 << 20
)

// ErrNoRelease means the feed had nothing usable, rather than nothing newer.
var ErrNoRelease = errors.New("update: no published release was found")

// Release is one candidate upgrade.
type Release struct {
	// Version is the tag without its leading v, matching what the binary
	// reports for itself.
	Version string `json:"version"`
	Tag     string `json:"tag"`
	URL     string `json:"url"`

	// AssetName is the file for THIS platform, and AssetURL is where it lives.
	// Empty when the release published nothing for this platform, which is a
	// real case worth reporting rather than crashing on.
	AssetName string `json:"asset_name"`
	AssetURL  string `json:"asset_url"`
	SumsURL   string `json:"sums_url"`

	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
}

// AssetFor is the release asset this build would replace itself with.
func AssetFor(goos, goarch string) string {
	name := "notifymatrix-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// Client fetches releases. The zero value is usable.
type Client struct {
	// HTTP is the client used for every request. nil means a sensible default.
	HTTP *http.Client

	// BaseURL overrides the GitHub API root, for tests. Never set in
	// production: see the note on Repo.
	BaseURL string

	// DownloadBase overrides where assets are fetched from, for tests.
	DownloadBase string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return "https://api.github.com"
}

// Check reports the newest published release when it is newer than current.
//
// Returns (nil, nil) when already up to date, which is a different answer from
// an error and must stay that way: a failed check reported as "up to date" is
// how a machine sits on a known-vulnerable build believing it is current.
func (c *Client) Check(ctx context.Context, current string) (*Release, error) {
	url := c.base() + "/repos/" + Repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: asking %s for releases: %w", Repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoRelease
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: %s answered %s", Repo, resp.Status)
	}

	var raw struct {
		TagName     string    `json:"tag_name"`
		HTMLURL     string    `json:"html_url"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSums)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("update: could not read the release feed: %w", err)
	}
	if raw.Draft || raw.TagName == "" {
		return nil, ErrNoRelease
	}

	rel := &Release{
		Version:     strings.TrimPrefix(raw.TagName, "v"),
		Tag:         raw.TagName,
		URL:         raw.HTMLURL,
		PublishedAt: raw.PublishedAt,
		Prerelease:  raw.Prerelease,
	}
	want := AssetFor(runtime.GOOS, runtime.GOARCH)
	for _, a := range raw.Assets {
		switch a.Name {
		case want:
			rel.AssetName, rel.AssetURL = a.Name, a.BrowserDownloadURL
		case SumsName:
			rel.SumsURL = a.BrowserDownloadURL
		}
	}

	if Compare(rel.Version, current) <= 0 {
		return nil, nil // already current
	}
	return rel, nil
}

// Compare orders two versions: -1 if a is older, 0 if equal, 1 if a is newer.
//
// Enough semver to order this project's own tags, and deliberately no more. A
// prerelease sorts BELOW the release it precedes -- 0.0.1-rc3 is older than
// 0.0.1 -- which is the rule that stops an rc looking like an upgrade from the
// final build it led to.
func Compare(a, b string) int {
	an, ap := splitVersion(a)
	bn, bp := splitVersion(b)

	for i := 0; i < len(an) || i < len(bn); i++ {
		x, y := at(an, i), at(bn, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case ap == "" && bp == "":
		return 0
	case ap == "": // a is the real release, b is a prerelease of it
		return 1
	case bp == "":
		return -1
	}
	return strings.Compare(ap, bp)
}

func at(v []int, i int) int {
	if i < len(v) {
		return v[i]
	}
	return 0
}

// splitVersion separates 1.2.3 from -rc4.
func splitVersion(v string) ([]int, string) {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	pre := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		pre, v = v[i+1:], v[:i]
	}
	var nums []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			// "dev", or anything else that is not a version. Treated as the
			// oldest possible thing rather than refused, so a developer build
			// is offered the update instead of being told its own version is
			// unparseable.
			return nil, "dev"
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// Download fetches the release asset and verifies it, writing it beside the
// target executable.
//
// Returns the path of the verified file. Anything that fails deletes what it
// downloaded and returns an error: a partially verified update left on disk is
// a thing somebody eventually runs.
func (c *Client) Download(ctx context.Context, rel *Release, targetExe string) (string, error) {
	if rel == nil || rel.AssetURL == "" {
		return "", fmt.Errorf("update: release %s publishes no %s",
			rel.Tag, AssetFor(runtime.GOOS, runtime.GOARCH))
	}
	if rel.SumsURL == "" {
		return "", fmt.Errorf("update: release %s publishes no %s, so the download "+
			"cannot be checked and will not be installed", rel.Tag, SumsName)
	}

	sums, err := c.fetch(ctx, rel.SumsURL, maxSums)
	if err != nil {
		return "", fmt.Errorf("update: fetching %s: %w", SumsName, err)
	}
	want, err := sumFor(string(sums), rel.AssetName)
	if err != nil {
		return "", err
	}

	// Downloaded next to the target, not to a temp directory: the final step
	// is a rename over the running binary, and a rename across filesystems is
	// a copy that can fail halfway.
	dir := filepath.Dir(targetExe)
	tmp, err := os.CreateTemp(dir, ".notifymatrix-update-*")
	if err != nil {
		return "", fmt.Errorf("update: cannot write to %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	var body io.ReadCloser
	if body, err = c.open(ctx, rel.AssetURL); err != nil {
		return "", fmt.Errorf("update: downloading %s: %w", rel.AssetName, err)
	}
	defer body.Close()

	sum := sha256.New()
	if _, err = io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(body, maxAsset)); err != nil {
		return "", fmt.Errorf("update: downloading %s: %w", rel.AssetName, err)
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}

	if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, want) {
		err = fmt.Errorf("update: %s does not match its published checksum "+
			"(got %s, expected %s) -- it was discarded and nothing was installed",
			rel.AssetName, got, want)
		return "", err
	}

	// The check that actually pins WHO built it. Before this, every guarantee
	// above comes from two files served by the same host: an attacker who can
	// serve one can serve the other.
	if err = VerifyPublisher(tmpName, targetExe); err != nil {
		return "", err
	}

	if err = os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}
	return tmpName, nil
}

func (c *Client) open(ctx context.Context, url string) (io.ReadCloser, error) {
	if c.DownloadBase != "" {
		url = strings.TrimSuffix(c.DownloadBase, "/") + "/" + filepath.Base(url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return resp.Body, nil
}

func (c *Client) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	body, err := c.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(io.LimitReader(body, limit))
}

// sumFor pulls one file's hash out of a SHA256SUMS manifest.
func sumFor(manifest, name string) (string, error) {
	for _, line := range strings.Split(manifest, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		// `sha256sum` writes "hash  name" and "hash  *name" for binary mode.
		if strings.TrimPrefix(fields[1], "*") == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("update: %s does not list %s, so the download cannot "+
		"be checked and will not be installed", SumsName, name)
}
