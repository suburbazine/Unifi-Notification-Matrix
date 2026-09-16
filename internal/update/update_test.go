package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The ordering rule that matters is the prerelease one: 0.0.1-rc3 is OLDER
// than 0.0.1. Get it backwards and every machine on the final release is
// offered a downgrade to the release candidate it came from, for ever.
func TestPrereleasesSortBelowTheReleaseTheyPrecede(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"0.0.1", "0.0.1-rc3", 1},
		{"0.0.1-rc3", "0.0.1", -1},
		{"0.0.1-rc3", "0.0.1-rc2", 1},
		{"0.0.2", "0.0.1", 1},
		{"0.1.0", "0.0.9", 1},
		{"1.0.0", "0.9.9", 1},
		{"0.0.1", "0.0.1", 0},
		{"v0.0.2", "0.0.1", 1}, // a leading v must not change the answer
		{"0.1", "0.1.0", 0},    // missing components are zero
		{"0.0.1", "dev", 1},    // a developer build is older than anything
	} {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := Compare(tc.b, tc.a); got != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (not antisymmetric)", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestTheChecksumManifestIsParsedInBothSpellings(t *testing.T) {
	manifest := "aaaa  notifymatrix-linux-amd64\nbbbb *notifymatrix-windows-amd64.exe\ngarbage\n"
	for name, want := range map[string]string{
		"notifymatrix-linux-amd64":       "aaaa",
		"notifymatrix-windows-amd64.exe": "bbbb",
	} {
		got, err := sumFor(manifest, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := sumFor(manifest, "notifymatrix-linux-arm64"); err == nil {
		t.Error("a file missing from the manifest was given a checksum anyway")
	}
}

// A release with no SHA256SUMS cannot be checked. Installing it regardless is
// the difference between an updater and an arbitrary-code-execution endpoint.
func TestADownloadWithNoManifestIsRefusedBeforeAnythingIsFetched(t *testing.T) {
	c := &Client{}
	_, err := c.Download(context.Background(),
		&Release{Tag: "v9.9.9", AssetName: "x", AssetURL: "http://example.invalid/x"},
		filepath.Join(t.TempDir(), "notifymatrix"))
	if err == nil {
		t.Fatal("a release with no checksum manifest was accepted")
	}
	if !strings.Contains(err.Error(), SumsName) {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

type fakeRelease struct {
	asset []byte
	sums  string
	srv   *httptest.Server
}

func newFakeRelease(t *testing.T, tag string, asset []byte, corruptSums bool) *fakeRelease {
	t.Helper()
	name := AssetFor(runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(asset)
	hexsum := hex.EncodeToString(sum[:])
	if corruptSums {
		hexsum = strings.Repeat("0", 64)
	}
	f := &fakeRelease{asset: asset, sums: hexsum + "  " + name + "\n"}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q,"draft":false,"prerelease":false,
			"html_url":"https://example.test/r","assets":[
			{"name":%q,"browser_download_url":"https://example.test/%s"},
			{"name":%q,"browser_download_url":"https://example.test/%s"}]}`,
			tag, name, name, SumsName, SumsName)
	})
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(f.asset) })
	mux.HandleFunc("/"+SumsName, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, f.sums)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRelease) client() *Client {
	return &Client{BaseURL: f.srv.URL, DownloadBase: f.srv.URL}
}

func TestCheckReportsOnlySomethingNewer(t *testing.T) {
	f := newFakeRelease(t, "v0.0.2", []byte("binary"), false)
	c := f.client()

	rel, err := c.Check(context.Background(), "0.0.1")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rel == nil || rel.Version != "0.0.2" {
		t.Fatalf("got %+v, want 0.0.2", rel)
	}

	// Already current, and already ahead, must both be "nothing to do" rather
	// than an error -- and, crucially, an error must never be reported as
	// "up to date", which is how a machine sits on a vulnerable build.
	for _, current := range []string{"0.0.2", "0.0.3"} {
		rel, err := c.Check(context.Background(), current)
		if err != nil {
			t.Fatalf("Check at %s: %v", current, err)
		}
		if rel != nil {
			t.Errorf("at %s it offered %s", current, rel.Version)
		}
	}
}

func TestAFailedCheckIsAnErrorAndNotSilenceThatLooksCurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL}
	rel, err := c.Check(context.Background(), "0.0.1")
	if err == nil {
		t.Fatal("a failing feed reported success")
	}
	if rel != nil {
		t.Fatal("a failing feed produced a release")
	}
}

// The checksum gate, end to end over HTTP.
func TestADownloadThatDoesNotMatchTheManifestIsDiscarded(t *testing.T) {
	f := newFakeRelease(t, "v0.0.2", []byte("the real binary"), true /* wrong sums */)
	dir := t.TempDir()
	target := filepath.Join(dir, AssetFor(runtime.GOOS, runtime.GOARCH))
	if err := os.WriteFile(target, []byte("installed"), 0o755); err != nil {
		t.Fatal(err)
	}

	rel, err := f.client().Check(context.Background(), "0.0.1")
	if err != nil || rel == nil {
		t.Fatalf("Check: %v %+v", err, rel)
	}
	path, err := f.client().Download(context.Background(), rel, target)
	if err == nil {
		t.Fatalf("a mismatched download was accepted at %s", path)
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("the refusal does not name the reason: %v", err)
	}

	// And it left nothing behind. A half-verified update sitting on disk is a
	// thing somebody eventually runs.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".notifymatrix-update-") {
			t.Errorf("a rejected download was left on disk: %s", e.Name())
		}
	}
	if got, _ := os.ReadFile(target); string(got) != "installed" {
		t.Errorf("the installed binary was touched: %q", got)
	}
}
