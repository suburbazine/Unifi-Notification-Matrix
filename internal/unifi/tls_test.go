package unifi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tlsServer(t *testing.T) (*httptest.Server, string, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)

	cert := srv.Certificate()
	sum := sha256.Sum256(cert.Raw)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return srv, hex.EncodeToString(sum[:]), pool
}

func dialWith(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()
	d := &tls.Dialer{Config: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func TestTheRightPinConnects(t *testing.T) {
	srv, want, _ := tlsServer(t)

	cfg, err := TLS{Fingerprint: want, InsecureSkipVerify: true}.Config()
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(t, srv.Listener.Addr().String(), cfg); err != nil {
		t.Fatalf("the pinned certificate was refused: %v", err)
	}
}

// The verification callback runs after EVERY handshake regardless of
// InsecureSkipVerify -- which is exactly what makes a pin hold in the
// self-signed configuration it exists for. A pin installed anywhere that
// InsecureSkipVerify bypasses would be decoration on a UniFi console.
func TestThePinIsEnforcedEvenWithVerificationOtherwiseSkipped(t *testing.T) {
	srv, _, _ := tlsServer(t)

	cfg, err := TLS{
		Fingerprint:        strings.Repeat("ab", sha256.Size),
		InsecureSkipVerify: true,
	}.Config()
	if err != nil {
		t.Fatal(err)
	}

	err = dialWith(t, srv.Listener.Addr().String(), cfg)
	if err == nil {
		t.Fatal("a console presenting the wrong certificate was accepted; the pin does not run under InsecureSkipVerify")
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, which does not satisfy errors.Is(err, ErrPinMismatch)", err)
	}
}

// And it is still enforced when verification is NOT skipped: a certificate
// that chains correctly but is not the pinned one is still refused.
func TestThePinIsEnforcedOnTopOfOrdinaryVerificationToo(t *testing.T) {
	srv, _, pool := tlsServer(t)

	cfg, err := TLS{Fingerprint: strings.Repeat("cd", sha256.Size)}.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.RootCAs = pool

	err = dialWith(t, srv.Listener.Addr().String(), cfg)
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("a trusted-but-unpinned certificate produced %v, want ErrPinMismatch", err)
	}
}

// A pin REFUSES; it does not warn. Nothing gets through a mismatch.
func TestAMismatchRefusesTheRequestRatherThanWarning(t *testing.T) {
	srv, _, _ := tlsServer(t)

	client, err := TLS{
		Fingerprint:        strings.Repeat("01", sha256.Size),
		InsecureSkipVerify: true,
	}.HTTPClient(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(srv.URL)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("a request completed against a mismatched pin and returned %q", body)
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("the sentinel did not survive the http.Client's wrapping: %v", err)
	}
}

// Trust on first use is an operator action: this is the call a setup screen
// makes to SHOW a fingerprint to a human, and its result then becomes the pin.
func TestFetchCertFingerprintReportsWhatIsThenPinnable(t *testing.T) {
	srv, want, _ := tlsServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := FetchCertFingerprint(ctx, srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("FetchCertFingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}

	cfg, err := TLS{Fingerprint: got, InsecureSkipVerify: true}.Config()
	if err != nil {
		t.Fatal(err)
	}
	if err := dialWith(t, srv.Listener.Addr().String(), cfg); err != nil {
		t.Fatalf("the fingerprint this call reported was then refused as a pin: %v", err)
	}
}

// A client that learns a pin by itself on a failed connection has no
// protection on the one connection an attacker would ever target. The guard
// against that regression is mechanical rather than a reviewer's memory: no
// shipped code may call FetchCertFingerprint at all.
func TestNoShippedCodeLearnsAPinByItself(t *testing.T) {
	dirs := []string{".", filepath.Join("..", "source", "protect")}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if calleeName(call.Fun) == "FetchCertFingerprint" {
					t.Errorf("%s calls FetchCertFingerprint at %s; trust-on-first-use is an operator action and must never happen on a connection path",
						path, fset.Position(call.Pos()))
				}
				return true
			})
		}
	}
}

func calleeName(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// The fingerprint is pasted by a human out of whatever showed it to them, so
// the shapes those tools print are all accepted -- and anything that is not a
// SHA-256 is refused when the config is built, not when the console is next
// unreachable at 3am.
func TestFingerprintParsingIsToleratedOrRefusedEarly(t *testing.T) {
	want := strings.Repeat("ab", sha256.Size)

	ok := []string{
		want,
		strings.ToUpper(want),
		colonise(want),
		" " + colonise(strings.ToUpper(want)) + "\n",
		"sha256:" + want,
	}
	for _, in := range ok {
		got, err := normaliseFingerprint(in)
		if err != nil {
			t.Errorf("normaliseFingerprint(%q) = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normaliseFingerprint(%q) = %s, want %s", in, got, want)
		}
	}

	bad := []string{
		"not hex at all",
		strings.Repeat("ab", sha256.Size-1), // a SHA-1 length pin is not a SHA-256 one
		strings.Repeat("ab", sha256.Size+1),
		"zz" + want[2:],
	}
	for _, in := range bad {
		if _, err := (TLS{Fingerprint: in}).Config(); err == nil {
			t.Errorf("TLS{Fingerprint: %q}.Config() was accepted; a malformed pin must fail at configuration time", in)
		}
	}
}

func colonise(hexStr string) string {
	parts := make([]string, 0, len(hexStr)/2)
	for i := 0; i+2 <= len(hexStr); i += 2 {
		parts = append(parts, hexStr[i:i+2])
	}
	return strings.Join(parts, ":")
}

// No pin configured is not an error; it is ordinary verification, and it is
// the right answer for a console behind a real certificate.
func TestAnEmptyFingerprintInstallsNoCallback(t *testing.T) {
	cfg, err := TLS{}.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Fatal("a config with no pin installed a verification callback")
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("the default must be ordinary verification, not none")
	}
}

// The console is on the operator's own LAN. Sending API-key-bearing requests
// to whatever HTTPS_PROXY happens to be exported is a silent exfiltration
// path, and the proxy answering makes it invisible.
func TestTheTransportNeverFollowsAProxyFromTheEnvironment(t *testing.T) {
	tr, err := TLS{}.Transport()
	if err != nil {
		t.Fatal(err)
	}
	if tr.Proxy != nil {
		t.Fatal("the console transport carries a Proxy function; a LAN address must not be routed through an environment proxy")
	}
}
