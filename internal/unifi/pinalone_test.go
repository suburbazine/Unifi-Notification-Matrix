package unifi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A UniFi console serves a self-signed certificate signed by nothing. This
// generates a fresh one per call, which httptest does NOT: its built-in
// server reuses one canned certificate for every instance in a binary, so
// "connect to a different server" is not "presented a different certificate"
// and a pin test built on it passes without a pin.
func selfSigned(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "unifi-console"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	sum := sha256.Sum256(der)
	return srv, hex.EncodeToString(sum[:])
}

func get(t *testing.T, pin TLS, url string) error {
	t.Helper()
	c, err := pin.HTTPClient(0)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

// THE CONFIGURATION THE INTERFACE RECOMMENDS, which could not connect.
//
// "Leave the certificate check on and paste the fingerprint" is the advice on
// the Consoles screen, and against a self-signed console it fails in the chain
// verifier before the pin is ever consulted -- so an operator following it
// sees a broken console and switches the check OFF to recover, which reads
// like being told to weaken something.
//
// A pin is not a weaker check than a chain; it is an exact identity instead of
// a delegated one. When one is set it REPLACES chain verification rather than
// standing behind it.
func TestAPinnedConsoleConnectsWithTheCertificateCheckOn(t *testing.T) {
	srv, fp := selfSigned(t)
	if err := get(t, TLS{Fingerprint: fp}, srv.URL); err != nil {
		t.Errorf("a pinned self-signed console refused to connect: %v", err)
	}
}

// And the pin is still doing its job in that configuration -- otherwise the
// fix above would just be "skip verification", which is the thing it must not
// become.
func TestAPinnedConsolePresentingAnotherCertificateIsRefused(t *testing.T) {
	_, fp := selfSigned(t)
	other, _ := selfSigned(t)

	err := get(t, TLS{Fingerprint: fp}, other.URL)
	if err == nil {
		t.Fatal("a console presenting a different certificate was accepted")
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Errorf("refused with %v, want a pin mismatch", err)
	}
}

// The same, with the check explicitly off: the pin is what is deciding, so
// the flag changes nothing when one is set.
func TestTheCheckboxDoesNotChangeAPinnedConsole(t *testing.T) {
	srv, fp := selfSigned(t)
	if err := get(t, TLS{Fingerprint: fp, InsecureSkipVerify: true}, srv.URL); err != nil {
		t.Errorf("pinned with the check off refused to connect: %v", err)
	}
	other, _ := selfSigned(t)
	if err := get(t, TLS{Fingerprint: fp, InsecureSkipVerify: true}, other.URL); !errors.Is(err, ErrPinMismatch) {
		t.Errorf("pinned with the check off accepted another certificate: %v", err)
	}
}

// WITHOUT a pin, nothing changes: ordinary verification still refuses a
// self-signed certificate, and skipping it still accepts anything. The fix
// must not leak into the unpinned case, where the checkbox is the only
// control there is.
func TestAnUnpinnedConsoleIsUnaffected(t *testing.T) {
	srv, _ := selfSigned(t)

	if err := get(t, TLS{}, srv.URL); err == nil {
		t.Error("an unpinned self-signed console was accepted with the check on")
	}
	if err := get(t, TLS{InsecureSkipVerify: true}, srv.URL); err != nil {
		t.Errorf("an unpinned console with the check off refused: %v", err)
	}
}
