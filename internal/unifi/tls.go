package unifi

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrPinMismatch is returned when the console presents a certificate that is
// not the pinned one.
//
// A SENTINEL, matched with errors.Is and never by string comparison on a
// message. A pin mismatch is the one connection failure that is terminal --
// every other 4xx, 5xx and dropped socket on this hardware is a console that
// is still starting up -- so the caller has to be able to tell it apart
// reliably. A string match on an error text is a security control that breaks
// the next time somebody improves the wording.
var ErrPinMismatch = errors.New("unifi: certificate pin mismatch")

// ErrNoCertificate means the handshake produced no peer certificate to pin.
var ErrNoCertificate = errors.New("unifi: peer presented no certificate")

// TLS is the console's transport security, which is a property of the HOST.
//
// One console, one certificate, one pin. Protect, Access and Network are
// applications behind a single UniFi OS host and are served the same
// certificate by the same reverse proxy, so the pin is configured once per
// console rather than once per application. Two applications with two pins for
// one host is not redundancy; it is two chances to be wrong.
type TLS struct {
	// Fingerprint is the SHA-256 of the console's leaf certificate in its DER
	// form, as hex. Colons, whitespace and case are accepted, because this
	// value is pasted by a human from whatever showed it to them.
	//
	// Empty means no pin, and then verification is whatever InsecureSkipVerify
	// says: ordinary system roots, or nothing.
	Fingerprint string

	// InsecureSkipVerify disables chain and hostname verification.
	//
	// This is the normal configuration for a UniFi console, whose certificate
	// is self-signed against an IP address -- and it is only defensible
	// TOGETHER WITH a Fingerprint. Verification is not being skipped; it is
	// being replaced by something stronger for this case, namely an exact
	// identity rather than a delegated one.
	InsecureSkipVerify bool

	// ServerName overrides the name used for SNI and verification.
	ServerName string
}

// Config returns a *tls.Config that enforces the pin.
//
// The pin is installed as VerifyPeerCertificate, which crypto/tls calls after
// EVERY handshake regardless of InsecureSkipVerify. That is the whole reason
// the pin is expressed this way: the chain verifier is bypassed entirely by
// InsecureSkipVerify, and a pin that stops being checked in exactly the
// self-signed configuration it was written for is decoration.
//
// A pin REFUSES; it does not warn. There is no log-and-continue branch here
// and adding one would make the control advisory.
func (t TLS) Config() (*tls.Config, error) {
	want, err := normaliseFingerprint(t.Fingerprint)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.InsecureSkipVerify,
		ServerName:         t.ServerName,
	}
	if want == "" {
		return cfg, nil
	}

	// A PIN REPLACES THE CHAIN; IT DOES NOT STAND BEHIND IT.
	//
	// A UniFi console's certificate is signed by nothing, so with the chain
	// verifier switched on the handshake fails at "unknown authority" before
	// VerifyPeerCertificate is ever consulted -- and the pin, the stronger
	// control, never gets to decide. An operator who pinned a console and
	// left the certificate check on therefore could not connect at all, and
	// recovered the only way the screen offered: by turning the check off,
	// which reads like being told to weaken something in order to work.
	//
	// So when a pin is set, the chain verifier is stood down here. Nothing is
	// being skipped: an exact identity is being checked instead of a
	// delegated one, and the check below refuses on mismatch rather than
	// warning. The operator's flag is irrelevant once a pin exists, which is
	// what the interface now says.
	cfg.InsecureSkipVerify = true

	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoCertificate
		}
		// The leaf, and only the leaf. Pinning an intermediate would let the
		// pin survive the console being issued a different leaf, which is the
		// event it exists to notice.
		got := fingerprintOf(rawCerts[0])
		if got != want {
			// The presented fingerprint is named because an operator who
			// legitimately replaced the console certificate needs to see the
			// new value, and it is public to anyone who can reach the host
			// anyway. The SENTINEL is what callers branch on.
			return fmt.Errorf("%w: console presented %s, pinned %s", ErrPinMismatch, got, want)
		}
		return nil
	}
	return cfg, nil
}

// Transport returns an *http.Transport carrying this console's TLS settings.
//
// Deliberately NOT http.ProxyFromEnvironment. The console is on the operator's
// own LAN; routing a LAN address through whatever HTTPS_PROXY happens to be
// exported would send API-key-bearing requests somewhere nobody chose, and the
// failure is invisible because the proxy answers.
func (t TLS) Transport() (*http.Transport, error) {
	cfg, err := t.Config()
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       cfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}, nil
}

// HTTPClient is Transport with a request timeout attached.
func (t TLS) HTTPClient(timeout time.Duration) (*http.Client, error) {
	tr, err := t.Transport()
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// FetchCertFingerprint connects to a console and reports the SHA-256 of the
// leaf certificate it presents.
//
// This is trust-on-first-use, and it is an OPERATOR ACTION. It is exported so
// that a setup screen or a CLI verb can show an operator a fingerprint and ask
// them to confirm it. It must never be called from a connection path, and in
// particular never from the handling of a failed or mismatched connection: a
// client that silently learns a pin when the pin does not match has no
// protection on the one connection an attacker would ever target, which makes
// the automatic version strictly worse than no pin at all because it also
// reports success.
//
// A test in this package fails the build if this function is called from any
// non-test file.
func FetchCertFingerprint(ctx context.Context, host string) (string, error) {
	addr := dialAddress(host)
	if addr == "" {
		return "", errors.New("unifi: no console host to fetch a certificate from")
	}

	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		// Deliberate: this call is asking "what certificate is there", so it
		// has to complete against the self-signed certificate that is the
		// whole reason pinning exists. Its answer is shown to a human to
		// approve; nothing here is trusted on its own.
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("unifi: reading the certificate of %s: %w", addr, err)
	}
	defer conn.Close()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "", ErrNoCertificate
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", ErrNoCertificate
	}
	return fingerprintOf(certs[0].Raw), nil
}

// fingerprintOf is the canonical form: lowercase hex, no separators.
func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// normaliseFingerprint accepts the shapes a human will actually paste.
func normaliseFingerprint(raw string) (string, error) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, raw)
	if s == "" {
		return "", nil
	}
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "sha256")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		// Refused at configuration time rather than at connection time. A
		// malformed pin discovered on the wire is a console outage during the
		// incident it was supposed to be watching for.
		return "", fmt.Errorf("unifi: certificate fingerprint must be %d hex bytes of SHA-256, got %q", sha256.Size, raw)
	}
	return s, nil
}

// dialAddress turns whatever the operator typed into host:port.
func dialAddress(host string) string {
	h := ConsoleKey(host)
	if h == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h
	}
	return net.JoinHostPort(h, "443")
}
