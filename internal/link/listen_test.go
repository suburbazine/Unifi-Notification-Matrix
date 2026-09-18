package link

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// liveLink stands the real listener up over TLS and returns a client that
// reaches it the way a peer does: pinned, with no name verification and no
// certificate authority in sight.
func liveLink(t *testing.T) (base string, fp string, h *harness, client *http.Client) {
	t.Helper()

	certPEM, keyPEM, err := MintCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp, err = Fingerprint(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := TLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	h = newHarness(t)
	h.rc.deps.Pairer = NewPairer(fp)
	h.rc.deps.Pairer.Now = func() time.Time { return now }
	h.rc.deps.OnPaired = func(_ context.Context, p Peer, key []byte) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.peer = p
		h.cred = Credential{LinkID: p.LinkID, Key: key}
		return nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, ln, h.rc, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("the listener did not shut down")
		}
	})

	client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: PinnedClientConfig(fp)},
		Timeout:   5 * time.Second,
	}
	return "https://" + ln.Addr().String(), fp, h, client
}

// THE WHOLE PATH, over a real connection: pair with a typed code, then send a
// signed event with the credential pairing minted.
func TestPairingThenSendingAnEventOverTLS(t *testing.T) {
	base, fp, h, client := liveLink(t)

	code, err := h.rc.deps.Pairer.Offer()
	if err != nil {
		t.Fatal(err)
	}

	pairBody, _ := json.Marshal(pairReq(FormatCode(code), fp))
	resp, err := client.Post(base+RoutePair, "application/json", bytes.NewReader(pairBody))
	if err != nil {
		t.Fatalf("pairing over TLS failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pairing answered %d", resp.StatusCode)
	}

	var paired PairResponse
	if err := json.NewDecoder(resp.Body).Decode(&paired); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(paired.Key)
	if err != nil {
		t.Fatal(err)
	}
	// The peer checks the server knew the code too, so it cannot be talked
	// into storing a credential by something that merely intercepted.
	if paired.Proof != PairProof(code, "server", paired.LinkID, fp, "pair-nonce") {
		t.Fatal("the server proof did not verify against the typed code")
	}

	// Now send a real event with the minted credential.
	body, _ := json.Marshal(sweep())
	stamp := strconv.FormatInt(now.Unix(), 10)
	req, _ := http.NewRequest(http.MethodPost, base+RouteEvents, bytes.NewReader(body))
	req.Header.Set(HeaderLinkID, paired.LinkID)
	req.Header.Set(HeaderTimestamp, stamp)
	req.Header.Set(HeaderNonce, "live-1")
	req.Header.Set("Authorization", Scheme+" "+
		Sign(key, Canonical(http.MethodPost, RouteEvents, paired.LinkID, stamp, "live-1", body)))

	ev, err := client.Do(req)
	if err != nil {
		t.Fatalf("sending an event failed: %v", err)
	}
	defer ev.Body.Close()
	if ev.StatusCode != http.StatusOK {
		t.Fatalf("a correctly signed event answered %d", ev.StatusCode)
	}
	if h.count() != 1 {
		t.Errorf("ingested %d events, want 1", h.count())
	}
}

// THE PIN IS THE IDENTITY. A client expecting a different fingerprint must
// refuse the connection outright -- this is what makes a man in the middle
// unable to complete a pairing even holding the code.
func TestAClientPinningTheWrongFingerprintRefusesToConnect(t *testing.T) {
	base, _, _, _ := liveLink(t)

	wrong := &http.Client{
		Transport: &http.Transport{TLSClientConfig: PinnedClientConfig(fpB)},
		Timeout:   5 * time.Second,
	}
	_, err := wrong.Post(base+RoutePair, "application/json", strings.NewReader("{}"))
	if err == nil {
		t.Fatal("a client pinning the wrong certificate connected anyway")
	}
	if !strings.Contains(err.Error(), "expected") && !errors.Is(err, ErrFingerprint) {
		t.Errorf("the refusal does not look like a pin failure: %v", err)
	}
}

// THE POINT OF A SEPARATE PORT. A forward aimed here must expose the link and
// nothing else -- not the status page, not the settings sign-in, not the
// acknowledgement routes.
func TestTheListenerServesNothingButLink(t *testing.T) {
	base, _, _, client := liveLink(t)

	for _, path := range []string{"/", "/api/status", "/ack/anything", "/hook/anything", "/settings"} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body := make([]byte, 256)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s answered %d, want 404", path, resp.StatusCode)
		}
		if strings.Contains(strings.ToLower(string(body[:n])), "notifymatrix") {
			t.Errorf("GET %s leaked something about the product: %q", path, body[:n])
		}
	}
}

// A certificate minted twice is two identities, so a peer that pinned the
// first must refuse the second. This is what makes "re-pair" the only way back
// after the certificate changes, rather than a silent relearn.
func TestEachMintedCertificateIsADistinctIdentity(t *testing.T) {
	a, _, err := MintCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := MintCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := Fingerprint(a)
	fb, _ := Fingerprint(b)
	if fa == fb {
		t.Fatal("two mints produced the same fingerprint")
	}
	if len(fa) != 64 {
		t.Errorf("fingerprint %q is not a SHA-256 hex digest", fa)
	}
}

func TestFingerprintsNormaliseTheWayHumansWriteThem(t *testing.T) {
	const want = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899"
	for _, v := range []string{
		want,
		strings.ToUpper(want),
		"AA:11:BB:22:CC:33:DD:44:EE:55:FF:66:00:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
	} {
		if got := NormaliseFingerprint(v); got != want {
			t.Errorf("NormaliseFingerprint(%q) = %q", v, got)
		}
	}
}

// The scoping is enforced by the listener, not merely inherited from the
// handler that happens to be mounted today.
//
// The receiver 404s unknown paths on its own, so a test that only asks the
// real handler cannot tell the two apart -- removing the listener's own check
// left the suite green. This mounts something that WOULD answer, which is the
// case the wrapper exists for: adding a handler to this server later must not
// quietly widen what a forwarded port exposes.
func TestTheListenerScopesEvenAWideOpenHandler(t *testing.T) {
	certPEM, keyPEM, err := MintCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := Fingerprint(certPEM)
	cfg, err := TLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// Answers everything, cheerfully, with something an operator would mind.
	wideOpen := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("the settings page and every camera name"))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, ln, wideOpen, cfg) }()
	t.Cleanup(func() { cancel(); <-served })

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: PinnedClientConfig(fp)},
		Timeout:   5 * time.Second,
	}
	base := "https://" + ln.Addr().String()

	for _, path := range []string{"/", "/api/status", "/settings", "/ack/x"} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		buf := make([]byte, 128)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s answered %d through the link listener, want 404", path, resp.StatusCode)
		}
		if strings.Contains(string(buf[:n]), "camera") {
			t.Errorf("GET %s served the wide-open handler's body", path)
		}
	}

	// ...and the link prefix still reaches whatever is mounted.
	resp, err := client.Get(base + RoutePing)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the link prefix answered %d; the wrapper is blocking everything", resp.StatusCode)
	}
}
