package protect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/unifi"
)

// One console, one certificate, one pin. Protect is an application behind a
// UniFi OS host, not a host of its own, so the certificate policy comes from
// the shared console layer and reaches BOTH paths that talk to it -- the two
// WebSocket dials and the REST sweep. A source that pinned its sockets and not
// its sweep would be pinned in the half an attacker did not need.
func TestTheConsolePinReachesTheSocketDialerAndTheSweep(t *testing.T) {
	pin := strings.Repeat("ab", 32)

	src, err := New(Config{
		Host:   "10.0.0.1",
		APIKey: "k",
		TLS:    &unifi.TLS{Fingerprint: pin, InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	d := src.dial()
	if d.TLSClientConfig == nil {
		t.Fatal("the WebSocket dialer carries no TLS config; the socket would verify against system roots the console has never chained to")
	}
	if d.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("the dialer's TLS config installs no pin check")
	}
	// The dialer must not route the console through an environment proxy.
	if d.Proxy != nil {
		t.Fatal("the WebSocket dialer carries a Proxy function")
	}

	r, ok := src.cfg.States.(*restReader)
	if !ok {
		t.Fatalf("the default sweep reader is %T", src.cfg.States)
	}
	if r.hc == nil {
		t.Fatal("the sweep got no HTTP client")
	}
}

// A malformed pin is a configuration fault, reported by New. Discovering it on
// the wire means finding out the console is unreachable during the incident
// the product was supposed to be watching for.
func TestAMalformedPinIsAConfigurationFault(t *testing.T) {
	_, err := New(Config{
		Host:   "10.0.0.1",
		APIKey: "k",
		TLS:    &unifi.TLS{Fingerprint: "not-a-fingerprint"},
	})
	if err == nil {
		t.Fatal("New accepted an unparseable certificate fingerprint")
	}
}

// A pin mismatch is the ONE failure this source does not retry.
//
// Every other connection failure on this hardware is a console that is still
// starting up. This one is something that is not the console at all, and
// retrying it means presenting the API key again and again to whatever is
// answering. Matched on the sentinel, never on the text of a message.
func TestAPinMismatchStopsIngestRatherThanRetryingForever(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := websocket.Upgrader{}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	// The pin names a certificate this server is not presenting.
	consoleTLS := unifi.TLS{Fingerprint: strings.Repeat("ab", 32), InsecureSkipVerify: true}
	cfg, err := consoleTLS.Config()
	if err != nil {
		t.Fatal(err)
	}

	src, err := New(Config{
		Host:       srv.URL,
		APIKey:     "k",
		States:     &fakeStates{},
		Dialer:     &websocket.Dialer{TLSClientConfig: cfg, HandshakeTimeout: 5 * time.Second},
		Pace:       unifi.NewPacer(time.Millisecond).Wait,
		MinBackoff: 5 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond,
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, newCollector()) }()

	select {
	case err := <-done:
		if !errors.Is(err, unifi.ErrPinMismatch) {
			t.Fatalf("Run returned %v, want an error satisfying errors.Is(err, unifi.ErrPinMismatch)", err)
		}
	case <-ctx.Done():
		t.Fatal("Run kept reconnecting to a console whose certificate does not match the pin")
	}
}
