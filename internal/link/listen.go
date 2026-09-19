package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Serve runs the Link listener over TLS until ctx is cancelled.
//
// A LISTENER OF ITS OWN, not a path on the existing one, for the reason the
// acknowledgement listener already established: a port forward cannot scope by
// path. An operator forwarding the main listener to let a peer reach this
// would publish the status page and the settings sign-in with it. This port
// serves /link/ and answers everything else with a 404, so forwarding it
// exposes exactly one thing.
//
// The certificate is this product's own, self-signed, and pinned by the peer
// at pairing. There is no verification of the client at the TLS layer: every
// request carries its own signature, and a second identity here would be
// another key to pair, rotate and lose.
// MaxHeaderBytes caps the request head on the link port.
//
// Generous for what a peer actually sends -- an id, a timestamp, a nonce and a
// base64 signature come to a few hundred bytes -- and small enough that an
// unauthenticated caller cannot decide how much memory a request costs.
const MaxHeaderBytes = 8 << 10

func Serve(ctx context.Context, ln net.Listener, h http.Handler, cfg *tls.Config) error {
	srv := &http.Server{
		Handler: onlyLink(h),
		// Bounded, because this port is reachable by whatever the operator
		// forwarded. A peer sends a small JSON body and reads a small reply;
		// anything that wants to hold a connection open longer than this is
		// not a peer.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// A peer sends four short headers: the link id, a timestamp, a nonce
		// and a signature. Go's default allows a MEGABYTE of them per request,
		// and this port is reachable by whatever the operator forwarded -- so
		// without this, an unauthenticated caller chooses how much memory each
		// request costs, and the header values are retained afterwards in the
		// receipt ring.
		MaxHeaderBytes: MaxHeaderBytes,
		TLSConfig:      cfg,
	}

	done := make(chan error, 1)
	go func() {
		err := srv.ServeTLS(ln, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	}
}

// onlyLink answers everything outside the link prefix with a 404.
//
// The scoping is enforced HERE rather than trusted to the mux, so that adding
// a handler to this server later cannot quietly widen what a forwarded port
// exposes. The whole value of a separate port is that exactly one thing is on
// it.
func onlyLink(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, PathPrefix) {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// PinnedClientConfig is the TLS configuration a peer uses to reach this
// product: no name verification, no certificate authorities, one pinned
// fingerprint.
//
// Provided here so the two sides cannot drift, and so this product can test
// its own listener the way a peer will actually reach it.
//
// InsecureSkipVerify is set because there is nothing for the standard chain to
// verify against -- the certificate is self-signed and reached by whatever
// address the operator forwarded. Verification is not skipped; it is replaced
// by an exact identity, checked on every handshake, which refuses rather than
// warns. The same reasoning as the console pin, and the same shape of code.
func PinnedClientConfig(fingerprint string) *tls.Config {
	want := NormaliseFingerprint(fingerprint)
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // replaced by the pin below
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("link: the server presented no certificate")
			}
			got := fingerprintDER(raw[0])
			if got != want {
				return fmt.Errorf("%w: expected %s, got %s", ErrFingerprint, want, got)
			}
			return nil
		},
	}
}
