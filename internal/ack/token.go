// Package ack lets a human stop an alert from the notification itself.
//
// The constraint that shapes everything here: the person receiving a 3am push
// is not going to VPN in and sign into a web UI. So an acknowledgement has to
// be reachable as a tap on an unauthenticated URL carrying its own authority.
//
// That means the URL IS the credential, and the rest of this package is about
// the consequences of that.
package ack

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// SecretBytes is the length of a per-installation ack key.
const SecretBytes = 32

// tokenBytes is how much of the HMAC ends up in the URL.
//
// 16 bytes is 128 bits, which is not brute-forceable across a network at any
// rate a link this long could be tried. Longer would make a URL that wraps in
// a push notification and looks like something is wrong with it, which costs
// real taps at 3am.
const tokenBytes = 16

var (
	// ErrBadToken covers every rejection: wrong token, unknown incident,
	// malformed path.
	//
	// ONE error on purpose. Distinguishing "no such incident" from "wrong
	// token" would let anyone with the endpoint enumerate which incident ids
	// exist, and incident ids are the only thing standing between a stranger
	// and silencing an alarm.
	ErrBadToken = errors.New("that acknowledgement link is not valid")

	// ErrNoSecret means the installation has no ack key configured.
	ErrNoSecret = errors.New("no acknowledgement key is configured")
)

// NewSecret generates a per-installation ack key.
func NewSecret() (secret.Secret, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ack: generating a key: %w", err)
	}
	return secret.Secret(base64.RawURLEncoding.EncodeToString(b)), nil
}

// Signer mints and verifies acknowledgement tokens.
type Signer struct {
	key []byte
}

// NewSigner builds a Signer from the installation's key.
func NewSigner(s secret.Secret) (*Signer, error) {
	if s.IsZero() {
		return nil, ErrNoSecret
	}
	// The key is used as raw bytes; whether it decodes as base64 does not
	// matter, only that it is the same bytes every time.
	return &Signer{key: []byte(s.Reveal())}, nil
}

// Mint returns the token for one incident.
//
// Bound to the incident id AND its open time. Binding to the id alone would
// let a token minted for a closed incident acknowledge a later one that
// happened to reuse the id; binding to the open time means a token names
// exactly one occurrence of one condition.
//
// There is deliberately NO EXPIRY. An alert that is still repeating at
// 6am must still be stoppable by the link sent at 3am, and an expired token
// would mean the operator's only remaining option is a web UI they are not
// going to open. An old link stays valid for an incident that is already
// closed, where acknowledging is a harmless no-op.
func (s *Signer) Mint(id string, openedAt time.Time) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(id))
	m.Write([]byte{0}) // separator: "ab"+"c" must not hash as "a"+"bc"
	fmt.Fprintf(m, "%d", openedAt.UTC().UnixNano())
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:tokenBytes])
}

// Verify checks a token against an incident.
func (s *Signer) Verify(inc *incident.Incident, token string) error {
	if inc == nil || token == "" {
		return ErrBadToken
	}
	want := s.Mint(inc.ID, inc.OpenedAt)
	// Constant time: a byte-by-byte comparison leaks how much of a guessed
	// token was right, which turns 128 bits into 16 one-byte guesses.
	if subtle.ConstantTimeCompare([]byte(want), []byte(token)) != 1 {
		return ErrBadToken
	}
	return nil
}

// URL builds the acknowledgement link for an incident.
func (s *Signer) URL(base, incidentID string, openedAt time.Time, via string) string {
	b := strings.TrimRight(base, "/")
	u := fmt.Sprintf("%s/ack/%s/%s", b, incidentID, s.Mint(incidentID, openedAt))
	if via != "" {
		// Advisory only, and recorded as such. Anyone holding the link can set
		// it to anything, so it says which channel the link was PRINTED in,
		// never which channel a human actually used. The audit record must not
		// claim more than that.
		u += "?via=" + via
	}
	return u
}
