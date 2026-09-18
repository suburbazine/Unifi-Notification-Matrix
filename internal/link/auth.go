package link

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The wire names for request authentication.
const (
	Scheme = "Xt-Link-HMAC-SHA256"

	HeaderLinkID    = "X-Link-Id"
	HeaderTimestamp = "X-Link-Ts"
	HeaderNonce     = "X-Link-Nonce"
)

// canonicalTag is the FIRST line of everything signed, and it is a security
// control rather than a version label.
//
// Xtremission has more than one signed channel: this one, and Console Cast
// between Door Matrix and Sentry, which reuses the same construction on
// purpose rather than inventing a second. Tagging the canonical string means
// that if a key is ever reused across the two by mistake -- the ordinary human
// error of pasting the wrong secret -- a signature minted for a Link request
// still cannot be replayed as a Cast request.
//
// It lives INSIDE the signed string deliberately. A separator carried in a
// header beside the signature is a separator an attacker can edit, which
// separates nothing.
const canonicalTag = "xtremission-link/v1"

// Window is how far a request's timestamp may be from ours in either
// direction. Generous enough for ordinary clock drift, short enough that a
// captured request stops being useful quickly.
const Window = 300 * time.Second

// MaxNonces bounds the per-link replay cache.
//
// A bounded table that occasionally refuses beats a memory bomb: the same
// reasoning as the observed-entity cap. A peer sending under one request a
// minute cannot reach this; something that does is a bug or an attacker, and
// either way refusing is the right answer.
const MaxNonces = 8192

var (
	ErrNoSignature  = errors.New("link: no Xt-Link-HMAC-SHA256 authorization")
	ErrUnknownLink  = errors.New("link: no such link id")
	ErrBadSignature = errors.New("link: signature does not match")
	ErrSkew         = errors.New("link: timestamp outside the accepted window")
	ErrReplay       = errors.New("link: nonce has been used before")
	ErrNonceFull    = errors.New("link: replay cache is full")
	ErrMalformed    = errors.New("link: malformed authentication headers")
)

// Canonical is the exact string both ends sign.
//
// Every field that changes the meaning of the request is in it: the method and
// path so a signed read cannot be replayed as a write or aimed at another
// route, the link id so one peer's signature is not another's, the timestamp
// and nonce so a captured request expires and cannot be repeated, and a hash
// of the body so the payload cannot be edited under a valid signature.
func Canonical(method, path, linkID, ts, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		canonicalTag,
		strings.ToUpper(method),
		path,
		linkID,
		ts,
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n")
}

// Sign returns the base64 signature for a canonical string.
func Sign(key []byte, canonical string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Credential is one paired peer's shared secret.
type Credential struct {
	LinkID string
	Key    []byte
}

// Request is the parts of an inbound HTTP request that authentication uses.
// Taken as plain fields rather than an http.Request so the rules can be tested
// without a server standing up.
type Request struct {
	Method        string
	Path          string
	LinkID        string
	Timestamp     string
	Nonce         string
	Authorization string
	Body          []byte
}

// Verifier authenticates inbound Link requests.
type Verifier struct {
	// Now is the clock. Tests replace it; production leaves it nil.
	Now func() time.Time

	mu     sync.Mutex
	nonces map[string]map[string]time.Time
}

// NewVerifier returns a verifier with an empty replay cache.
func NewVerifier() *Verifier {
	return &Verifier{nonces: map[string]map[string]time.Time{}}
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify authenticates a request against the paired credentials.
//
// EVERY failure is the same failure to the caller, which answers a bare 404 --
// the reasoning internal/inbound already settled: an endpoint that distinguishes
// "wrong key" from "no such peer" tells an attacker which half to keep working
// on, and one that says "unauthorised" confirms something is listening here.
// The specific error is returned so it can be written to that link's receipt,
// where a signed-in operator can read it.
func (v *Verifier) Verify(creds []Credential, req Request) (Credential, error) {
	sig, ok := parseAuthorization(req.Authorization)
	if !ok {
		return Credential{}, ErrNoSignature
	}
	if req.LinkID == "" || req.Nonce == "" || req.Timestamp == "" {
		return Credential{}, ErrMalformed
	}

	secs, err := strconv.ParseInt(strings.TrimSpace(req.Timestamp), 10, 64)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: timestamp %q", ErrMalformed, req.Timestamp)
	}
	now := v.now()
	if d := now.Sub(time.Unix(secs, 0)); d > Window || d < -Window {
		return Credential{}, fmt.Errorf("%w: %s off", ErrSkew, d.Round(time.Second))
	}

	// Scanned with no early break, and compared in constant time, so neither
	// the number of configured links nor which one matched is readable from
	// how long this took.
	var found Credential
	var matched int
	for _, c := range creds {
		idOK := subtle.ConstantTimeCompare([]byte(c.LinkID), []byte(req.LinkID))
		want := Sign(c.Key, Canonical(req.Method, req.Path, c.LinkID, req.Timestamp, req.Nonce, req.Body))
		sigOK := subtle.ConstantTimeCompare([]byte(want), []byte(sig))
		if idOK&sigOK == 1 {
			found = c
			matched++
		}
	}
	if matched == 0 {
		// Deliberately not distinguished: a caller that knows whether the id
		// or the signature was wrong can enumerate ids.
		return Credential{}, ErrBadSignature
	}

	// The nonce is consumed LAST, once the request is known to be genuine.
	// Consuming it earlier would let anybody who can reach the port fill a
	// peer's replay cache with nonces of their choosing and have real requests
	// refused as full.
	if err := v.useNonce(found.LinkID, req.Nonce, now); err != nil {
		return Credential{}, err
	}
	return found, nil
}

// useNonce records a nonce, refusing a repeat or a full cache.
func (v *Verifier) useNonce(linkID, nonce string, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	seen := v.nonces[linkID]
	if seen == nil {
		seen = map[string]time.Time{}
		v.nonces[linkID] = seen
	}
	// Expire first: a nonce older than the window can never be accepted again
	// anyway, because its timestamp is already outside it.
	for n, at := range seen {
		if now.Sub(at) > Window {
			delete(seen, n)
		}
	}
	if _, dup := seen[nonce]; dup {
		return ErrReplay
	}
	if len(seen) >= MaxNonces {
		return ErrNonceFull
	}
	seen[nonce] = now
	return nil
}

// parseAuthorization pulls the signature out of the header value.
func parseAuthorization(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) <= len(Scheme) || !strings.EqualFold(v[:len(Scheme)], Scheme) {
		return "", false
	}
	sig := strings.TrimSpace(v[len(Scheme):])
	if sig == "" {
		return "", false
	}
	return sig, true
}
