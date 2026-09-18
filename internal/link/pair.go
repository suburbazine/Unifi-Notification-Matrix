package link

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Pairing constants, all chosen so one short code typed once is enough.
const (
	// CodeLength is 12 Crockford characters: 60 bits, which is far past
	// guessing inside a ten-minute window that also dies after five wrong
	// answers.
	CodeLength = 12

	// CodeTTL is how long a code is offered for. Long enough to walk to
	// another machine, short enough that a code left on a screen expires.
	CodeTTL = 10 * time.Minute

	// MaxCodeAttempts voids a code rather than letting it be ground down. The
	// operator generates another; an attacker does not get a second window.
	MaxCodeAttempts = 5
)

// crockford is Crockford's base32 alphabet: no I, L, O or U, so a code read
// aloud or copied by hand has no ambiguous characters and no accidental words.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// pairTag separates pairing proofs from request signatures.
//
// The same reasoning as the request canonical tag: two constructions sharing a
// key must never produce a value that verifies in the other's context. Here
// the key IS the pairing code, briefly, and a proof minted for pairing must
// not be replayable as anything else.
const pairTag = "xtremission-link/pair/v1"

var (
	ErrNoPairing      = errors.New("link: no pairing is in progress")
	ErrCodeExpired    = errors.New("link: the pairing code has expired")
	ErrCodeUsed       = errors.New("link: the pairing code has already been used")
	ErrCodeVoided     = errors.New("link: the pairing code was voided after too many attempts")
	ErrBadProof       = errors.New("link: the pairing proof does not match")
	ErrFingerprint    = errors.New("link: the peer saw a different certificate")
	ErrManifestNeeded = errors.New("link: a peer must declare a manifest to pair")
)

// NewCode returns a fresh pairing code.
func NewCode() (string, error) {
	var b strings.Builder
	for i := 0; i < CodeLength; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(crockford))))
		if err != nil {
			return "", fmt.Errorf("link: generating a pairing code: %w", err)
		}
		b.WriteByte(crockford[n.Int64()])
	}
	return b.String(), nil
}

// NormaliseCode accepts what a human actually types.
//
// Crockford's decoding rules: case does not matter, and the characters left
// out of the alphabet are the ones people substitute -- I and L read as 1, O
// reads as 0. Hyphens and spaces are grouping, not content.
func NormaliseCode(v string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(v)) {
		switch r {
		case '-', ' ':
			continue
		case 'I', 'L':
			b.WriteByte('1')
		case 'O':
			b.WriteByte('0')
		case 'U':
			// Not in the alphabet and not a substitution for anything. Kept so
			// it fails the comparison rather than being silently dropped into
			// a shorter code that might match.
			b.WriteByte('U')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FormatCode groups a code for display: XXXX-XXXX-XXXX.
func FormatCode(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 4 {
		end := i + 4
		if end > len(code) {
			end = len(code)
		}
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}

// PairProof is the value each side computes to prove it knows the code.
//
// THE FINGERPRINT IS IN IT, and that is what defeats an active attacker at
// pairing time. A peer computes its proof over the certificate IT saw. If
// anything terminated TLS in the middle, the peer saw that thing's
// certificate, its proof is over a different fingerprint, and it cannot match
// the one this product computes over its own. The attacker holds a code and
// still cannot complete a pairing.
//
// role distinguishes the two directions so a peer's proof cannot be replayed
// back at it as the server's.
func PairProof(code, role, party, fingerprint, nonce string) string {
	return base64.StdEncoding.EncodeToString(proofBytes(code, role, party, fingerprint, nonce))
}

// proofBytes is the proof before it is written down.
func proofBytes(code, role, party, fingerprint, nonce string) []byte {
	m := hmac.New(sha256.New, []byte(NormaliseCode(code)))
	m.Write([]byte(strings.Join([]string{
		pairTag, role, party, NormaliseFingerprint(fingerprint), nonce,
	}, "\n")))
	return m.Sum(nil)
}

// PairRequest is what a peer sends to /link/pair.
type PairRequest struct {
	Code string `json:"code"`
	Slug string `json:"product"`

	// Fingerprint is the certificate the peer SAW. Sent so the two sides can
	// disagree loudly rather than pair through a man in the middle.
	Fingerprint string `json:"cert_fingerprint"`
	Nonce       string `json:"nonce"`
	Proof       string `json:"proof"`

	Manifest Manifest `json:"manifest"`
}

// PairResponse is what this product returns on success.
type PairResponse struct {
	LinkID string `json:"link_id"`
	Key    string `json:"link_key"`

	// Proof lets the peer confirm this product knew the code too, so a peer
	// cannot be talked into storing a key by something that merely intercepted
	// the request.
	Proof string `json:"proof"`

	Capability string `json:"capability"`
}

// Pairer offers a code and completes one pairing with it.
//
// In memory only, deliberately. A pairing code is a credential with a
// ten-minute life; writing it down would make it outlive its own window and
// give an attacker with the config file something to use.
type Pairer struct {
	// Fingerprint is this product's own certificate fingerprint.
	Fingerprint string

	// NewKey mints the long-lived link key. Replaced in tests.
	NewKey func() (linkID string, key []byte, err error)

	Now func() time.Time

	mu       sync.Mutex
	code     string
	offered  time.Time
	attempts int
	used     bool
	voided   bool
}

// NewPairer returns a pairer for a product with this certificate.
func NewPairer(fingerprint string) *Pairer {
	return &Pairer{Fingerprint: NormaliseFingerprint(fingerprint)}
}

func (p *Pairer) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Offer generates a code and starts the window. Any previous code is
// abandoned: two live codes would mean an operator cannot tell which one they
// are looking at.
func (p *Pairer) Offer() (string, error) {
	code, err := NewCode()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.code, p.offered, p.attempts, p.used, p.voided = code, p.now(), 0, false, false
	return code, nil
}

// Cancel withdraws an offered code.
func (p *Pairer) Cancel() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.code, p.used, p.voided = "", false, true
}

// Offered reports the live code and how long is left, for the operator's
// screen. Empty when nothing is on offer.
func (p *Pairer) Offered() (string, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.code == "" || p.used || p.voided {
		return "", 0
	}
	left := CodeTTL - p.now().Sub(p.offered)
	if left <= 0 {
		return "", 0
	}
	return p.code, left
}

// Complete verifies a peer's proof and mints its credential.
func (p *Pairer) Complete(req PairRequest) (PairResponse, Peer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	switch {
	case p.code == "":
		return PairResponse{}, Peer{}, ErrNoPairing
	case p.voided:
		return PairResponse{}, Peer{}, ErrCodeVoided
	case p.used:
		return PairResponse{}, Peer{}, ErrCodeUsed
	case now.Sub(p.offered) > CodeTTL:
		return PairResponse{}, Peer{}, ErrCodeExpired
	case p.attempts >= MaxCodeAttempts:
		p.voided = true
		return PairResponse{}, Peer{}, ErrCodeVoided
	}

	// THE FINGERPRINT CHECK COMES FIRST and is separate from the proof, so the
	// operator's receipt can say "the peer saw a different certificate" --
	// which means something is terminating TLS between them -- rather than the
	// generic "wrong code" that would send them retyping it.
	if NormaliseFingerprint(req.Fingerprint) != p.Fingerprint {
		p.attempts++
		return PairResponse{}, Peer{}, ErrFingerprint
	}
	if err := req.Manifest.Validate(req.Slug); err != nil {
		p.attempts++
		return PairResponse{}, Peer{}, fmt.Errorf("%w: %v", ErrManifestNeeded, err)
	}

	// Compared by bytes rather than by text, for the reason decodeDigest
	// gives -- and it matters MORE here than on an ordinary request. A peer
	// whose base64 alphabet differs from ours would not merely be refused: it
	// would burn one of five attempts per try and VOID the operator's code on
	// the fifth, which reads as a mistyped code and is not.
	want := proofBytes(p.code, "client", req.Slug, p.Fingerprint, req.Nonce)
	if !sameDigest(want, req.Proof) {
		p.attempts++
		if p.attempts >= MaxCodeAttempts {
			p.voided = true
		}
		return PairResponse{}, Peer{}, ErrBadProof
	}

	mint := p.NewKey
	if mint == nil {
		mint = newLinkCredential
	}
	linkID, key, err := mint()
	if err != nil {
		return PairResponse{}, Peer{}, err
	}

	// Single use. The code is spent whether or not anything later fails, so a
	// half-finished pairing cannot be retried against the same secret.
	p.used = true

	peer := Peer{
		Slug:     req.Slug,
		LinkID:   linkID,
		Manifest: req.Manifest,
	}
	return PairResponse{
		LinkID:     linkID,
		Key:        base64.StdEncoding.EncodeToString(key),
		Proof:      PairProof(p.code, "server", linkID, p.Fingerprint, req.Nonce),
		Capability: req.Manifest.Capability,
	}, peer, nil
}

// KeyBytes is the length of a link key: 256 bits of randomness, and the
// number the configuration is checked against.
//
// Named rather than written as 32 at the two places that care, because the
// check in config is only meaningful if it cannot drift from what pairing
// actually mints.
const KeyBytes = 32

// newLinkCredential mints a link id and a 256-bit key.
func newLinkCredential() (string, []byte, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, fmt.Errorf("link: generating a link id: %w", err)
	}
	key := make([]byte, KeyBytes)
	if _, err := rand.Read(key); err != nil {
		return "", nil, fmt.Errorf("link: generating a link key: %w", err)
	}
	var id strings.Builder
	id.WriteString("lnk_")
	for _, b := range idBytes {
		id.WriteByte(crockford[int(b)%len(crockford)])
	}
	return id.String(), key, nil
}
