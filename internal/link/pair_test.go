package link

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const fpA = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899"
const fpB = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

func pairer(t *testing.T) (*Pairer, string) {
	t.Helper()
	p := NewPairer(fpA)
	p.Now = func() time.Time { return now }
	code, err := p.Offer()
	if err != nil {
		t.Fatal(err)
	}
	return p, code
}

func pairReq(code, fingerprint string) PairRequest {
	m := sentry().Manifest
	return PairRequest{
		Code: code, Slug: "sentry", Fingerprint: fingerprint, Nonce: "pair-nonce",
		Proof:    PairProof(code, "client", "sentry", fingerprint, "pair-nonce"),
		Manifest: m,
	}
}

func TestAPairingCompletesAndMintsACredential(t *testing.T) {
	p, code := pairer(t)

	res, peer, err := p.Complete(pairReq(code, fpA))
	if err != nil {
		t.Fatalf("a correct pairing was refused: %v", err)
	}
	if res.LinkID == "" || res.Key == "" {
		t.Error("pairing minted no credential")
	}
	if peer.Slug != "sentry" || peer.LinkID != res.LinkID {
		t.Errorf("peer = %+v, want the slug and the minted link id", peer)
	}
	if res.Capability != "access" {
		t.Errorf("capability = %q, want the one the manifest declared", res.Capability)
	}

	// The peer can check this product knew the code too, so it cannot be
	// talked into storing a key by something that merely intercepted.
	want := PairProof(code, "server", res.LinkID, fpA, "pair-nonce")
	if res.Proof != want {
		t.Error("the server proof does not verify against the code the peer typed")
	}
}

// THE MAN IN THE MIDDLE. A peer computes its proof over the certificate IT
// saw. Anything terminating TLS between them presents a different certificate,
// so the proof is over a different fingerprint and cannot match -- an attacker
// holding the code still cannot complete a pairing.
func TestAPeerThatSawADifferentCertificateCannotPair(t *testing.T) {
	p, code := pairer(t)

	_, _, err := p.Complete(pairReq(code, fpB))
	if !errors.Is(err, ErrFingerprint) {
		t.Fatalf("a pairing through a different certificate was accepted: %v", err)
	}

	// Reported distinctly from a wrong code on purpose: "something is
	// terminating TLS between you" and "you mistyped" send an operator to
	// completely different places.
	if errors.Is(err, ErrBadProof) {
		t.Error("a MITM was reported as a bad code, which sends the operator retyping")
	}
}

// A proof computed over the right fingerprint but the wrong code fails too --
// knowing the fingerprint is public knowledge, knowing the code is not.
func TestTheWrongCodeIsRefused(t *testing.T) {
	p, _ := pairer(t)
	req := pairReq("0000000000ZZ", fpA)
	if _, _, err := p.Complete(req); !errors.Is(err, ErrBadProof) {
		t.Errorf("a pairing with the wrong code was accepted: %v", err)
	}
}

// Single use. A half-finished pairing must not be retriable against the same
// secret.
func TestACodeIsSpentOnce(t *testing.T) {
	p, code := pairer(t)
	if _, _, err := p.Complete(pairReq(code, fpA)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Complete(pairReq(code, fpA)); !errors.Is(err, ErrCodeUsed) {
		t.Errorf("a spent code paired a second peer: %v", err)
	}
}

func TestACodeExpires(t *testing.T) {
	p, code := pairer(t)
	p.Now = func() time.Time { return now.Add(CodeTTL + time.Second) }
	if _, _, err := p.Complete(pairReq(code, fpA)); !errors.Is(err, ErrCodeExpired) {
		t.Errorf("an expired code was accepted: %v", err)
	}
	if got, left := p.Offered(); got != "" || left != 0 {
		t.Errorf("an expired code is still being offered to the operator: %q", got)
	}
}

// Ground down rather than guessed: the window dies after a handful of wrong
// answers and the operator generates another.
func TestACodeIsVoidedAfterTooManyAttempts(t *testing.T) {
	p, code := pairer(t)
	wrong := pairReq("0000000000ZZ", fpA)

	for i := 0; i < MaxCodeAttempts; i++ {
		if _, _, err := p.Complete(wrong); err == nil {
			t.Fatalf("attempt %d was accepted", i)
		}
	}
	// Even the RIGHT code is refused now.
	if _, _, err := p.Complete(pairReq(code, fpA)); !errors.Is(err, ErrCodeVoided) {
		t.Errorf("the correct code still worked after the window was ground down: %v", err)
	}
}

// A peer must declare what it is asking to be allowed to say.
func TestPairingRequiresAValidManifest(t *testing.T) {
	p, code := pairer(t)
	req := pairReq(code, fpA)
	req.Manifest = Manifest{}
	if _, _, err := p.Complete(req); !errors.Is(err, ErrManifestNeeded) {
		t.Errorf("a peer paired without declaring anything: %v", err)
	}
}

func TestNoPairingInProgressIsRefused(t *testing.T) {
	p := NewPairer(fpA)
	p.Now = func() time.Time { return now }
	if _, _, err := p.Complete(pairReq("ABCDEFGHJKMN", fpA)); !errors.Is(err, ErrNoPairing) {
		t.Errorf("a pairing completed with no code on offer: %v", err)
	}
}

// Crockford's decoding rules, because a human reads this code off one screen
// and types it into another.
func TestACodeSurvivesBeingTypedByAHuman(t *testing.T) {
	for _, typed := range []string{
		"ABCD-EFGH-JKMN",
		"abcd efgh jkmn",
		"AbCd-EfGh-JkMn",
	} {
		if got := NormaliseCode(typed); got != "ABCDEFGHJKMN" {
			t.Errorf("NormaliseCode(%q) = %q", typed, got)
		}
	}
	// The characters left out of the alphabet are the ones people substitute.
	if got := NormaliseCode("I1L0O"); got != "11100" {
		t.Errorf("NormaliseCode(\"I1L0O\") = %q, want \"11100\"", got)
	}
	// A code typed with a substitution still pairs.
	p, code := pairer(t)
	typed := strings.ReplaceAll(FormatCode(code), "1", "I")
	req := pairReq(typed, fpA)
	if _, _, err := p.Complete(req); err != nil {
		t.Errorf("a code typed with I for 1 was refused: %v", err)
	}
}

// The alphabet has no ambiguous characters, which is the point of choosing it.
func TestGeneratedCodesUseAnUnambiguousAlphabet(t *testing.T) {
	for i := 0; i < 200; i++ {
		code, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != CodeLength {
			t.Fatalf("code %q is %d characters, want %d", code, len(code), CodeLength)
		}
		if strings.ContainsAny(code, "ILOU") {
			t.Fatalf("code %q contains a character people mistype", code)
		}
	}
}

// Pairing proofs and request signatures share a key shape, so they are
// separated by tag: a proof minted for pairing must not verify anywhere else.
func TestPairProofsAreDomainSeparated(t *testing.T) {
	code := "ABCDEFGHJKMN"
	proof := PairProof(code, "client", "sentry", fpA, "n1")

	// The same inputs through the REQUEST construction must not collide.
	req := Sign([]byte(NormaliseCode(code)), Canonical("POST", "/link/pair", "sentry", "0", "n1", nil))
	if proof == req {
		t.Error("a pairing proof and a request signature collided")
	}
	// The two roles are distinct, so a peer's proof cannot be replayed at it.
	if proof == PairProof(code, "server", "sentry", fpA, "n1") {
		t.Error("the client and server proofs are identical")
	}
}
