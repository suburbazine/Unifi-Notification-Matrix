package link

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// THE CROSS-IMPLEMENTATION VECTOR.
//
// Every other test in this package checks this implementation against itself,
// which is the one thing that cannot find a divergence: a signer and a verifier
// written from the same file agree even when both are wrong about the protocol.
// The numbers below came from the OTHER end -- Sentry's independent Python
// implementation, written from the shared design note and not from this code --
// and are pinned here so a change to the canonical string that both ends did
// not agree to fails at build time rather than at an operator's first pair.
//
// The tag, the path and the body hash are each load-bearing: changing any one
// of them fails this test, which was confirmed by making each change and
// watching it go red.
func TestTheCanonicalStringMatchesSentrysIndependentImplementation(t *testing.T) {
	// A fixed test key -- the bytes 0x00..0x1f -- and NOT a pairing secret.
	const keyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	const body = `{"v":1,"event_id":"11111111-2222-3333-4444-555555555555",` +
		`"dedup_key":"sentry/d540df0c/sentry-credential-sweep","state":"raised",` +
		`"condition":"sentry-credential-sweep","severity":"critical",` +
		`"title":"Credential sweep: test","detail":"test vector"}`
	const wantBodyHash = "09472f3a0b29e3c2a7e3e5d33b5bb77573a886fdbc15630b087ac24d0660bb7d"
	const wantSignature = "CQVvVkyZgpUAkv5t2sj4BM8cNw+vO0xjAOFawgC7ul8="

	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatal(err)
	}

	// Checked separately from the signature so that a body-hashing difference
	// is not reported as a signing difference. They fail together otherwise,
	// and the second is much the harder thing to go looking for.
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != wantBodyHash {
		t.Errorf("body hash\n got %s\nwant %s\n"+
			"The two ends hash the request body differently, so no signature "+
			"over it can agree.", got, wantBodyHash)
	}

	canonical := Canonical("POST", "/link/v1/events", "lnk-testvector",
		"1789700000", "dGVzdC12ZWN0b3Itbm9uY2U=", []byte(body))
	if got := Sign(key, canonical); got != wantSignature {
		t.Errorf("signature\n got %s\nwant %s\ncanonical string was:\n%s",
			got, wantSignature, canonical)
	}
}

// DOMAIN SEPARATION, CHECKED AGAINST THE REAL OTHER CHANNEL.
//
// TestASignatureFromAnotherChannelDoesNotVerify proves the tag is load-bearing
// using a tag this file made up, which cannot show that the tag we separate
// FROM is the one the other channel actually uses. This vector came from Door
// Matrix's independent implementation of Console Cast -- a different protocol
// that reuses this construction deliberately, with its own tag -- so it pins
// three things at once: that our HMAC and canonical layout agree with a THIRD
// implementation, that the real Cast tag produces a different signature from
// ours, and that the key is the decoded bytes.
//
// That last one is not decoration. It is the bug this vector found in a live
// pairing between the other two products: one end keyed the MAC with the
// 43-character base64 text of the key and the other with the 32 bytes it
// decodes to. Same secret, same canonical string, two signatures, and on a
// port where every failure is a bare 404 it read as a credential problem.
func TestOurConstructionAgreesWithConsoleCastAndOurTagDoesNot(t *testing.T) {
	// 0xdeadbeef repeated, written url-safe and unpadded, which is how the
	// other product stores it. The alphabet is part of the vector.
	const keyB64URL = "3q2-796tvu_erb7v3q2-796tvu_erb7v3q2-796tvu8"
	const body = `{"state":"begin","id":"b1","hold_seconds":60}`
	const bodyHash = "3dbb5c2687ca9408fd35b4d45a7a13c2022d5f9d6575d99584bf4bb08754579a"
	const castTag = "xtremission-cast/v1"
	const wantCast = "uwdg+mwe19FGVZQEiO25EZte5X2nptJp8vNT0VHRM8w="

	key, err := base64.RawURLEncoding.DecodeString(keyB64URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("the vector's key decodes to %d bytes, want 32", len(key))
	}
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != bodyHash {
		t.Fatalf("body hash got %s, want %s", got, bodyHash)
	}

	canonical := func(tag string) string {
		return strings.Join([]string{tag, "POST", "/api/cast/burst", "link-1",
			"1789711700", "conformance-vector-1", bodyHash}, "\n")
	}

	if got := Sign(key, canonical(castTag)); got != wantCast {
		t.Errorf("Console Cast's vector\n got %s\nwant %s\n"+
			"The two products no longer compute the same MAC over the same "+
			"canonical string, which is a divergence in the shared construction.",
			got, wantCast)
	}

	// Keying with the base64 TEXT rather than the bytes it decodes to. Pinned
	// as a DIFFERENCE so that "simplify this" can never quietly restore the
	// reading that cost the other two products a live pairing.
	if got := Sign([]byte(keyB64URL), canonical(castTag)); got == wantCast {
		t.Error("keying the MAC with the base64 text produced the same signature " +
			"as keying it with the decoded bytes, so this vector cannot tell " +
			"the two readings apart and the check is worthless")
	}

	// And ours is not theirs.
	if got := Sign(key, canonical(canonicalTag)); got == wantCast {
		t.Errorf("a Console Cast signature verifies under the Link tag %q: "+
			"the two channels are not separated", canonicalTag)
	}
}
