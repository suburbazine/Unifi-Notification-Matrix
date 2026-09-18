package link

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// respell rewrites a standard padded base64 digest into one of the other three
// spellings of the same bytes.
func respell(std, as string) string {
	raw, err := base64.StdEncoding.DecodeString(std)
	if err != nil {
		panic(err)
	}
	switch as {
	case "RawStd":
		return base64.RawStdEncoding.EncodeToString(raw)
	case "URL":
		return base64.URLEncoding.EncodeToString(raw)
	case "RawURL":
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return std
}

// spellings are the four ways the same digest is written in the wild. The
// url-safe ones are not exotic: Python's urlsafe_b64encode and Go's
// base64.RawURLEncoding are what a careful author reaches for when a value
// might end up in a URL, and a signature looks exactly like such a value.
var spellings = []string{"Std", "RawStd", "URL", "RawURL"}

// A CORRECT SIGNATURE IN A DIFFERENT BASE64 IS STILL A CORRECT SIGNATURE.
//
// This is the mirror of a bug the other end of this protocol hit for real: its
// key decoder refused our alphabet, so a correct credential was reported as
// "not valid base64" and the operator was told to paste again exactly what he
// had already pasted correctly. On this side every refusal answers a bare 404,
// so the same strictness would present as an authentication failure with
// nothing whatsoever to read.
//
// The test is written over a signature that CONTAINS a character the two
// alphabets disagree about, or it proves nothing: most digests happen to use
// neither "+" nor "/", and those respell to themselves.
func TestASignatureVerifiesInAnyBase64Spelling(t *testing.T) {
	c := creds()[0]
	body := []byte(`{"a":1}`)
	const path = "/link/v1/events"
	stamp := strconv.FormatInt(signedAt.Unix(), 10)

	// Nonces are walked until the signature is one the alphabets disagree
	// about. Without this the whole test can pass on a digest for which every
	// spelling is byte-identical.
	var nonce, sig string
	for i := 0; i < 200; i++ {
		nonce = "spelling-" + strconv.Itoa(i)
		sig = Sign(c.Key, Canonical("POST", path, c.LinkID, stamp, nonce, body))
		if strings.ContainsAny(sig, "+/") {
			break
		}
	}
	if !strings.ContainsAny(sig, "+/") {
		t.Fatal("no signature containing + or / was found, so this test cannot " +
			"tell the two alphabets apart and is checking nothing")
	}

	for _, as := range spellings {
		t.Run(as, func(t *testing.T) {
			req := Request{
				Method: "POST", Path: path,
				LinkID: c.LinkID, Timestamp: stamp, Nonce: nonce + as,
				Authorization: Scheme + " " + respell(sig, as),
				Body:          body,
			}
			// The nonce differs per spelling only so the replay cache does not
			// refuse the second and third for the right reason.
			req.Authorization = Scheme + " " + respell(
				Sign(c.Key, Canonical("POST", path, c.LinkID, stamp, req.Nonce, body)), as)
			if _, err := verifier().Verify(creds(), req); err != nil {
				t.Errorf("a correct signature spelled in %s base64 was refused: %v", as, err)
			}
		})
	}
}

// ...AND A WRONG SIGNATURE IS STILL WRONG.
//
// The guard on the test above. Accepting four spellings must not have turned
// into accepting anything that decodes, which is the way a permissive decoder
// usually fails.
func TestBeingRelaxedAboutBase64DoesNotAcceptAWrongSignature(t *testing.T) {
	c := creds()[0]
	body := []byte(`{"a":1}`)
	const path = "/link/v1/events"
	stamp := strconv.FormatInt(signedAt.Unix(), 10)
	good := Sign(c.Key, Canonical("POST", path, c.LinkID, stamp, "n1", body))
	raw, _ := base64.StdEncoding.DecodeString(good)

	// One bit, in the last byte.
	raw[len(raw)-1] ^= 1
	bad := base64.StdEncoding.EncodeToString(raw)

	for _, as := range spellings {
		req := Request{
			Method: "POST", Path: path,
			LinkID: c.LinkID, Timestamp: stamp, Nonce: "n-" + as,
			Authorization: Scheme + " " + respell(bad, as),
			Body:          body,
		}
		if _, err := verifier().Verify(creds(), req); err == nil {
			t.Errorf("a signature wrong in one bit was accepted when spelled in %s base64", as)
		}
	}

	// And something that is not base64 at all is refused rather than treated
	// as an empty digest -- the second half of the same bug at the other end,
	// where a decoder that silently dropped stray characters turned garbage
	// into a zero-length key.
	for _, junk := range []string{"!!!", "not base64", "="} {
		req := Request{
			Method: "POST", Path: path,
			LinkID: c.LinkID, Timestamp: stamp, Nonce: "junk-" + junk,
			Authorization: Scheme + " " + junk,
			Body:          body,
		}
		if _, err := verifier().Verify(creds(), req); err == nil {
			t.Errorf("%q was accepted as a signature", junk)
		}
	}
}

// THE SAME TOLERANCE AT PAIRING, WHERE GETTING IT WRONG COSTS MORE.
//
// An ordinary request refused for a spelling difference is refused again on
// the next one. A PAIRING refused for a spelling difference burns one of five
// attempts, and the fifth voids the operator's code -- so a peer whose base64
// differs from ours does not merely fail to pair, it destroys the code while
// reporting something that reads as a mistyped one.
func TestAPairingProofIsAcceptedInAnyBase64Spelling(t *testing.T) {
	for _, as := range spellings {
		t.Run(as, func(t *testing.T) {
			p, code := pairer(t)
			req := pairReq(code, fpA)
			req.Proof = respell(req.Proof, as)
			if _, _, err := p.Complete(req); err != nil {
				t.Errorf("a correct proof spelled in %s base64 was refused: %v", as, err)
			}
		})
	}
}

// ...and a wrong proof still voids nothing it should not: it is still wrong.
func TestARelaxedProofCheckStillRefusesTheWrongProof(t *testing.T) {
	p, code := pairer(t)
	req := pairReq(code, fpA)
	raw, _ := base64.StdEncoding.DecodeString(req.Proof)
	raw[0] ^= 1
	req.Proof = base64.RawURLEncoding.EncodeToString(raw)
	if _, _, err := p.Complete(req); err == nil {
		t.Error("a proof wrong in one bit was accepted because it was url-safe base64")
	}
}
