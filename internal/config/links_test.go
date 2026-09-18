package config

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// pairedKey is what pairing actually stores: the raw bytes, not their text.
func pairedKey() secret.Secret {
	b := make([]byte, link.KeyBytes)
	for i := range b {
		b[i] = byte(i)
	}
	return secret.Secret(b)
}

func withPeer(l Link) Config {
	c := workable()
	c.Web.LinkListen = "0.0.0.0:8332"
	c.Links = []Link{l}
	return c
}

func goodPeer() Link {
	return Link{
		Slug: "sentry", LinkID: "lnk_sentry", Key: pairedKey(),
		Capability: "access",
		Conditions: []LinkCondition{{Name: "sentry-access-denied", Meaning: "a door refused someone"}},
	}
}

func TestAPairedPeerValidates(t *testing.T) {
	c := withPeer(goodPeer())
	// access is claimed by the peer and no console serves it, which is a
	// warning and must not be an error -- that is the whole failback design.
	if err := c.Validate(); err != nil {
		t.Fatalf("a correctly paired peer was refused: %v", err)
	}
}

// THE BASE64 THAT IS NOT THE KEY.
//
// Pairing mints 32 bytes here and hands the peer a base64 rendering of them.
// Somebody rebuilding a configuration by hand pastes the rendering, and then
// this end signs with 44 characters of ASCII while the peer signs with the 32
// bytes they decode to -- same secret, two readings, two signatures. The link
// port answers every failure with a bare 404, so there is nothing at all to
// read: it presents as a wrong key.
//
// This exact reading cost the other two Xtremission products their first live
// pairing, on the other side of the same construction. The length is the tell,
// and startup is where it can still be said out loud.
func TestTheBase64TextOfALinkKeyIsRefusedRatherThanSignedWith(t *testing.T) {
	raw := []byte(pairedKey().Reveal())
	l := goodPeer()
	l.Key = secret.Secret(base64.StdEncoding.EncodeToString(raw))

	err := withPeer(l).Validate()
	if err == nil {
		t.Fatal("the base64 TEXT of a link key was accepted as the key; every " +
			"event the peer sends would be refused as a bad signature, with a " +
			"bare 404 and no reason anywhere")
	}
	msg := err.Error()
	for _, want := range []string{
		"sentry", // which peer
		"44",     // what is there
		"32",     // what belongs there
		"base64", // and the mistake, by name
		"Pair again",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q, so it does not explain "+
				"itself:\n%s", want, msg)
		}
	}
}

func TestAKeyOfTheWrongLengthIsRefusedWhateverItIs(t *testing.T) {
	l := goodPeer()
	l.Key = secret.Secret("short")
	if err := withPeer(l).Validate(); err == nil {
		t.Fatal("a five-byte link key was accepted")
	}
}

// An absent key is a different thing and is left alone here: BuildLinks skips
// such an entry, and validateLinks refusing it would make a half-written file
// unopenable rather than inert.
func TestAPeerWithNoKeyIsNotRefusedForItsLength(t *testing.T) {
	l := goodPeer()
	l.Key = ""
	if err := withPeer(l).Validate(); err != nil {
		t.Fatalf("an entry with no key yet was refused: %v", err)
	}
}

// ONE CLAIMANT PER CAPABILITY. Two peers both claiming to serve the doors is
// the duplicate-source problem the claim exists to prevent, and last-writer-
// wins would silently demote a working product.
func TestTwoPeersCannotClaimTheSameCapability(t *testing.T) {
	c := withPeer(goodPeer())
	second := goodPeer()
	second.Slug = "doormatrix"
	second.LinkID = "lnk_door"
	second.Conditions = []LinkCondition{{Name: "doormatrix-forced", Meaning: "a door was forced"}}
	c.Links = append(c.Links, second)

	err := c.Validate()
	if err == nil {
		t.Fatal("two peers were allowed to claim the same capability")
	}
	if !strings.Contains(err.Error(), "access") {
		t.Errorf("the refusal does not name the contested capability:\n%v", err)
	}
}

func TestTwoPeersCannotShareALinkID(t *testing.T) {
	c := withPeer(goodPeer())
	second := goodPeer()
	second.Slug = "doormatrix"
	second.Capability = ""
	second.Conditions = nil
	c.Links = append(c.Links, second)

	if err := c.Validate(); err == nil {
		t.Fatal("two peers sharing a link id were accepted; they cannot be told apart")
	}
}

// BuildLinks must hand the signer the BYTES, which is the other half of the
// same question. A change that passed the base64 text through here would leave
// validation green and every signature wrong.
func TestBuildLinksHandsOverTheDecodedKeyBytes(t *testing.T) {
	c := withPeer(goodPeer())
	peers, creds := BuildLinks(&c)
	if len(peers) != 1 || len(creds) != 1 {
		t.Fatalf("built %d peers and %d credentials, want one of each", len(peers), len(creds))
	}
	if len(creds[0].Key) != link.KeyBytes {
		t.Errorf("the credential key is %d bytes, want %d: the signer would be "+
			"keyed with something other than the key", len(creds[0].Key), link.KeyBytes)
	}
	if string(creds[0].Key) != pairedKey().Reveal() {
		t.Error("the credential key is not the stored key")
	}
}
