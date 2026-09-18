package link

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
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

// THE VECTORS ABOVE PROVE NOTHING ABOUT THE PAYLOAD, and that gap cost the
// first live pairing every single event.
//
// A signature is computed over the body's BYTES. The body is opaque to it, so
// a vector can agree perfectly while the two ends disagree about what the
// bytes mean. Sentry's vector body says "v":1; this product's envelope field
// is "link_version". Both implementations reproduced each other's signature,
// both were told interop was proved, and the first real event was refused for
// a field neither vector had ever looked at.
//
// Pinned as a DIFFERENCE, which is the only shape of test that keeps working:
// one asserting the right thing stays right is satisfied by an implementation
// that cannot tell the two apart.
func TestASignatureVectorSaysNothingAboutTheEnvelopeSchema(t *testing.T) {
	// The exact body from Sentry's vector, which we sign identically.
	const vectorBody = `{"v":1,"event_id":"11111111-2222-3333-4444-555555555555",` +
		`"dedup_key":"sentry/d540df0c/sentry-credential-sweep","state":"raised",` +
		`"condition":"sentry-credential-sweep","severity":"critical",` +
		`"title":"Credential sweep: test","detail":"test vector"}`

	var env Envelope
	if err := json.Unmarshal([]byte(vectorBody), &env); err != nil {
		t.Fatalf("the vector body is not even JSON: %v", err)
	}
	if env.LinkVersion == Version {
		t.Fatal("the vector body now carries link_version, so this test no longer " +
			"demonstrates the gap it was written for -- check whether the schema " +
			"vector below has replaced it")
	}
	if err := env.Validate(sentry()); err == nil {
		t.Error("a body we sign byte-for-byte identically also validates as an " +
			"envelope; if that is genuinely true now, this test should be deleted " +
			"rather than left asserting a gap that has closed")
	}
}

// THE SCHEMA VECTOR. What the signature vectors could not say.
//
// Every field name here is the wire name a peer must send, checked against the
// validator rather than against a note. A rename that a peer was not told
// about fails here, which is where the first live pairing should have failed
// rather than at somebody's daemon.
func TestACompleteEnvelopeValidatesUnderTheWireFieldNames(t *testing.T) {
	const body = `{
		"link_version": 1,
		"product": "sentry",
		"product_version": "0.1.9",
		"site_id": "default",
		"event_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"sent_at": "2026-09-18T06:45:00Z",
		"occurred_at": "2026-09-18T06:44:58Z",
		"state": "raised",
		"condition": "sentry-credential-sweep",
		"severity": "critical",
		"title": "Credential sweep",
		"detail": "sixteen denials by one identity in a minute",
		"entity": {"kind": "identity", "id": "test-actor-1", "name": "T"},
		"actor": {"kind": "identity", "id": "test-actor-1", "name": "T"},
		"dedup_key": "sentry/test-actor-1/sentry-credential-sweep",
		"context": {"denials": 16}
	}`

	var env Envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatal(err)
	}
	if err := env.Validate(sentry()); err != nil {
		t.Fatalf("an envelope written with the documented wire names was refused: %v", err)
	}

	// The three that were actually absent in the first live attempt, each
	// checked alone so a peer fixing one is not told about the next only after
	// another round trip.
	for _, missing := range []struct {
		name string
		drop func(*Envelope)
	}{
		{"link_version", func(e *Envelope) { e.LinkVersion = 0 }},
		{"product", func(e *Envelope) { e.Product = "" }},
		{"site_id", func(e *Envelope) { e.SiteID = "" }},
		{"event_id", func(e *Envelope) { e.EventID = "" }},
		{"title", func(e *Envelope) { e.Title = "" }},
		{"entity.id", func(e *Envelope) { e.Entity.ID = "" }},
		{"sent_at", func(e *Envelope) { e.SentAt = time.Time{} }},
	} {
		t.Run("without "+missing.name, func(t *testing.T) {
			var e Envelope
			if err := json.Unmarshal([]byte(body), &e); err != nil {
				t.Fatal(err)
			}
			missing.drop(&e)
			if err := e.Validate(sentry()); err == nil {
				t.Errorf("an envelope with no %s was accepted", missing.name)
			}
		})
	}

	// And the tripwire holds: the key in the body is the one we compute.
	if got := env.dedupKeyFor(sentry()); got != env.DedupKey {
		t.Errorf("computed dedup key %q, envelope says %q", got, env.DedupKey)
	}
}

// SENTRY'S CORRECTED ENVELOPE, exactly as it sent it.
//
// The first one it sent was refused three times in a row for three different
// missing fields, which is what a validator returning the first failure does
// to somebody fixing them one at a time. This is the shape that passed, pinned
// so a change to validation that would refuse it fails here rather than in the
// other product's logs.
func TestSentrysCorrectedEnvelopeValidates(t *testing.T) {
	const body = `{"link_version":1,"product":"sentry","product_version":"1.5.0",
 "site_id":"site-live-verify-01",
 "event_id":"51244833-e0c9-4093-b156-9023ee699b8f",
 "dedup_key":"sentry/test-actor-1/sentry-credential-sweep",
 "sent_at":"2026-09-18T06:46:40+00:00","occurred_at":"2026-09-18T06:46:40+00:00",
 "state":"raised","condition":"sentry-credential-sweep","severity":"critical",
 "title":"Live envelope verification","detail":"post-fix",
 "entity":{"kind":"identity","id":"test-actor-1","name":"Test Actor"},
 "actor":{"kind":"identity","id":"test-actor-1","name":"Test Actor"},
 "context":{}}`

	var e Envelope
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatal(err)
	}
	p := sentry()
	if err := e.Validate(p); err != nil {
		t.Fatalf("the peer's corrected envelope was refused: %v", err)
	}

	// An empty context object is accepted and renders nothing -- one of the two
	// questions the peer asked, answered by the code rather than by opinion.
	if got := e.Event(p, time.Now()).Detail; got != "post-fix" {
		t.Errorf("detail = %q; an empty context should add nothing", got)
	}

	// The tripwire agrees, which is the whole reason it is sent.
	if got := e.dedupKeyFor(p); got != e.DedupKey {
		t.Errorf("computed %q, the peer sent %q", got, e.DedupKey)
	}
}

// WHY AN EMPTY entity.id IS REFUSED RATHER THAN REPAIRED.
//
// incident.Key turns an empty part into "unknown", which is a value that looks
// like data. Every site-scoped condition of one kind from one peer would
// therefore share a single dedup key and merge into ONE incident, for ever,
// with nothing anywhere reading wrong -- the repair produces a working system
// that is quietly incorrect, and it is invisible precisely because it worked.
//
// Pinned as the difference between what the key WOULD be and what validation
// does about it, because the refusal alone reads like a missing-field check
// and is really a collision guard.
func TestAnEmptyEntityIsRefusedBecauseItWouldCollide(t *testing.T) {
	p := sentry()
	blank := Envelope{Entity: Party{ID: ""}, Condition: "sentry-link-test"}
	other := Envelope{Entity: Party{ID: ""}, Condition: "sentry-link-test"}

	// Two DIFFERENT site-scoped events land on the same key once the empty id
	// is repaired into "unknown".
	if blank.dedupKeyFor(p) != other.dedupKeyFor(p) {
		t.Fatal("two empty entities no longer collide, so this test is checking nothing")
	}
	if !strings.Contains(blank.dedupKeyFor(p), "unknown") {
		t.Fatalf("key = %q, expected the repaired \"unknown\" part", blank.dedupKeyFor(p))
	}

	// Which is why the envelope never gets that far.
	full := Envelope{
		LinkVersion: Version, Product: "sentry", SiteID: "s", EventID: "e",
		SentAt: time.Now(), State: StateRaised, Condition: "sentry-link-test",
		Severity: "info", Title: "t", Entity: Party{ID: ""},
	}
	if err := full.Validate(p); err == nil {
		t.Error("an envelope with an empty entity.id was accepted; every " +
			"site-scoped event of this condition would merge into one incident")
	}
}
