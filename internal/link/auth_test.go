package link

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

var signedAt = time.Date(2026, 9, 18, 5, 0, 0, 0, time.UTC)

func creds() []Credential {
	return []Credential{
		{LinkID: "lnk_sentry", Key: []byte("sentry-shared-secret")},
		{LinkID: "lnk_other", Key: []byte("a different secret")},
	}
}

// signed builds a request the way a correct client would.
func signed(c Credential, method, path string, body []byte, ts time.Time, nonce string) Request {
	stamp := strconv.FormatInt(ts.Unix(), 10)
	return Request{
		Method: method, Path: path,
		LinkID: c.LinkID, Timestamp: stamp, Nonce: nonce,
		Authorization: Scheme + " " + Sign(c.Key, Canonical(method, path, c.LinkID, stamp, nonce, body)),
		Body:          body,
	}
}

func verifier() *Verifier {
	v := NewVerifier()
	v.Now = func() time.Time { return signedAt }
	return v
}

func TestAWellSignedRequestVerifies(t *testing.T) {
	c := creds()[0]
	got, err := verifier().Verify(creds(), signed(c, "POST", "/link/v1/events", []byte(`{"a":1}`), signedAt, "n1"))
	if err != nil {
		t.Fatalf("a correctly signed request was refused: %v", err)
	}
	if got.LinkID != c.LinkID {
		t.Errorf("verified as %q, want %q", got.LinkID, c.LinkID)
	}
}

// DOMAIN SEPARATION. Console Cast reuses this construction with its own tag.
// A signature minted for one channel must not verify on the other, so that an
// operator pasting the wrong secret is one mistake and not two.
func TestASignatureFromAnotherChannelDoesNotVerify(t *testing.T) {
	c := creds()[0]
	stamp := strconv.FormatInt(signedAt.Unix(), 10)

	// The tag must be the ONLY difference, or this passes for the wrong
	// reason. An earlier version of this test hard-coded the empty-body hash
	// while sending a body, so the signature differed on two counts and the
	// test stayed green even with domain separation removed.
	const emptyBodySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	var body []byte
	link := Canonical("POST", "/link/v1/events", c.LinkID, stamp, "n1", body)
	cast := "xtremission-cast/v1\nPOST\n/link/v1/events\n" + c.LinkID + "\n" + stamp + "\nn1\n" + emptyBodySHA
	if strings.TrimPrefix(link, canonicalTag) != strings.TrimPrefix(cast, "xtremission-cast/v1") {
		t.Fatalf("the two canonical strings differ by more than the tag:\n%q\n%q", link, cast)
	}
	req := Request{
		Method: "POST", Path: "/link/v1/events",
		LinkID: c.LinkID, Timestamp: stamp, Nonce: "n1",
		Authorization: Scheme + " " + Sign(c.Key, cast),
		Body:          body,
	}
	if _, err := verifier().Verify(creds(), req); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a Console Cast signature verified as a Link request: %v", err)
	}
}

// The body is hashed into the signature, so a payload cannot be edited under a
// signature that was valid for a different one.
func TestATamperedBodyIsRefused(t *testing.T) {
	c := creds()[0]
	req := signed(c, "POST", "/link/v1/events", []byte(`{"severity":"info"}`), signedAt, "n1")
	req.Body = []byte(`{"severity":"critical"}`)
	if _, err := verifier().Verify(creds(), req); !errors.Is(err, ErrBadSignature) {
		t.Errorf("an edited body was accepted: %v", err)
	}
}

// Method and path are signed, so a request cannot be re-aimed at another route
// or turned into a different verb.
func TestAReAimedRequestIsRefused(t *testing.T) {
	c := creds()[0]
	for _, tamper := range []func(*Request){
		func(r *Request) { r.Path = "/link/v1/self" },
		func(r *Request) { r.Method = "DELETE" },
		func(r *Request) { r.LinkID = "lnk_other" },
	} {
		req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "n1")
		tamper(&req)
		if _, err := verifier().Verify(creds(), req); err == nil {
			t.Errorf("a re-aimed request was accepted: %+v", req)
		}
	}
}

func TestTheWrongKeyIsRefused(t *testing.T) {
	bad := Credential{LinkID: "lnk_sentry", Key: []byte("not the secret")}
	req := signed(bad, "POST", "/link/v1/events", []byte(`{}`), signedAt, "n1")
	if _, err := verifier().Verify(creds(), req); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a request signed with the wrong key was accepted: %v", err)
	}
}

// An unknown link id fails the same way a wrong signature does. A caller who
// can tell those apart can enumerate link ids.
func TestAnUnknownLinkFailsLikeABadSignature(t *testing.T) {
	c := Credential{LinkID: "lnk_nobody", Key: []byte("whatever")}
	req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "n1")
	if _, err := verifier().Verify(creds(), req); !errors.Is(err, ErrBadSignature) {
		t.Errorf("an unknown link id produced a distinguishable error: %v", err)
	}
}

// A captured request stops being useful: outside the window in either
// direction, including a clock running ahead.
func TestATimestampOutsideTheWindowIsRefused(t *testing.T) {
	c := creds()[0]
	for _, skew := range []time.Duration{-Window - time.Second, Window + time.Second} {
		req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt.Add(skew), "n"+skew.String())
		if _, err := verifier().Verify(creds(), req); !errors.Is(err, ErrSkew) {
			t.Errorf("a request %s out of date was accepted: %v", skew, err)
		}
	}
	// ...and just inside it is fine.
	req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt.Add(-Window+time.Second), "n-ok")
	if _, err := verifier().Verify(creds(), req); err != nil {
		t.Errorf("a request just inside the window was refused: %v", err)
	}
}

func TestAReplayedNonceIsRefused(t *testing.T) {
	c := creds()[0]
	v := verifier()
	req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "n1")

	if _, err := v.Verify(creds(), req); err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	if _, err := v.Verify(creds(), req); !errors.Is(err, ErrReplay) {
		t.Errorf("the same request replayed was accepted: %v", err)
	}
}

// Nonces are per link: two peers may legitimately choose the same one.
func TestNoncesDoNotCollideAcrossLinks(t *testing.T) {
	v := verifier()
	for _, c := range creds() {
		req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "same-nonce")
		if _, err := v.Verify(creds(), req); err != nil {
			t.Errorf("link %s was refused a nonce another link had used: %v", c.LinkID, err)
		}
	}
}

// THE CACHE IS CONSUMED LAST, once the request is known to be genuine.
//
// Filling it earlier would let anyone who can reach the port stuff a peer's
// replay cache with nonces of their choosing and have real requests refused as
// full -- a denial of service that needs no key at all.
func TestAnUnauthenticatedRequestDoesNotConsumeTheCache(t *testing.T) {
	v := verifier()
	bad := Credential{LinkID: "lnk_sentry", Key: []byte("wrong")}
	for i := 0; i < 50; i++ {
		_, _ = v.Verify(creds(), signed(bad, "POST", "/link/v1/events", []byte(`{}`), signedAt, "burn"))
	}
	// The genuine request may still use that nonce, because no failed attempt
	// recorded it.
	good := signed(creds()[0], "POST", "/link/v1/events", []byte(`{}`), signedAt, "burn")
	if _, err := v.Verify(creds(), good); err != nil {
		t.Errorf("failed attempts poisoned the replay cache: %v", err)
	}
}

// A bounded table that occasionally refuses beats a memory bomb.
func TestAFullNonceCacheRefusesRatherThanGrowing(t *testing.T) {
	v := verifier()
	c := creds()[0]
	for i := 0; i < MaxNonces; i++ {
		req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "n"+strconv.Itoa(i))
		if _, err := v.Verify(creds(), req); err != nil {
			t.Fatalf("refused at %d, before the cache was full: %v", i, err)
		}
	}
	over := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "one-too-many")
	if _, err := v.Verify(creds(), over); !errors.Is(err, ErrNonceFull) {
		t.Errorf("a full cache did not refuse: %v", err)
	}

	// Once the window has passed, the old nonces expire and it works again --
	// refusing is a back-pressure signal, not a permanent wedge.
	v.Now = func() time.Time { return signedAt.Add(Window + time.Second) }
	later := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt.Add(Window+time.Second), "after")
	if _, err := v.Verify(creds(), later); err != nil {
		t.Errorf("the cache did not recover after the window passed: %v", err)
	}
}

func TestMalformedAuthenticationIsRefused(t *testing.T) {
	c := creds()[0]
	for name, tamper := range map[string]func(*Request){
		"no authorization":  func(r *Request) { r.Authorization = "" },
		"wrong scheme":      func(r *Request) { r.Authorization = "Bearer abc" },
		"scheme no value":   func(r *Request) { r.Authorization = Scheme + "   " },
		"no nonce":          func(r *Request) { r.Nonce = "" },
		"no link id":        func(r *Request) { r.LinkID = "" },
		"unparsed stamp":    func(r *Request) { r.Timestamp = "not-a-number" },
		"no timestamp":      func(r *Request) { r.Timestamp = "" },
		"lowercase scheme?": func(r *Request) { r.Authorization = "xt-link-hmac-sha256 " + "x" },
	} {
		req := signed(c, "POST", "/link/v1/events", []byte(`{}`), signedAt, "n-"+name)
		tamper(&req)
		if _, err := verifier().Verify(creds(), req); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The canonical string is the contract between two codebases, so its exact
// shape is pinned here rather than left to whoever edits it next.
func TestTheCanonicalStringIsExactlyAsSpecified(t *testing.T) {
	got := Canonical("post", "/link/v1/events", "lnk_sentry", "1789700400", "abc", nil)
	want := "xtremission-link/v1\n" +
		"POST\n" +
		"/link/v1/events\n" +
		"lnk_sentry\n" +
		"1789700400\n" +
		"abc\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("canonical string drifted:\n got %q\nwant %q", got, want)
	}
}

// A FUTURE-STAMPED REQUEST STAYS UNREPLAYABLE FOR AS LONG AS IT STAYS VALID.
//
// The window is SYMMETRIC on purpose: a stamp up to Window in the future is
// accepted, because two machines' clocks disagree and refusing that breaks a
// peer whose clock runs fast.
//
// That symmetry is what made expiring nonces by ARRIVAL time wrong. A request
// stamped now+Window-1s was accepted now, its nonce was dropped a moment
// later, and its own timestamp stayed inside the window for nearly another
// Window -- so the identical signed request was accepted a second time, which
// is the whole thing the nonce exists to prevent.
//
// It fails silently in both directions, which is why this test walks the clock
// rather than checking one instant.
func TestAFutureStampedRequestCannotBeReplayedWhileItIsStillInWindow(t *testing.T) {
	v := verifier()
	c := creds()[0]

	// Stamped almost a full window ahead, and accepted -- that is the
	// behaviour being protected, not a bug.
	stamp := signedAt.Add(Window - time.Second)
	req := signed(c, "POST", "/link/v1/events", []byte(`{}`), stamp, "future-nonce")
	if _, err := v.Verify(creds(), req); err != nil {
		t.Fatalf("a request from a peer whose clock runs fast was refused: %v", err)
	}

	// Walk forward in steps. At every point the SAME signed request must be
	// answered either as a replay or as out of window -- never accepted.
	for _, ahead := range []time.Duration{
		time.Second,
		Window / 2,
		Window,
		Window + time.Second,
		Window + Window/2,
		2*Window - 2*time.Second,
	} {
		at := signedAt.Add(ahead)
		v.Now = func() time.Time { return at }
		_, err := v.Verify(creds(), req)
		switch {
		case err == nil:
			t.Fatalf("%s later the identical signed request was accepted again; "+
				"its stamp is still %s from that moment, so it was inside the "+
				"window with nothing remembering it",
				ahead, at.Sub(stamp).Round(time.Second))
		case errors.Is(err, ErrReplay), errors.Is(err, ErrSkew):
		default:
			t.Fatalf("%s later: unexpected %v", ahead, err)
		}
	}
}

// AND THE ENTRY IS NOT KEPT FOR EVER EITHER.
//
// Expiring on the stamp has to drop the nonce once no request bearing it could
// pass the skew check -- otherwise the cache fills with entries that can never
// matter and a busy peer is refused as full.
func TestANonceIsForgottenOnceNothingCarryingItCouldStillBeAccepted(t *testing.T) {
	v := verifier()
	c := creds()[0]

	stamp := signedAt.Add(Window - time.Second)
	req := signed(c, "POST", "/link/v1/events", []byte(`{}`), stamp, "future-nonce")
	if _, err := v.Verify(creds(), req); err != nil {
		t.Fatal(err)
	}

	// Well past the point where anything carrying that stamp would be refused
	// for skew, the table must be empty again.
	at := stamp.Add(Window + time.Second)
	v.Now = func() time.Time { return at }
	for i := 0; i < MaxNonces; i++ {
		fresh := signed(c, "POST", "/link/v1/events", []byte(`{}`), at, "fresh"+strconv.Itoa(i))
		if _, err := v.Verify(creds(), fresh); err != nil {
			t.Fatalf("refused a fresh request at %d; the expired entry was "+
				"never dropped and the cache is filling with nonces that can "+
				"no longer matter: %v", i, err)
		}
	}
}
