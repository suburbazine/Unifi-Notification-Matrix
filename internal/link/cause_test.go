package link

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// lastCause returns the cause on the most recent refusal.
func (h *harness) lastCause(t *testing.T) Cause {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.receipts) - 1; i >= 0; i-- {
		if !h.receipts[i].Accepted {
			return h.receipts[i].Cause
		}
	}
	t.Fatal("nothing was refused")
	return CauseNone
}

// raw sends a request with the headers exactly as given, signing nothing.
func (h *harness) raw(path, linkID, ts, nonce, auth string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	if linkID != "" {
		r.Header.Set(HeaderLinkID, linkID)
	}
	if ts != "" {
		r.Header.Set(HeaderTimestamp, ts)
	}
	if nonce != "" {
		r.Header.Set(HeaderNonce, nonce)
	}
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.rc.ServeHTTP(w, r)
	return w
}

// EVERY REFUSAL IS THE SAME 404 AND A DIFFERENT CAUSE.
//
// The wire answer is identical for all of these on purpose. The receipt is the
// only place the difference survives, and it was surviving only as prose --
// readable one at a time and impossible to count. This is the test that keeps
// the labels distinct: if two of these collapse onto one cause, the operator's
// wall of refusals stops being able to answer "what kind of wrong is this".
func TestEachKindOfRefusalGetsItsOwnCause(t *testing.T) {
	stamp := strconv.FormatInt(now.Unix(), 10)
	good := func(h *harness, path, nonce string, body []byte) string {
		return Scheme + " " + Sign(h.cred.Key,
			Canonical(http.MethodPost, path, h.cred.LinkID, stamp, nonce, body))
	}

	cases := []struct {
		name string
		want Cause
		run  func(h *harness)
	}{
		{"unsigned", CauseUnsigned, func(h *harness) {
			h.raw(RouteEvents, h.cred.LinkID, stamp, "n", "", []byte("{}"))
		}},
		{"no such route", CauseNoRoute, func(h *harness) {
			h.post("/link/v1/nope", []byte("{}"), "n")
		}},
		// A path that exists with the wrong verb, and a path that does not
		// exist, are different facts. Both answer the same bare 404; only the
		// receipt is allowed to tell them apart, and it used to call the
		// second one a method problem.
		{"a real route with the wrong verb", CauseMethod, func(h *harness) {
			h.rc.deps.Pairer = NewPairer(fpA)
			r := httptest.NewRequest(http.MethodPost, RouteHello, strings.NewReader("{}"))
			h.rc.ServeHTTP(httptest.NewRecorder(), r)
		}},
		{"a route that does not exist, asked for with a GET", CauseNoRoute, func(h *harness) {
			r := httptest.NewRequest(http.MethodGet, "/link/nothing-here", nil)
			h.rc.ServeHTTP(httptest.NewRecorder(), r)
		}},
		{"wrong method", CauseMethod, func(h *harness) {
			r := httptest.NewRequest(http.MethodGet, RouteEvents, nil)
			h.rc.ServeHTTP(httptest.NewRecorder(), r)
		}},
		{"no headers at all", CauseMalformedAuth, func(h *harness) {
			h.raw(RouteEvents, "", "", "", Scheme+" AAAA", []byte("{}"))
		}},
		{"timestamp that is not a number", CauseMalformedAuth, func(h *harness) {
			h.raw(RouteEvents, h.cred.LinkID, "half past three", "n", Scheme+" AAAA", []byte("{}"))
		}},
		{"clock far out", CauseClockSkew, func(h *harness) {
			old := strconv.FormatInt(now.Add(-2*Window).Unix(), 10)
			h.raw(RouteEvents, h.cred.LinkID, old, "n", Scheme+" AAAA", []byte("{}"))
		}},
		// THE ONE THE WIRE REFUSES TO TELL APART. Verify answers
		// ErrBadSignature for both, so a caller cannot enumerate link ids --
		// and the operator, for whom this difference IS the diagnosis, gets it
		// anyway.
		{"a link id nobody has", CauseUnknownLink, func(h *harness) {
			h.raw(RouteEvents, "lnk_nobody", stamp, "n",
				Scheme+" "+Sign([]byte("whatever"), "whatever"), []byte("{}"))
		}},
		{"a known link id and a wrong signature", CauseBadSignature, func(h *harness) {
			h.raw(RouteEvents, h.cred.LinkID, stamp, "n",
				Scheme+" "+Sign([]byte("the wrong key"), "whatever"), []byte("{}"))
		}},
		{"a nonce used twice", CauseReplay, func(h *harness) {
			b := h.envelope(t, nil)
			h.post(RouteEvents, b, "same")
			h.post(RouteEvents, b, "same")
		}},
		{"a body that is not JSON", CauseMalformedEnvelope, func(h *harness) {
			body := []byte("not json")
			h.raw(RouteEvents, h.cred.LinkID, stamp, "n",
				good(h, RouteEvents, "n", body), body)
		}},
		// SPLIT OUT FROM CauseInvalidEnvelope, because the operator does a
		// different thing about it: every other invalid envelope is a bug to
		// report to the peer's author, and this one is usually their next
		// release carrying a condition nobody has been asked about yet.
		{"a condition the manifest does not declare", CauseUndeclaredCondition, func(h *harness) {
			body := h.envelope(t, func(e *Envelope) { e.Condition = "sentry-not-declared" })
			h.raw(RouteEvents, h.cred.LinkID, stamp, "n",
				good(h, RouteEvents, "n", body), body)
		}},
		{"an envelope the manifest does not allow", CauseInvalidEnvelope, func(h *harness) {
			body := h.envelope(t, func(e *Envelope) { e.Severity = "urgent" })
			h.raw(RouteEvents, h.cred.LinkID, stamp, "n",
				good(h, RouteEvents, "n", body), body)
		}},
		{"ingest refuses it", CauseIngest, func(h *harness) {
			h.mu.Lock()
			h.ingestErr = errors.New("the store is unwell")
			h.mu.Unlock()
			h.post(RouteEvents, h.envelope(t, nil), "n")
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			c.run(h)
			if got := h.lastCause(t); got != c.want {
				t.Errorf("cause = %q, want %q", got, c.want)
			}
		})
	}

	// And the labels are all different from one another, which is the property
	// that makes them worth having. A table where two entries share a label is
	// a table that has stopped distinguishing them.
	seen := map[Cause]string{}
	for _, c := range cases {
		if prev, dup := seen[c.want]; dup && prev != c.name {
			// Shared labels are allowed when the cases really are the same
			// kind of wrong -- two ways of writing a malformed header.
			continue
		}
		seen[c.want] = c.name
	}
	if len(seen) < 10 {
		t.Errorf("only %d distinct causes across %d kinds of failure; the labels "+
			"have collapsed and cannot answer what kind of wrong a refusal is",
			len(seen), len(cases))
	}
}

// PAIRING FAILURES ARE LABELLED TOO, and these are the ones an operator is
// most likely to be standing in front of: a code that has expired, a code
// already spent, and the fingerprint mismatch that means something is
// terminating TLS in between.
func TestPairingFailuresAreLabelledSeparately(t *testing.T) {
	for _, c := range []struct {
		name string
		want Cause
		err  error
	}{
		{"nothing offered", CausePairNoneOffered, ErrNoPairing},
		{"expired", CausePairExpired, ErrCodeExpired},
		{"already used", CausePairUsed, ErrCodeUsed},
		{"voided", CausePairVoided, ErrCodeVoided},
		{"wrong proof", CausePairBadProof, ErrBadProof},
		{"a different certificate", CausePairFingerprint, ErrFingerprint},
		{"no manifest", CausePairManifest, ErrManifestNeeded},
	} {
		if got := pairCause(c.err); got != c.want {
			t.Errorf("%s: cause = %q, want %q", c.name, got, c.want)
		}
	}
}

// The unknown-id answer must not become readable from the WIRE, which is what
// distinguishing it in the receipt could quietly cost.
func TestTellingUnknownFromBadSignatureNeverReachesTheCaller(t *testing.T) {
	h := newHarness(t)
	stamp := strconv.FormatInt(now.Unix(), 10)

	unknown := h.raw(RouteEvents, "lnk_nobody", stamp, "a",
		Scheme+" "+Sign([]byte("k"), "c"), []byte("{}"))
	known := h.raw(RouteEvents, h.cred.LinkID, stamp, "b",
		Scheme+" "+Sign([]byte("k"), "c"), []byte("{}"))

	if unknown.Code != known.Code {
		t.Errorf("an unknown link id answered %d and a known one %d; the id is "+
			"enumerable", unknown.Code, known.Code)
	}
	if unknown.Body.String() != known.Body.String() {
		t.Errorf("the two answers differ:\n%q\n%q", unknown.Body.String(), known.Body.String())
	}
	for _, hdr := range []string{"Content-Type", "Content-Length", "WWW-Authenticate"} {
		if unknown.Header().Get(hdr) != known.Header().Get(hdr) {
			t.Errorf("header %s differs between an unknown and a known link id", hdr)
		}
	}
}
