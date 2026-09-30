package link

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A PRODUCT STILL SENDING WITH A CREDENTIAL THIS INSTALLATION RETIRED IS
// NAMED, NOT CALLED A STRANGER.
//
// A Sentry watch re-paired and kept signing heartbeats -- and its door events
// -- with the credential the re-pair had retired. Every one was refused as "a
// credential this installation has no record of. Either it was paired
// somewhere else, or you have forgotten it here", which sent the operator
// looking for a stranger when the answer was their own product needing a
// restart.
func TestARetiredCredentialIsNamedOnTheReceipt(t *testing.T) {
	h := newHarness(t)
	got := h.contacts()
	retiredAt := time.Date(2026, 9, 30, 6, 36, 31, 0, time.UTC)
	h.rc.deps.Retired = func(id string) (RetiredLink, bool) {
		if id == "lnk_OLD" {
			return RetiredLink{Slug: "sentry", At: retiredAt, Why: "re-paired"}, true
		}
		return RetiredLink{}, false
	}

	// Signed with a key this installation no longer holds, under the old id,
	// while the receiver holds only the current credential.
	w := h.postAs(Credential{LinkID: "lnk_OLD", Key: []byte("the-key-before-the-re-pair")},
		RouteHeartbeat, []byte(`{}`), "n-stale")

	if w.Code != http.StatusNotFound {
		t.Fatalf("a retired credential answered %d; every refusal is the same bare 404", w.Code)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	last := h.receipts[len(h.receipts)-1]
	if last.Cause != CauseRetiredLink {
		t.Fatalf("cause = %q, want %q -- the operator is told a stranger is knocking "+
			"when it is their own product with the old pairing", last.Cause, CauseRetiredLink)
	}
	for _, want := range []string{"lnk_OLD", "sentry", "re-paired", "still sending"} {
		if !strings.Contains(last.Reason, want) {
			t.Errorf("reason = %q; it does not say %q", last.Reason, want)
		}
	}
	if len(*got) != 0 {
		t.Error("a request under a retired credential counted as contact; an old " +
			"credential proves nothing about the product being alive")
	}
}

// An id nobody ever had here stays unknown: the lookup must not dress a
// stranger up as a known product.
func TestAnUnknownCredentialStaysUnknown(t *testing.T) {
	h := newHarness(t)
	h.rc.deps.Retired = func(string) (RetiredLink, bool) { return RetiredLink{}, false }
	h.postAs(Credential{LinkID: "lnk_NEVER", Key: []byte("nobody's")},
		RouteHeartbeat, []byte(`{}`), "n-never")

	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.receipts[len(h.receipts)-1].Cause; c != CauseUnknownLink {
		t.Errorf("cause = %q for an id this installation never had, want %q", c, CauseUnknownLink)
	}
}

// postAs signs with a credential of the caller's choosing, leaving the
// receiver's own credential list alone -- the harness's post signs with the
// same credential the receiver holds, which makes any credential valid.
func (h *harness) postAs(c Credential, path string, body []byte, nonce string) *httptest.ResponseRecorder {
	stamp := strconv.FormatInt(now.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	r.Header.Set(HeaderLinkID, c.LinkID)
	r.Header.Set(HeaderTimestamp, stamp)
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set("Authorization", Scheme+" "+
		Sign(c.Key, Canonical(http.MethodPost, path, c.LinkID, stamp, nonce, body)))
	w := httptest.NewRecorder()
	h.rc.ServeHTTP(w, r)
	return w
}
