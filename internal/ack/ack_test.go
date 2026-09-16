package ack

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

func newHandler(t *testing.T) (*Handler, *Signer, *store.SQLite) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	key, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(db, signer, WithClock(func() time.Time { return t0.Add(time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}
	return h, signer, db
}

func openIncident(t *testing.T, db *store.SQLite, id string) *incident.Incident {
	t.Helper()
	inc := incident.Open(id, "access/front-door/forced-open",
		incident.SeverityCritical, "access", "Door forced open", "Front door", t0)
	if err := db.Put(context.Background(), inc); err != nil {
		t.Fatal(err)
	}
	return inc
}

func do(h *Handler, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func body(w *httptest.ResponseRecorder) string {
	b, _ := io.ReadAll(w.Result().Body)
	return string(b)
}

// ==========================================================================
// THE ONE THAT MATTERS MOST.
// ==========================================================================
//
// Corporate mail scanners and chat link-preview bots fetch every link they
// see. If GET acknowledged, every emailed alert would be silenced by a machine
// seconds after it was sent -- silently, and indistinguishably from a human
// having dealt with it.
func TestGETDoesNotAcknowledge(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")
	url := "/ack/i1/" + signer.Mint(inc.ID, inc.OpenedAt)

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := do(h, method, url)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", method, w.Code)
		}
		after, err := db.Get(context.Background(), "i1")
		if err != nil {
			t.Fatal(err)
		}
		if after.Acknowledged() {
			t.Fatalf("%s acknowledged the incident -- a mail scanner fetching "+
				"the link would silence every emailed alert", method)
		}
	}

	// And the page it renders must offer the POST that actually does it.
	w := do(h, http.MethodGet, url)
	if !strings.Contains(body(w), `method="post"`) {
		t.Error("the confirmation page has no POST form, so the link cannot be acted on")
	}
}

func TestPOSTAcknowledges(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")

	var hooked *incident.Incident
	var hookedVia string
	h.OnAck = func(i *incident.Incident, via string) { hooked, hookedVia = i, via }

	w := do(h, http.MethodPost, "/ack/i1/"+signer.Mint(inc.ID, inc.OpenedAt)+"?via=ntfy")
	if w.Code != http.StatusOK {
		t.Fatalf("POST = %d, want 200: %s", w.Code, body(w))
	}
	after, err := db.Get(context.Background(), "i1")
	if err != nil {
		t.Fatal(err)
	}
	if !after.Acknowledged() {
		t.Fatal("POST did not acknowledge the incident")
	}
	if after.AckVia != "ntfy" {
		t.Errorf("AckVia = %q, want %q", after.AckVia, "ntfy")
	}
	if hooked == nil || hookedVia != "ntfy" {
		t.Error("the audit hook was not called with the channel")
	}
	// Acknowledged is not resolved: the door is still open and the incident
	// stays on the board as the obligation it is.
	if after.Resolved() {
		t.Error("acknowledging also marked the condition resolved")
	}
}

// Two taps is not an error. Somebody who taps twice must see that it worked,
// not an error page that makes them think it did not.
func TestAcknowledgingTwiceIsFine(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")
	url := "/ack/i1/" + signer.Mint(inc.ID, inc.OpenedAt)

	first := do(h, http.MethodPost, url)
	second := do(h, http.MethodPost, url)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("codes = %d, %d; both should be 200", first.Code, second.Code)
	}
	if !strings.Contains(strings.ToLower(body(second)), "already") {
		t.Errorf("the second tap did not say it was already done:\n%s", body(second))
	}

	after, _ := db.Get(context.Background(), "i1")
	if !after.AckedAt.Equal(t0.Add(time.Minute)) {
		t.Error("the second acknowledgement moved the timestamp; the first is " +
			"the one that counts")
	}
}

// A wrong token and an unknown incident must be indistinguishable, or anyone
// with the endpoint can enumerate which incident ids exist.
func TestAWrongTokenAndAnUnknownIncidentLookIdentical(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")

	wrongToken := do(h, http.MethodPost, "/ack/i1/"+signer.Mint("i1", inc.OpenedAt.Add(time.Second)))
	unknownID := do(h, http.MethodPost, "/ack/i-does-not-exist/"+signer.Mint(inc.ID, inc.OpenedAt))

	if wrongToken.Code != unknownID.Code {
		t.Errorf("status codes differ: %d vs %d -- that difference enumerates "+
			"incident ids", wrongToken.Code, unknownID.Code)
	}
	if body(wrongToken) != body(unknownID) {
		t.Error("the response bodies differ between a bad token and a missing " +
			"incident, which leaks which ids exist")
	}

	after, _ := db.Get(context.Background(), "i1")
	if after.Acknowledged() {
		t.Fatal("a wrong token acknowledged the incident")
	}
}

// A token is bound to the incident AND its open time, so it names exactly one
// occurrence of one condition.
func TestATokenIsBoundToOneIncidentOccurrence(t *testing.T) {
	_, signer, _ := newHandler(t)

	a := signer.Mint("i1", t0)
	if signer.Mint("i2", t0) == a {
		t.Error("two incidents share a token")
	}
	if signer.Mint("i1", t0.Add(time.Second)) == a {
		t.Error("two occurrences of one incident id share a token; a token " +
			"minted for a closed incident could acknowledge a later one")
	}
	// A different installation key must produce different tokens.
	other, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSigner(other)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Mint("i1", t0) == a {
		t.Error("the token does not depend on the installation key")
	}
}

func TestTokensAreLongEnoughToBeUnguessable(t *testing.T) {
	_, signer, _ := newHandler(t)
	tok := signer.Mint("i1", t0)
	// 16 bytes base64url, unpadded.
	if len(tok) < 20 {
		t.Errorf("token %q is %d characters; too short to resist guessing", tok, len(tok))
	}
}

func TestMalformedPathsAreRejected(t *testing.T) {
	h, _, _ := newHandler(t)
	for _, p := range []string{"/ack", "/ack/", "/ack/i1", "/ack/i1/", "/ack//tok", "/", "/ack/i1/tok/extra"} {
		w := do(h, http.MethodPost, p)
		if w.Code == http.StatusOK {
			t.Errorf("%s was accepted", p)
		}
	}
}

// The via hint is attacker-controlled: it arrives in the query string and
// lands in the audit record.
func TestTheViaHintIsSanitised(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")

	nasty := "<script>alert(1)</script>"
	w := do(h, http.MethodPost, "/ack/i1/"+signer.Mint(inc.ID, inc.OpenedAt)+"?via="+nasty)
	if w.Code != http.StatusOK {
		t.Fatalf("POST = %d", w.Code)
	}
	after, _ := db.Get(context.Background(), "i1")
	if strings.ContainsAny(after.AckVia, "<>/()") {
		t.Errorf("AckVia = %q; unsafe characters reached the audit record", after.AckVia)
	}
	if strings.Contains(body(w), "<script>") {
		t.Errorf("the response echoed a script tag:\n%s", body(w))
	}
}

// The URL is a credential; an intermediary caching the response is caching it.
func TestResponsesAreNotCacheable(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")
	w := do(h, http.MethodGet, "/ack/i1/"+signer.Mint(inc.ID, inc.OpenedAt))
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if w.Header().Get("Referrer-Policy") == "" {
		t.Error("no Referrer-Policy, so the token can leak in a Referer header")
	}
}

// An acknowledgement arriving while the scheduler is writing the very alert
// that prompted it must not be lost -- the reason the handler uses a
// compare-and-swap rather than a plain Put.
func TestConcurrentAcknowledgementsAllSucceedAndOneWins(t *testing.T) {
	h, signer, db := newHandler(t)
	inc := openIncident(t, db, "i1")
	url := "/ack/i1/" + signer.Mint(inc.ID, inc.OpenedAt)

	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = do(h, http.MethodPost, url).Code
		}(i)
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("request %d = %d, want 200", i, c)
		}
	}
	after, _ := db.Get(context.Background(), "i1")
	if !after.Acknowledged() {
		t.Fatal("eight concurrent acknowledgements and the incident is not acknowledged")
	}
}

func TestNewSignerRefusesAnEmptyKey(t *testing.T) {
	if _, err := NewSigner(""); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("NewSigner(\"\") = %v, want ErrNoSecret", err)
	}
}

func TestURLIncludesTheTokenAndTheChannelHint(t *testing.T) {
	_, signer, _ := newHandler(t)
	u := signer.URL("https://nm.example.com/", "i1", t0, "ntfy")
	if !strings.HasPrefix(u, "https://nm.example.com/ack/i1/") {
		t.Errorf("URL = %q", u)
	}
	if !strings.HasSuffix(u, "?via=ntfy") {
		t.Errorf("URL = %q, want the channel hint", u)
	}
	// And it must be usable: mint/verify round trip through the built URL.
	tok := strings.TrimSuffix(strings.TrimPrefix(u, "https://nm.example.com/ack/i1/"), "?via=ntfy")
	inc := incident.Open("i1", "k", incident.SeverityHigh, "access", "t", "", t0)
	if err := signer.Verify(inc, tok); err != nil {
		t.Errorf("the token from URL() does not verify: %v", err)
	}
}
