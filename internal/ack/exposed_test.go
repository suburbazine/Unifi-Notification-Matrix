package ack

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

// ==========================================================================
// THIS IS THE PORT THAT FACES THE INTERNET.
//
// The operator is told to forward web.ack_listen, so it will be found by
// background scanning within days and probed indefinitely. These tests are
// about what a hostile request COSTS, not about what it is allowed to do --
// that half was already settled.
// ==========================================================================

// countingStore wraps a store and counts the reads, which is the measurement
// that matters: this handler shares a SQLite connection pool and a write lock
// with the escalation engine, so a stranger making it query the database is a
// stranger taking capacity from the alarm path.
type countingStore struct {
	incident.Store
	db   *store.SQLite
	gets int
}

func (c *countingStore) Get(ctx context.Context, id string) (*incident.Incident, error) {
	c.gets++
	return c.Store.Get(ctx, id)
}

func countingHandler(t *testing.T) (*Handler, *countingStore, *Signer) {
	t.Helper()
	h, signer, db := newHandler(t)
	cs := &countingStore{Store: db, db: db}
	h.store = cs
	return h, cs, signer
}

func request(h *Handler, method, path, from string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if from != "" {
		r.RemoteAddr = from
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A MALFORMED REQUEST MUST NOT REACH THE DATABASE.
//
// Every shape below used to cost one SQLite read. A megabyte of junk in a path
// segment was handed to the database as a query parameter.
func TestNothingMalformedEverReachesTheStore(t *testing.T) {
	h, cs, _ := countingHandler(t)
	long := strings.Repeat("A", 1<<20)
	good := strings.Repeat("a", TokenChars)

	for _, path := range []string{
		"/ack/i1/x",                  // token too short
		"/ack/i1/" + good + "a",      // token too long
		"/ack/i1/" + long,            // token absurdly long
		"/ack/" + long + "/" + good,  // id absurdly long
		"/ack/i1/" + good[:21] + "=", // padding is not in the alphabet
		"/ack/i1/" + good[:21] + "+", // nor is standard base64
		"/ack/i1/" + good[:21] + "/", // nor a separator
		"/ack//" + good,
		"/ack/i1/",
		"/ack/i1",
		"/ack/i1/a/b",
		"/nope/i1/" + good,
		"/",
	} {
		w := request(h, "POST", path, "203.0.113.9:1234")
		if w.Code != http.StatusNotFound {
			t.Errorf("%.40q gave %d, want 404", path, w.Code)
		}
	}
	if cs.gets != 0 {
		t.Errorf("%d database reads for requests that could not be links this "+
			"product minted; an unauthenticated caller must not be able to "+
			"make this listener query SQLite", cs.gets)
	}
}

// The byte-level cases, checked against the parser directly.
//
// Not through httptest: net/url refuses a control character in a URL before
// anything of ours runs, so routing these through a request would assert on
// the standard library rather than on this package. The bytes still have to be
// refused here, because a caller that builds a path some other way is not
// protected by net/url.
func TestTheParserRefusesBytesThatCannotBeInALink(t *testing.T) {
	good := strings.Repeat("a", TokenChars)
	for _, c := range []struct{ id, token string }{
		{"i1", good[:21] + "\x00"},
		{"i1", good[:20] + "éé"},
		{"i1", good[:21] + " "},
		{"i1", strings.Repeat(" ", TokenChars)},
		{"", good},
		{strings.Repeat("x", maxIDChars+1), good},
		{"a/b", good},
		{"a\x00b" + strings.Repeat("c", 18), good},
		{"i1", ""},
		{"i1", good[:21]},
	} {
		if wellFormed(c.id, c.token) {
			t.Errorf("accepted id %q token %q", c.id, c.token)
		}
	}
	// And a real-looking pair IS accepted, or this refuses everything and
	// proves nothing.
	if !wellFormed("0123456789abcdef01234567", good) {
		t.Error("a real-looking id and token were refused")
	}
}

// A WELL-FORMED WRONG TOKEN COSTS EXACTLY ONE READ, which is the floor: to
// know it is wrong, the incident has to be looked up.
func TestAWellFormedWrongTokenCostsOneRead(t *testing.T) {
	h, cs, _ := countingHandler(t)
	w := request(h, "POST", "/ack/i1/"+strings.Repeat("a", TokenChars), "203.0.113.9:1")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d", w.Code)
	}
	if cs.gets != 1 {
		t.Errorf("gets = %d, want 1", cs.gets)
	}
}

// EVERY MINTED TOKEN PASSES THE SHAPE CHECK.
//
// The failure this guards against is the worst kind: a length or alphabet rule
// that has quietly stopped matching the minter refuses every REAL link, and
// the discovery happens at 3am when somebody taps one.
func TestEveryTokenThisProductMintsPassesTheShapeCheck(t *testing.T) {
	_, signer, _ := newHandler(t)
	for i := 0; i < 500; i++ {
		id := fmt.Sprintf("%024x", i*2654435761)
		tok := signer.Mint(id, t0.Add(time.Duration(i)*time.Second))
		if len(tok) != TokenChars {
			t.Fatalf("Mint produced %d characters, the parser demands %d",
				len(tok), TokenChars)
		}
		if !wellFormed(id, tok) {
			t.Fatalf("a token this product just minted is refused by its own "+
				"parser: id %q token %q", id, tok)
		}
	}
}

// THE SINGLE ERROR CLASS HAS TO HOLD IN TIME AS WELL AS IN THE BODY.
//
// "No such incident" skipped the HMAC and answered measurably faster than
// "wrong token", which is the enumeration the one-error rule exists to
// prevent, arriving through the clock rather than through the body.
//
// Asserted on the WORK DONE rather than on elapsed time: a wall-clock
// assertion on a shared machine is a flake generator, and the thing that was
// actually missing was the verification, not the microseconds.
func TestAMissDoesTheSameCryptographicWorkAsAHit(t *testing.T) {
	h, cs, signer := countingHandler(t)
	counting := &countingVerifier{Signer: signer}
	h.signer = counting
	openIncident(t, cs.db, "i1")
	good := signer.Mint("i1", t0)

	before := counting.verifies
	request(h, "POST", "/ack/i1/"+strings.Repeat("a", TokenChars), "203.0.113.1:1")
	hit := counting.verifies - before

	before = counting.verifies
	request(h, "POST", "/ack/nosuchincidentnosuchi/"+good, "203.0.113.2:1")
	miss := counting.verifies - before

	if miss == 0 {
		t.Fatal("an unknown incident does no cryptographic work at all, so it " +
			"answers faster than a wrong token and the difference is the " +
			"enumeration the single error class exists to prevent")
	}
	if hit != miss {
		t.Errorf("a wrong token costs %d verifications and an unknown incident "+
			"costs %d", hit, miss)
	}
}

// countingVerifier records how many verifications a request performed.
type countingVerifier struct {
	*Signer
	verifies int
}

func (c *countingVerifier) Verify(inc *incident.Incident, token string) error {
	c.verifies++
	return c.Signer.Verify(inc, token)
}

// ---------------------------------------------------------------------------
// The rate limit
// ---------------------------------------------------------------------------

// ONE SOURCE CANNOT HAMMER THIS, and being refused costs no database read.
func TestOneSourceIsBoundedAndARefusalIsFree(t *testing.T) {
	h, cs, signer := countingHandler(t)
	good := signer.Mint("i1", t0)
	path := "/ack/i1/" + good

	for i := 0; i < DefaultBurst; i++ {
		if w := request(h, "GET", path, "203.0.113.5:1000"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("refused legitimate request %d of %d", i+1, DefaultBurst)
		}
	}
	reads := cs.gets

	w := request(h, "GET", path, "203.0.113.5:1000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request %d gave %d, want 429", DefaultBurst+1, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a 429 with no Retry-After tells a client nothing")
	}
	if cs.gets != reads {
		t.Errorf("a rate-limited request still cost %d database reads",
			cs.gets-reads)
	}
}

// AND IT IS PER SOURCE. A limit that one caller can spend on everybody's
// behalf is a denial of service with extra steps.
func TestOneSourceCannotSpendAnothersAllowance(t *testing.T) {
	h, _, signer := countingHandler(t)
	path := "/ack/i1/" + signer.Mint("i1", t0)

	for i := 0; i < DefaultBurst+5; i++ {
		request(h, "GET", path, "203.0.113.5:1000")
	}
	if w := request(h, "GET", path, "198.51.100.7:1000"); w.Code == http.StatusTooManyRequests {
		t.Error("a second address was refused because the first had been busy")
	}
}

// X-FORWARDED-FOR IS NOT A SOURCE.
//
// On a port reachable from the internet it is written by whoever is calling,
// so keying on it would hand every caller a private allowance and turn the
// limit off entirely.
func TestAForwardedForHeaderCannotBuyMoreAllowance(t *testing.T) {
	h, _, signer := countingHandler(t)
	path := "/ack/i1/" + signer.Mint("i1", t0)

	refused := false
	for i := 0; i < DefaultBurst+5; i++ {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "203.0.113.5:1000"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			refused = true
		}
	}
	if !refused {
		t.Error("a caller bought itself an unlimited allowance by varying a " +
			"header it writes")
	}
}

// The bucket refills, or a person who tapped a few times is locked out of the
// only thing that stops their phone ringing.
func TestTheAllowanceComesBack(t *testing.T) {
	now := t0
	h, _, signer := countingHandler(t)
	h.now = func() time.Time { return now }
	path := "/ack/i1/" + signer.Mint("i1", t0)

	for i := 0; i < DefaultBurst+3; i++ {
		request(h, "GET", path, "203.0.113.5:1")
	}
	if w := request(h, "GET", path, "203.0.113.5:1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("not limited: %d", w.Code)
	}

	now = now.Add(DefaultRefill)
	if w := request(h, "GET", path, "203.0.113.5:1"); w.Code == http.StatusTooManyRequests {
		t.Error("the allowance did not come back after one refill period")
	}
}

// A CLOCK THAT WENT BACKWARDS MUST NOT EMPTY SOMEBODY'S BUCKET.
//
// Not exotic: a machine that has just synchronised its time does this, and it
// would silently lock out the one person trying to stop an alarm.
func TestAClockGoingBackwardsDoesNotLockAnybodyOut(t *testing.T) {
	l := newLimiter(5, time.Second)
	now := t0
	if !l.allow("a", now) {
		t.Fatal("refused the first request")
	}
	now = now.Add(-time.Hour)
	for i := 0; i < 4; i++ {
		if !l.allow("a", now) {
			t.Fatalf("refused request %d after the clock went backwards", i+2)
		}
	}

	// AND THE BUCKET STILL REFILLS ON SCHEDULE.
	//
	// The half that actually bites: without resetting the bucket to the new
	// time, the last-seen stamp stays an HOUR IN THE FUTURE, every subsequent
	// elapsed time is negative, and nothing is handed back until the clock
	// catches up again. A person who tapped a few times is then locked out of
	// the only thing that stops their phone ringing, for an hour, because the
	// machine synchronised its time.
	if l.allow("a", now) {
		t.Fatal("the bucket was not empty, so this proves nothing")
	}
	now = now.Add(2 * time.Second)
	if !l.allow("a", now) {
		t.Error("two refill periods after the clock went backwards, nothing " +
			"had been handed back")
	}
}

// THE TABLE IS BOUNDED. It is keyed by an address the caller chooses, so an
// unbounded map here would be the memory exhaustion the limiter exists to
// prevent, arriving through the limiter.
func TestTheLimiterTableCannotGrowWithoutBound(t *testing.T) {
	l := newLimiter(2, time.Second)
	for i := 0; i < maxSources+1000; i++ {
		l.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), t0)
	}
	if n := l.size(); n > maxSources {
		t.Errorf("the table holds %d sources, the cap is %d", n, maxSources)
	}
}

// A REFUSAL LOOKS LIKE EVERY OTHER REFUSAL to anything that caches.
func TestARateLimitedAnswerIsStillNeverStored(t *testing.T) {
	h, _, signer := countingHandler(t)
	path := "/ack/i1/" + signer.Mint("i1", t0)
	for i := 0; i < DefaultBurst+2; i++ {
		request(h, "GET", path, "203.0.113.5:1")
	}
	w := request(h, "GET", path, "203.0.113.5:1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control = %q; the URL is a credential and every answer "+
			"about it has to be uncacheable", w.Header().Get("Cache-Control"))
	}
}

// AND THE LIMIT CAN BE TURNED OFF for a deployment where something in front is
// already doing it -- but only deliberately.
func TestTheLimitCanBeRemovedDeliberately(t *testing.T) {
	h, _, signer := countingHandler(t)
	WithRateLimit(0, 0)(h)
	path := "/ack/i1/" + signer.Mint("i1", t0)
	for i := 0; i < DefaultBurst*3; i++ {
		if w := request(h, "GET", path, "203.0.113.5:1"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("refused at %d with the limiter removed", i)
		}
	}
}
