package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// ==========================================================================
// WHAT A HOSTILE REQUEST COSTS.
//
// Two ports here are reachable by somebody the operator never granted
// anything to: the acknowledgement listener, which they are TOLD to forward,
// and the peer link listener. Both were safe in what they served and neither
// was bounded in what it cost.
// ==========================================================================

// THE RECEIVER ACTUALLY APPLIES THE RULE.
//
// The three tests below this one assert on the auditedCause TABLE, which is
// the decision. This one asserts on the BEHAVIOUR -- that the Record callback
// consults it at all. Both survived their first mutation without this: a
// table nothing reads is a comment.
func TestTheLinkReceiverOnlyAuditsRefusalsThatRequiredACredential(t *testing.T) {
	log := &capturingLog{}
	d := linkDeps{
		cfg:      func() *config.Config { return &config.Config{} },
		saveCfg:  func(*config.Config) error { return nil },
		state:    newLinkState(nil),
		auditLog: log,
	}
	record := d.build().Record

	// Everything a stranger can cause: no durable write at all.
	for _, c := range []link.Cause{
		link.CauseNoRoute, link.CauseMethod, link.CauseUnsigned,
		link.CauseBadSignature, link.CauseClockSkew, link.CauseReplay,
		link.CausePairBadProof, link.CausePairNoneOffered, link.CauseHelloClosed,
	} {
		record(link.Receipt{At: time.Now(), Route: "/link/v1/events", Cause: c,
			Reason: "refused"})
	}
	if n := len(log.entries); n != 0 {
		t.Errorf("%d audit entries from refusals nobody authenticated for; on a "+
			"port anybody can reach that is one fsync per packet, and the file "+
			"rotates away the acknowledgement record", n)
	}

	// And one that required a credential still lands.
	record(link.Receipt{At: time.Now(), LinkID: "lnk", Route: "/link/v1/events",
		Cause: link.CauseUndeclaredCondition, Reason: "not declared"})
	if len(log.entries) != 1 {
		t.Errorf("a refusal that required a credential was not recorded: %d entries",
			len(log.entries))
	}

	// An ACCEPTED receipt is not an audit entry either -- the receipts page
	// carries those, and a durable line per delivered event would be a second
	// copy of the incident record.
	before := len(log.entries)
	record(link.Receipt{At: time.Now(), LinkID: "lnk", Route: "/link/v1/ping", Accepted: true})
	if len(log.entries) != before {
		t.Error("an accepted request was written to the audit log")
	}
}

// AN UNAUTHENTICATED REFUSAL MUST NOT WRITE TO DISK.
//
// This used to append every refusal to audit.jsonl with an fsync -- one
// synchronous disk flush per stranger's packet, on a port anybody can reach.
// Worse than the cost: that file ROTATES, so filling it with refusals evicts
// the record of who acknowledged what, which is the thing the audit log is
// for. Knocking on the port could erase it.
func TestAnUnauthenticatedRefusalIsNotWrittenToTheAuditLog(t *testing.T) {
	for _, c := range []link.Cause{
		link.CauseNoRoute,
		link.CauseMethod,
		link.CauseUnsigned,
		link.CauseMalformedAuth,
		link.CauseUnknownLink,
		link.CauseBadSignature,
		link.CauseClockSkew,
		link.CauseReplay,
		link.CauseNonceFull,
		link.CauseBodyUnreadable,
		link.CauseBodyTooLarge,
		link.CauseHelloClosed,
		link.CausePairUnavailable,
		link.CausePairBody,
		link.CausePairNoneOffered,
		link.CausePairExpired,
		link.CausePairUsed,
		link.CausePairVoided,
		link.CausePairBadProof,
		link.CausePairFingerprint,
		link.CausePairManifest,
	} {
		if auditedCause[c] {
			t.Errorf("%q is reachable without authenticating and is written to "+
				"the audit log, so anybody who can open the port can make this "+
				"machine fsync -- and rotate away the acknowledgement record", c)
		}
	}
}

// AND A REFUSAL THAT REQUIRED A CREDENTIAL STILL IS.
//
// The point is not to stop auditing; it is to stop auditing things a stranger
// can cause. A paired peer sending something it did not declare is a fact
// about a product the operator granted a credential to, and it is rare by
// construction.
func TestARefusalThatRequiredACredentialIsStillAudited(t *testing.T) {
	for _, c := range []link.Cause{
		link.CauseRateLimited,
		link.CauseNoPeer,
		link.CauseMalformedEnvelope,
		link.CauseInvalidEnvelope,
		link.CauseEnvelopeVersion,
		link.CauseUndeclaredCondition,
		link.CauseStore,
		link.CauseIngest,
		link.CausePairStore,
	} {
		if !auditedCause[c] {
			t.Errorf("%q happens only after a peer has authenticated or paired, "+
				"and is no longer recorded anywhere durable", c)
		}
	}
}

// EVERY CAUSE IS DECIDED ONE WAY OR THE OTHER.
//
// A cause added later and not thought about here defaults to "not audited",
// which is the safe direction but a silent one. This is what makes the
// decision explicit: a new cause fails this test until somebody has answered
// the question for it.
func TestEveryRefusalCauseHasBeenDecidedAboutTheAuditLog(t *testing.T) {
	// Everything NOT in auditedCause is deliberately unaudited, and this is
	// the list of those, kept by hand so adding a cause forces a choice.
	unaudited := map[link.Cause]bool{
		link.CauseMethod: true, link.CauseNoRoute: true,
		link.CauseBodyUnreadable: true, link.CauseBodyTooLarge: true,
		link.CauseUnsigned: true, link.CauseMalformedAuth: true,
		link.CauseUnknownLink: true, link.CauseBadSignature: true,
		link.CauseClockSkew: true, link.CauseReplay: true,
		link.CauseNonceFull: true, link.CauseHelloClosed: true,
		link.CausePairUnavailable: true, link.CausePairBody: true,
		link.CausePairNoneOffered: true, link.CausePairExpired: true,
		link.CausePairUsed: true, link.CausePairVoided: true,
		link.CausePairBadProof: true, link.CausePairFingerprint: true,
		link.CausePairManifest: true,
	}
	for _, c := range link.AllCauses() {
		if auditedCause[c] == unaudited[c] {
			t.Errorf("%q is in both lists or neither; decide whether reaching "+
				"it requires a credential, and put it in exactly one", c)
		}
	}
}

// ---------------------------------------------------------------------------
// The acknowledgement listener's wrappers
// ---------------------------------------------------------------------------

// THE IN-FLIGHT CAP IS WHAT PROTECTS THE REST OF THE PRODUCT.
//
// This handler shares a process, a SQLite connection pool and a write lock
// with the escalation engine. The failure worth preventing is not a refused
// acknowledgement -- that is cheap and recoverable -- it is an ALARM THAT
// CANNOT BE DELIVERED because the ack port is busy.
func TestTheAckHandlerRefusesRatherThanQueueingPastItsCap(t *testing.T) {
	const cap = 4
	release := make(chan struct{})
	entered := make(chan struct{}, cap*4)
	h := inFlight(cap, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}))

	for i := 0; i < cap; i++ {
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/ack/x/y", nil))
		}()
	}
	// Wait for all of them to be INSIDE the handler, not merely started.
	for i := 0; i < cap; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatalf("only %d of %d requests reached the handler", i, cap)
		}
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/ack/x/y", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("request %d gave %d, want 503 -- queueing it would put it "+
			"behind the database lock the alarm path needs", cap+1, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a 503 with no Retry-After tells a client nothing")
	}
	// The same rule as every other answer on this port: the URL is a
	// credential, so nothing about it may be stored by an intermediary.
	if w.Header().Get("Cache-Control") == "" {
		t.Error("the busy answer is cacheable")
	}

	close(release)
	// And the slots come back, or the first burst would close the port for
	// good.
	w = httptest.NewRecorder()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/ack/x/y", nil))
		if w.Code != http.StatusServiceUnavailable {
			break
		}
	}
	if w.Code == http.StatusServiceUnavailable {
		t.Error("the slots never came back")
	}
}

// THE ACK-ONLY PORT SERVES ONE PREFIX AND NOTHING ELSE.
//
// A ServeMux answered some malformed paths with a 307 redirect to the cleaned
// path, generated before the handler ran -- so without the Cache-Control and
// Referrer-Policy every other answer here carries, and with the token already
// in the request line. This listener serves one prefix; it does not need a
// router.
func TestTheAckOnlyPortNeverRedirectsAndAlwaysSaysNoStore(t *testing.T) {
	served := false
	h := ackOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{"/", "/api/settings", "/static/app.js", "/ackx/1/2", "/hello"} {
		served = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if served {
			t.Errorf("%q reached the acknowledgement handler", path)
		}
		if w.Code != http.StatusNotFound {
			t.Errorf("%q gave %d, want 404", path, w.Code)
		}
		if w.Header().Get("Location") != "" {
			t.Errorf("%q was answered with a redirect carrying %q",
				path, w.Header().Get("Location"))
		}
		if w.Header().Get("Cache-Control") == "" {
			t.Errorf("%q was answered without a Cache-Control", path)
		}
	}

	// And the one prefix it exists for does get through.
	served = false
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/ack/id/token", nil))
	if !served || w.Code != http.StatusOK {
		t.Errorf("a real acknowledgement path was not served: served=%v code=%d",
			served, w.Code)
	}
}

// THE CONNECTION CAP IS THE ONE THAT EXHAUSTS THE WHOLE DAEMON.
//
// Unbounded accepts are worse than unbounded concurrency: each idle connection
// holds a goroutine, two buffers and a FILE DESCRIPTOR for up to IdleTimeout,
// and running out of descriptors takes down every listener in the process, not
// just this one.
func TestTheAckListenerHoldsOnlySoManyConnections(t *testing.T) {
	const cap = 3
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	l := limitListener(base, cap)

	var accepted []net.Conn
	done := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			done <- c
		}
	}()

	var dialled []net.Conn
	for i := 0; i < cap; i++ {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		dialled = append(dialled, c)
	}
	for i := 0; i < cap; i++ {
		select {
		case c := <-done:
			accepted = append(accepted, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d connections were accepted", i, cap)
		}
	}

	// One more: it must NOT be accepted while the cap is full.
	extra, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialled = append(dialled, extra)
	select {
	case <-done:
		t.Fatal("a connection past the cap was accepted; the limit is not applied")
	case <-time.After(300 * time.Millisecond):
	}

	// Closing one hands the slot back, or the first burst would close the
	// port permanently.
	accepted[0].Close()
	select {
	case c := <-done:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Error("closing a connection did not release its slot")
	}

	for _, c := range dialled {
		c.Close()
	}
	for _, c := range accepted[1:] {
		c.Close()
	}
}

// A SLOT IS RELEASED EXACTLY ONCE.
//
// net/http closes a connection on more than one path. A double release hands
// out a slot that was never taken, which over a long run removes the limit
// entirely -- and does it silently, on the port that gets hammered.
func TestClosingAConnectionTwiceReleasesOneSlot(t *testing.T) {
	// Counted rather than drained from a channel: a double release against a
	// real semaphore BLOCKS, so the mutation that breaks this would hang the
	// suite instead of failing it, and a deadlock is a much worse way to learn
	// something than an assertion.
	released := 0
	c := &limitedConn{Conn: fakeConn{}, release: func() { released++ }}

	_ = c.Close()
	_ = c.Close()
	_ = c.Close()

	if released != 1 {
		t.Errorf("three closes released %d slots; net/http closes a connection "+
			"on more than one path, so a slot handed back twice raises the cap "+
			"a little every time -- silently, on the port that gets hammered",
			released)
	}
}

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func (fakeConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
