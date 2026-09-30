package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/ack"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/store"
)

// ntfyRecorder stands in for an ntfy server and keeps the Actions value of
// every publication -- the button, exactly as the phone would receive it.
type ntfyRecorder struct {
	mu      sync.Mutex
	actions []string
	status  int
}

func (n *ntfyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.actions = append(n.actions, r.URL.Query().Get("actions"))
	if n.status != 0 {
		w.WriteHeader(n.status)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (n *ntfyRecorder) last(t *testing.T) string {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.actions) == 0 {
		t.Fatal("nothing was published to ntfy")
	}
	return n.actions[len(n.actions)-1]
}

type testRig struct {
	db       *store.SQLite
	delivery *config.Delivery
	ntfy     *ntfyRecorder
	ackBase  string
}

// newTestRig wires the pieces a real site has: the store, an ack listener on
// its own port with the site's key, and ntfy -- through BuildDelivery, the
// same constructor the daemon uses, so the alert is the one a phone gets.
func newTestRig(t *testing.T, withAckBase bool) *testRig {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "incidents.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	key, err := ack.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ack.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ack.New(db, signer)
	if err != nil {
		t.Fatal(err)
	}
	ackSrv := httptest.NewServer(h)
	t.Cleanup(ackSrv.Close)

	rec := &ntfyRecorder{}
	ntfySrv := httptest.NewServer(rec)
	t.Cleanup(ntfySrv.Close)

	c := &config.Config{}
	c.Web.AckKey = key
	if withAckBase {
		c.Web.AckBaseURL = ackSrv.URL
	}
	c.Channels.Ntfy = &config.Ntfy{Enabled: true, ServerURL: ntfySrv.URL, Topic: "site-test"}
	d, err := config.BuildDelivery(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return &testRig{db: db, delivery: d, ntfy: rec, ackBase: ackSrv.URL}
}

// press does what the ntfy app does with an http action: parse the short
// format, send the request it describes, show nobody the answer.
func press(t *testing.T, action string) {
	t.Helper()
	parts := strings.Split(action, ", ")
	if len(parts) < 3 || parts[0] != "http" || parts[1] != "Acknowledge" {
		t.Fatalf("the test alert carries no Acknowledge button; its actions are %q", action)
	}
	method := http.MethodGet // ntfy's default when none is given
	for _, p := range parts[3:] {
		if v, ok := strings.CutPrefix(p, "method="); ok {
			method = v
		}
	}
	req, err := http.NewRequest(method, parts[2], nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

var testT0 = time.Date(2026, 9, 30, 14, 0, 0, 0, time.UTC)

// THE TEST PRESSES THE BUTTON.
//
// The old test sent ntfy a hand-written message with no action on it, so it
// passed for months while the Acknowledge button on every real alert fetched a
// confirmation page and acknowledged nothing. This one sends the real alert
// through the real channel, takes the button off what ntfy received, presses
// it the way the app does, and checks the incident the page is watching.
func TestAChannelTestIsAcknowledgedByTheButtonItCarries(t *testing.T) {
	rig := newTestRig(t, true)
	ctx := context.Background()

	res, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0)
	if err != nil {
		t.Fatal(err)
	}
	if res.IncidentID == "" || !res.AckLink {
		t.Fatalf("result %+v: the page has nothing to watch, or was told there is no button", res)
	}

	inc, err := rig.db.Get(ctx, res.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	// Resolved from the start is what keeps a test out of the escalation
	// ladder: an unpressed test must not page the whole call list.
	if inc.State() != incident.StateResolved {
		t.Fatalf("the test incident is %s before anybody pressed anything; want resolved, "+
			"or the scheduler escalates a test nobody answered", inc.State())
	}

	press(t, rig.ntfy.last(t))

	inc, err = rig.db.Get(ctx, res.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if !inc.Acknowledged() {
		t.Fatal("pressing Acknowledge on the test alert did not acknowledge it -- which is " +
			"the failure this test exists to show on the settings page")
	}
	if inc.AckVia != "ntfy" {
		t.Errorf("acknowledged via %q, want ntfy: the page tells the operator which channel "+
			"the acknowledgement came back through", inc.AckVia)
	}
	if inc.State() != incident.StateClosed {
		t.Errorf("an acknowledged test is %s; it should be finished", inc.State())
	}
}

// Pressed twice, the page watches the newer one; the older is closed rather
// than left on the board.
func TestANewerTestSupersedesTheOneStillWaiting(t *testing.T) {
	rig := newTestRig(t, true)
	ctx := context.Background()

	first, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.IncidentID == second.IncidentID {
		t.Fatal("the second test reused the first's incident")
	}
	old, err := rig.db.Get(ctx, first.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if old.State() != incident.StateClosed || !strings.Contains(old.CloseReason, "superseded") {
		t.Errorf("the earlier test is %s (%q); want closed as superseded", old.State(), old.CloseReason)
	}
	cur, err := rig.db.Get(ctx, second.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Terminal() {
		t.Error("the newer test was closed too")
	}
}

// A test that could not be sent is not left waiting for a button nobody has.
func TestATestThatCouldNotBeSentIsClosed(t *testing.T) {
	rig := newTestRig(t, true)
	rig.ntfy.status = http.StatusForbidden
	ctx := context.Background()

	if _, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0); err == nil {
		t.Fatal("ntfy refused the publication and the test reported success")
	}
	active, err := rig.db.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, inc := range active {
		t.Errorf("an unsendable test was left on the board: %s (%s)", inc.Title, inc.State())
	}
}

// No ack_base_url: the alert went out with no button. Say so, and do not
// leave the test on the board waiting for something that cannot happen.
func TestATestWithNoButtonSaysSoAndIsNotLeftWaiting(t *testing.T) {
	rig := newTestRig(t, false)
	ctx := context.Background()

	res, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0)
	if err != nil {
		t.Fatal(err)
	}
	if res.AckLink || !strings.Contains(res.AckReason, "ack_base_url") {
		t.Errorf("result %+v: the page must be told the alert has no acknowledgement, and why", res)
	}
	if a := rig.ntfy.last(t); a != "" {
		t.Errorf("with no ack_base_url the alert still carried actions %q", a)
	}
	inc, err := rig.db.Get(ctx, res.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if !inc.Terminal() {
		t.Errorf("a test that can never be acknowledged is %s, waiting on the board", inc.State())
	}
}

// Nobody pressed it: closed after the window, and never over the top of an
// acknowledgement that got there first.
func TestAnUnansweredTestExpiresButAnAnsweredOneIsLeftAlone(t *testing.T) {
	rig := newTestRig(t, true)
	ctx := context.Background()

	unanswered, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0)
	if err != nil {
		t.Fatal(err)
	}
	if err := expireChannelTest(ctx, rig.db, unanswered.IncidentID, testT0.Add(testAckWindow)); err != nil {
		t.Fatal(err)
	}
	inc, _ := rig.db.Get(ctx, unanswered.IncidentID)
	if !inc.Terminal() || inc.Acknowledged() {
		t.Errorf("an unanswered test after the window is %s (acked %v); want closed, "+
			"unacknowledged", inc.State(), inc.Acknowledged())
	}

	answered, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	press(t, rig.ntfy.last(t))
	if err := expireChannelTest(ctx, rig.db, answered.IncidentID, testT0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	inc, _ = rig.db.Get(ctx, answered.IncidentID)
	if !inc.Acknowledged() || strings.Contains(inc.CloseReason, "nobody acknowledged") {
		t.Errorf("expiry rewrote a test that was acknowledged: acked %v, close reason %q",
			inc.Acknowledged(), inc.CloseReason)
	}
}

// A restart loses the expiry timers. Start-up closes the tests it
// interrupted -- and nothing else.
func TestStartUpClosesInterruptedTestsAndNothingElse(t *testing.T) {
	rig := newTestRig(t, true)
	ctx := context.Background()

	test, err := testWithAck(ctx, rig.db, rig.delivery, "ntfy", testT0)
	if err != nil {
		t.Fatal(err)
	}
	real := incident.Open("real1", incident.Key("internal", "self", "deadman"),
		incident.SeverityCritical, "internal", "Something real", "", testT0)
	if err := real.Resolve(testT0); err != nil {
		t.Fatal(err)
	}
	if err := rig.db.Put(ctx, real); err != nil {
		t.Fatal(err)
	}

	if err := closeLeftoverChannelTests(ctx, rig.db, testT0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	inc, _ := rig.db.Get(ctx, test.IncidentID)
	if !inc.Terminal() {
		t.Error("an interrupted test survived start-up and waits on the board for ever")
	}
	// A minute-old test closed at start-up was not "unanswered for fifteen
	// minutes", and the page shows the operator this reason.
	if !strings.Contains(inc.CloseReason, "restart") {
		t.Errorf("an interrupted test was closed as %q; it should say a restart interrupted it",
			inc.CloseReason)
	}
	other, _ := rig.db.Get(ctx, "real1")
	if other.Terminal() {
		t.Error("start-up closed a real incident from the same source")
	}
}

// The field configuration: the test tells the page, with the alert, that the
// link it carries goes to port 80 and what to set instead.
func TestTheChannelTestWarnsAboutALinkWithNoPort(t *testing.T) {
	c := &config.Config{}
	c.Web.Listen = "127.0.0.1:8322"
	c.Web.AckListen = "0.0.0.0:50001"
	c.Web.AckBaseURL = "http://fpcbr.xtremission.com"
	if w := testAckWarning(c); !strings.Contains(w, "http://fpcbr.xtremission.com:50001") {
		t.Errorf("warning = %q; want it to give the address with its port", w)
	}
	c.Web.AckBaseURL = "http://fpcbr.xtremission.com:50001"
	if w := testAckWarning(c); w != "" {
		t.Errorf("warned %q about an address that has its port", w)
	}
}
