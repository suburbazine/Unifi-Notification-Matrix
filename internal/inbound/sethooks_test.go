package inbound

import (
	"net/http"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// A HOOK ADDED IN THE INTERFACE IS A HOOK THAT ANSWERS.
//
// Hooks were built once at start, so a new one's URL did not exist until the
// daemon was restarted -- and posting to it before then returned exactly the
// same 404 as a mistyped token. An operator following the setup instructions
// gets the least useful possible answer to "why is my alarm not arriving":
// the URL the screen has just given them is wrong, according to the daemon
// that gave it to them.
func TestAHookAddedWithoutARestartAcceptsAnAlarm(t *testing.T) {
	r, s := newTestReceiver(t)

	fresh := Hook{
		Name: "door", Token: "tok-door-abcdefghij", Bearer: "bearer-door-abcdefghijkl",
		Product: "access", Condition: event.ConditionDoorForced,
		Severity: incident.SeverityHigh,
	}
	if w := postAs(t, r, PathPrefix+"tok-door-abcdefghij", `{"message":"forced"}`,
		HeaderValueFor(fresh)); w.Code == http.StatusNoContent {
		t.Fatal("the new hook's URL answered before it was configured")
	}

	r.SetHooks(append(testHooks(), fresh))

	w := postAs(t, r, PathPrefix+"tok-door-abcdefghij", `{"message":"forced"}`,
		HeaderValueFor(fresh))
	if w.Code != http.StatusNoContent {
		t.Fatalf("a hook added without a restart answered %d; its URL is on the "+
			"screen and it accepts nothing", w.Code)
	}
	got := s.all()
	if len(got) != 1 || got[0].Condition != event.ConditionDoorForced {
		t.Fatalf("events = %+v, want one door-forced", got)
	}
}

// A hook that is gone stops accepting, on the same save.
//
// It matters more than adding one: the operator deleted it because they did
// not want it, and a URL that keeps raising alarms after being removed from
// the configuration is a credential nobody can revoke without a restart.
func TestARemovedHookStopsAcceptingImmediately(t *testing.T) {
	r, s := newTestReceiver(t)

	if w := post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"down"}`); w.Code != http.StatusNoContent {
		t.Fatalf("setup: the wan hook answered %d", w.Code)
	}

	// Keep only the threat hook.
	r.SetHooks(testHooks()[1:])

	before := len(s.all())
	if w := post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"down"}`); w.Code == http.StatusNoContent {
		t.Error("a hook removed from the configuration still accepted an alarm; " +
			"its URL cannot be revoked without a restart")
	}
	if len(s.all()) != before {
		t.Error("a removed hook still raised an event")
	}
}

// WHAT A RECEIPT SURVIVES.
//
// "Something has arrived at this hook" is what the setup checklist reads, and
// it is the only proof an operator has that their Alarm Manager rule is
// wired up. Losing it because an unrelated setting was saved would send them
// back to re-test something that works.
func TestAnUnchangedHookKeepsItsArrivalReceipt(t *testing.T) {
	r, _ := newTestReceiver(t)

	if w := post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"down"}`); w.Code != http.StatusNoContent {
		t.Fatalf("setup: %d", w.Code)
	}
	if !received(r, "wan") {
		t.Fatal("setup: the wan hook has no receipt")
	}

	// An unrelated save: same hooks, plus a new one.
	r.SetHooks(append(testHooks(), Hook{
		Name: "door", Token: "tok-door-abcdefghij", Bearer: "bearer-door-abcdefghijkl",
		Product: "access", Condition: event.ConditionDoorForced,
	}))
	if !received(r, "wan") {
		t.Error("an untouched hook lost the record of what had arrived at it, so " +
			"the checklist now asks the operator to re-prove a hook that works")
	}
}

// And what it does not survive: a new token is a new URL, and the evidence
// belonged to the old one. The console is still posting to a URL that will
// now be refused, and the checklist has to say so rather than show a delivery
// that can no longer happen.
func TestAReTokenedHookLosesItsReceipt(t *testing.T) {
	r, _ := newTestReceiver(t)

	if w := post(t, r, PathPrefix+"tok-wan-1234567890", `{"message":"down"}`); w.Code != http.StatusNoContent {
		t.Fatalf("setup: %d", w.Code)
	}
	if !received(r, "wan") {
		t.Fatal("setup: the wan hook has no receipt")
	}

	rotated := testHooks()
	rotated[0].Token = "tok-wan-rotated-9876"
	r.SetHooks(rotated)

	if received(r, "wan") {
		t.Error("the hook's token changed -- a different URL -- and it kept the " +
			"receipt from the old one. The checklist will show a delivery that " +
			"can no longer happen, at a URL nothing is posting to.")
	}
}

// Test mode goes with the hook it was armed on.
func TestTestModeDoesNotOutliveItsHook(t *testing.T) {
	r, _ := newTestReceiver(t)
	if _, err := r.ArmTest("wan", 15*time.Minute); err != nil {
		t.Fatalf("ArmTest: %v", err)
	}
	r.SetHooks(testHooks()[1:])
	if _, err := r.ArmTest("wan", time.Minute); err == nil {
		t.Error("test mode could still be armed on a hook that no longer exists")
	}
}

func received(r *Receiver, name string) bool {
	for _, rec := range r.Receipts() {
		if rec.Name == name {
			return rec.Count > 0
		}
	}
	return false
}
