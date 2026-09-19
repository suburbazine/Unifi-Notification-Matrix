package web

import (
	"errors"
	"net/http"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/audit"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// armAmendment wires an approve/dismiss pair that records what it was asked
// for, so a test can assert on the decision rather than on the config write.
func armAmendment(h *harness, err error) (*[]ApprovedCondition, *[]string) {
	approved := &[]ApprovedCondition{}
	dismissed := &[]string{}
	h.srv.deps.LinkApproveCondition = func(slug string, c ApprovedCondition) error {
		if err != nil {
			return err
		}
		*approved = append(*approved, c)
		return nil
	}
	h.srv.deps.LinkDismissCondition = func(slug, cond string) {
		*dismissed = append(*dismissed, slug+"/"+cond)
	}
	return approved, dismissed
}

func TestASignedInOperatorCanApproveAProposedCondition(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	approved, _ := armAmendment(h, nil)

	res, body := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
		"condition": "sentry-door-missing",
		"meaning":   "a door the controller can no longer see",
		"severity":  "high",
		"momentary": false,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d %s", res.StatusCode, body)
	}
	if len(*approved) != 1 {
		t.Fatalf("approved = %+v", *approved)
	}
	got := (*approved)[0]
	if got.Condition != "sentry-door-missing" || got.Severity != "high" {
		t.Errorf("approved = %+v", got)
	}
	if got.Meaning != "a door the controller can no longer see" {
		t.Errorf("meaning = %q", got.Meaning)
	}
	if !h.log.has(audit.KindConfigChanged, "approved a new condition") {
		t.Errorf("not audited: %v", h.log.summaries())
	}
}

// A MEANING IS REQUIRED, AND THE PEER'S TITLE IS NOT ONE.
//
// The manifest exists to be reviewed. A condition whose only description is
// the title of one event the peer happened to send is a row nobody can judge
// next year, and the operator approving it is the person who has to write it.
func TestApprovingWithoutAMeaningIsRefused(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	approved, _ := armAmendment(h, nil)

	for _, meaning := range []string{"", "   ", "\t\n"} {
		res, body := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
			"condition": "sentry-x", "meaning": meaning, "severity": "high",
		})
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("meaning %q gave %d, want 400: %s", meaning, res.StatusCode, body)
		}
	}
	if len(*approved) != 0 {
		t.Errorf("approved anyway: %+v", *approved)
	}
}

func TestApprovingWithoutACondition(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	approved, _ := armAmendment(h, nil)

	res, _ := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
		"condition": "  ", "meaning": "something", "severity": "high",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.StatusCode)
	}
	if len(*approved) != 0 {
		t.Errorf("approved anyway: %+v", *approved)
	}
}

// ONLY WHAT THE PEER ASKED FOR.
//
// The guard that keeps this from being a second way to write configuration: an
// operator may approve what a peer has actually been refused for, and the
// answer to anything else is the same whether the page is stale or the name
// was invented.
func TestApprovingSomethingThePeerNeverAskedForIsRefused(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	armAmendment(h, ErrNotProposed)

	res, body := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
		"condition": "sentry-invented", "meaning": "whatever I like", "severity": "critical",
	})
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", res.StatusCode, body)
	}
	if h.log.has(audit.KindConfigChanged, "approved a new condition") {
		t.Error("a refused approval was recorded as one that happened")
	}
}

// A validation failure is SHOWN, because refusing with an explanation is the
// whole point of validating.
func TestAnInvalidAmendmentIsExplainedRatherThanSwallowed(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	armAmendment(h, config.Problems{`condition "sentry-x" proposes severity "urgent"`})

	res, body := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
		"condition": "sentry-x", "meaning": "something", "severity": "urgent",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if !contains(body, "urgent") {
		t.Errorf("the reason was not shown: %s", body)
	}
}

// An internal failure is NOT shown: it can name paths and library internals,
// and the detail belongs in the audit log where somebody already authorised
// can read it.
func TestAnInternalAmendmentFailureIsNotShown(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	armAmendment(h, errors.New("open C:\\secret\\path\\config.yaml: access denied"))

	res, body := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
		"condition": "sentry-x", "meaning": "something", "severity": "high",
	})
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if contains(body, "secret") {
		t.Errorf("an internal path reached the response: %s", body)
	}
	if !h.log.has(audit.KindService, "approving a peer condition") {
		t.Errorf("the real error was not recorded: %v", h.log.summaries())
	}
}

func TestAProposalCanBeDismissedWithoutApprovingIt(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	approved, dismissed := armAmendment(h, nil)

	res, body := h.do("DELETE", "/api/link/peers/sentry/conditions/sentry-x", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("dismiss: %d %s", res.StatusCode, body)
	}
	if len(*dismissed) != 1 || (*dismissed)[0] != "sentry/sentry-x" {
		t.Errorf("dismissed = %v", *dismissed)
	}
	if len(*approved) != 0 {
		t.Error("dismissing approved it")
	}
}

// A build with no link listener has nowhere for a peer to pair TO, and says
// that rather than failing in the language of a broken thing.
func TestAmendingWithNoListenerSaysThereIsNowhereToPair(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	for _, r := range []struct{ method, path string }{
		{"POST", "/api/link/peers/sentry/conditions"},
		{"DELETE", "/api/link/peers/sentry/conditions/sentry-x"},
	} {
		res, body := h.do(r.method, r.path, map[string]any{
			"condition": "sentry-x", "meaning": "m", "severity": "high",
		})
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s gave %d, want 404", r.method, r.path, res.StatusCode)
		}
		if !contains(body, "link_listen") {
			t.Errorf("%s does not say what to set: %s", r.path, body)
		}
	}
}

// A MEANING IS BOUNDED. It is rendered into a list somebody reads, and an
// unbounded string in a config file is a config file somebody has to repair.
func TestALongMeaningIsTrimmedRatherThanRefused(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()
	approved, _ := armAmendment(h, nil)

	long := ""
	for len(long) < 5000 {
		long += "very long explanation "
	}
	res, _ := h.do("POST", "/api/link/peers/sentry/conditions", map[string]any{
		"condition": "sentry-x", "meaning": long, "severity": "high",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if n := len([]rune((*approved)[0].Meaning)); n > 200 {
		t.Errorf("stored a %d-character meaning", n)
	}
}

func contains(b []byte, s string) bool {
	return len(b) > 0 && len(s) > 0 && indexOf(string(b), s) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
