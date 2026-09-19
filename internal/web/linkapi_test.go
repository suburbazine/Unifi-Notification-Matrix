package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/link"
)

// EVERY LINK ROUTE IS A CREDENTIAL OPERATION.
//
// Offering a code hands out something that, for the next ten minutes, lets a
// peer pair and then raise alarms here and take over a capability. Cancelling
// and forgetting revoke. None of them may be reachable without a session, and
// the state route carries the fingerprint and the live code, so it is a read
// that must be gated too.
func TestEveryLinkRouteIsRefusedToASignedOutCaller(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.srv.deps.LinkState = func() LinkPairing { return LinkPairing{Available: true} }
	h.srv.deps.LinkOfferCode = func() (string, time.Duration, error) {
		t.Error("a signed-out caller was given a pairing code")
		return "NOPE", time.Minute, nil
	}
	h.srv.deps.LinkCancelCode = func() { t.Error("a signed-out caller cancelled a code") }
	h.srv.deps.LinkUnpair = func(string) (bool, error) {
		t.Error("a signed-out caller unpaired a peer")
		return false, nil
	}
	h.srv.deps.LinkApproveCondition = func(string, ApprovedCondition) error {
		t.Error("a signed-out caller widened a peer's approved manifest")
		return nil
	}
	h.srv.deps.LinkDismissCondition = func(string, string) {
		t.Error("a signed-out caller dismissed a proposal")
	}

	for _, r := range []struct{ method, path string }{
		{"GET", "/api/link"},
		{"POST", "/api/link/code"},
		{"DELETE", "/api/link/code"},
		{"DELETE", "/api/link/peers/sentry"},
		{"POST", "/api/link/peers/sentry/conditions"},
		{"DELETE", "/api/link/peers/sentry/conditions/sentry-x"},
	} {
		res, body := h.do(r.method, r.path, nil)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d to a signed-out caller, want 401: %s",
				r.method, r.path, res.StatusCode, body)
		}
	}
}

func TestASignedInOperatorCanOfferAndCancelAPairingCode(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	offered := 0
	cancelled := 0
	h.srv.deps.LinkOfferCode = func() (string, time.Duration, error) {
		offered++
		return "ABCD-EFGH-JKMN", 10 * time.Minute, nil
	}
	h.srv.deps.LinkCancelCode = func() { cancelled++ }

	res, body := h.do("POST", "/api/link/code", map[string]any{})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("offering a code returned %d: %s", res.StatusCode, body)
	}
	var got struct {
		Code    string `json:"code"`
		Expires int    `json:"expires_seconds"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != "ABCD-EFGH-JKMN" {
		t.Errorf("code = %q, want the offered one", got.Code)
	}
	if got.Expires != 600 {
		t.Errorf("expires_seconds = %d, want 600; an operator typing this into "+
			"another machine needs to know how long is left", got.Expires)
	}

	if res, _ := h.do("DELETE", "/api/link/code", nil); res.StatusCode != http.StatusOK {
		t.Errorf("cancelling a code returned %d", res.StatusCode)
	}
	if offered != 1 || cancelled != 1 {
		t.Errorf("offered %d and cancelled %d, want one of each", offered, cancelled)
	}
}

// FORGETTING A PEER THAT IS NOT THERE MUST NOT READ AS SUCCESS.
//
// The button is the only way an operator revokes a credential. A revoke that
// quietly did nothing -- a typo in the slug, a peer already gone -- and still
// answered "done" is the worst possible answer to that particular question.
func TestForgettingAnUnknownPeerSaysSoRatherThanReportingSuccess(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	var asked []string
	h.srv.deps.LinkUnpair = func(slug string) (bool, error) {
		asked = append(asked, slug)
		return slug == "sentry", nil
	}

	if res, body := h.do("DELETE", "/api/link/peers/sentry", nil); res.StatusCode != http.StatusOK {
		t.Fatalf("forgetting a paired peer returned %d: %s", res.StatusCode, body)
	}
	res, body := h.do("DELETE", "/api/link/peers/sentrry", nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("forgetting an unknown peer returned %d, want 404", res.StatusCode)
	}
	if !bytes.Contains(body, []byte("sentrry")) {
		t.Errorf("the answer does not name what was not found: %s", body)
	}
	if len(asked) != 2 || asked[0] != "sentry" {
		t.Errorf("the slug did not reach the daemon intact: %v", asked)
	}
}

// A build with no listener says there is nowhere to pair, rather than
// reporting a failure. They are different facts and only one of them means
// something is broken.
func TestWithNoListenerTheRoutesSayThereIsNowhereToPair(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	res, body := h.do("GET", "/api/link", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the state route returned %d with no listener", res.StatusCode)
	}
	if !bytes.Contains(body, []byte(`"available":false`)) {
		t.Errorf("state does not report unavailable: %s", body)
	}

	res, body = h.do("POST", "/api/link/code", map[string]any{})
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("offering a code with no listener returned %d, want 404", res.StatusCode)
	}
	if !bytes.Contains(body, []byte("link_listen")) {
		t.Errorf("the answer does not say what to set: %s", body)
	}
}

// ...AND THE INTERFACE HAS TO RENDER WHAT THE SERVER SENDS.
//
// The same failure the hook credentials had: every field served correctly and
// dropped on the floor by the browser, which no API test can see because both
// halves pass while the operator gets nothing. The receipts matter most here.
// The link port answers every failure with a bare 404 on purpose, so these are
// the ONLY place a refusal has a reason -- a field served and not rendered
// would leave an operator debugging a number.
//
// The search is SCOPED to the pairing section of app.js rather than run over
// the whole file. Checked, and it matters: "available", "address", "why",
// "route", "reason", "accepted", "product", "conditions" and "holding" all
// occur elsewhere in that file for unrelated reasons, so a whole-file search
// reports nine of these sixteen fields as rendered when not one line of the
// section exists. That is a test passing for an adjacent reason, which is the
// way a guard like this usually fails.
func TestTheInterfaceRendersEveryLinkFieldTheServerSends(t *testing.T) {
	whole, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	const start = "// ---- peer link ----"
	const end = "// ---- the rail ----"
	from := bytes.Index(whole, []byte(start))
	to := bytes.Index(whole, []byte(end))
	if from < 0 || to <= from {
		t.Fatalf("app.js has no %q section ending at %q, so either the pairing "+
			"interface is gone or these markers were renamed and this test is "+
			"checking nothing", start, end)
	}
	js := whole[from:to]

	fields := []string{
		// LinkPairing
		"available", "address", "fingerprint", "expires_seconds", "peers", "receipts",
		// LinkPeerView -- "holding" and "why" are the alive-but-blind surface
		"product", "link_id", "capability", "conditions", "holding", "why",
		// LinkReceiptView
		"accepted", "duplicate", "cause", "reason", "route", "since_seconds",
		// LinkProposalView -- the amendment surface. "count" in particular:
		// a peer that fired once during its own testing and a door that has
		// been reporting something real and unheard for two days are the same
		// row without it.
		"proposals", "condition", "severity", "title", "count", "unusable",
		"overflowed",
	}
	for _, f := range fields {
		if !bytes.Contains(js, []byte(f)) {
			t.Errorf("the link state carries %q and app.js never mentions it, "+
				"so a signed-in operator is never shown it", f)
		}
	}

	// The routes themselves: a page that renders the state and cannot act on
	// it is the gap this section was built to close.
	for _, route := range []string{"/api/link/code", "/api/link/peers/", "/conditions"} {
		if !bytes.Contains(js, []byte(route)) {
			t.Errorf("app.js never calls %s, so pairing is still something that "+
				"needs a terminal", route)
		}
	}
}

// EVERY CAUSE HAS WORDS.
//
// The label is what the server counts by; the page has to turn it into what to
// do about it. A cause with no translation renders as its own slug --
// "pairing-fingerprint-mismatch" instead of "something is terminating TLS
// between you and it, stop and find out what" -- which is the label doing the
// job the sentence exists for, on the one screen where somebody is already
// stuck.
func TestEveryRefusalCauseHasSomethingAnOperatorCanRead(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(js, []byte("LINK_CAUSES")) {
		t.Fatal("app.js has no LINK_CAUSES table, so this test is checking nothing")
	}
	for _, c := range link.AllCauses() {
		if !bytes.Contains(js, []byte(`"`+string(c)+`":`)) {
			t.Errorf("refusals can be labelled %q and LINK_CAUSES has no entry for "+
				"it, so an operator is shown the slug", c)
		}
	}
}
