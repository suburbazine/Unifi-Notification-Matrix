package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The wall display says so, without a sign-in -- and says only how many.
func TestTheStatusSaysADecisionIsWaiting(t *testing.T) {
	h := newHarness(t)
	h.srv.deps.PendingDecisions = func() PendingDecisions { return PendingDecisions{Kinds: 2, Refused: 14} }

	_, raw := h.do("GET", "/api/status", nil)
	var st struct {
		Decisions PendingDecisions `json:"decisions"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Decisions.Kinds != 2 || st.Decisions.Refused != 14 {
		t.Errorf("status decisions = %+v, want 2 kinds / 14 refused", st.Decisions)
	}
}

// Every tab, the Settings count, the receipt, and the card.
func TestADecisionWaitingIsHardToMiss(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)

	if !strings.Contains(fnBody(src, "function refreshStatus("), "renderDecisionsBanner(d.decisions)") {
		t.Error("the status poll does not draw the decisions banner, so a refused " +
			"release is visible only to somebody already in Peer link")
	}
	banner := fnBody(src, "function renderDecisionsBanner(")
	if !strings.Contains(banner, `setTabCount("settings", kinds || "", "err")`) {
		t.Error("the Settings tab does not carry the count of decisions waiting")
	}
	if !regexp.MustCompile(`if \(!kinds\) \{`).MatchString(banner) ||
		!strings.Contains(banner, "removeChild(existing)") {
		t.Error("the banner is not removed once nothing is waiting")
	}
	// Rebuilt on every poll, the link went stale under the cursor in the
	// browser check.
	if !strings.Contains(banner, "if (existing) { existing.firstChild.nodeValue = said; return; }") {
		t.Error("the banner is rebuilt on every status poll instead of updated in place")
	}
	if !strings.Contains(banner, `a.href = "#settings/link"`) {
		t.Error("the banner does not take the operator to the decision")
	}

	receipts := fnBody(src, "function receiptsCard(")
	if !regexp.MustCompile(`if \(r\.cause === "undeclared-condition"\) why\.appendChild\(decideButton\(\)\)`).
		MatchString(receipts) {
		t.Error("a refusal for an undeclared condition has no way to the decision it is waiting on")
	}

	// Where the banner lands. In the browser, following it arrived at the
	// fingerprint, with the decision three cards further down.
	section := fnBody(src, "function renderLinkSection(")
	first := strings.Index(section, "if (pending.length) body.appendChild(proposalsCard(pending))")
	where := strings.Index(section, `"What the peer needs"`)
	if first < 0 || where < 0 || first > where {
		t.Error("a waiting decision is not the first thing in the Peer link section")
	}

	card := fnBody(src, "function proposalsCard(")
	if !strings.Contains(card, `card.id = "link-decisions"`) {
		t.Error("the decisions card has no id for the banner and the receipts to land on")
	}
	if !regexp.MustCompile(`callout\(\s*"These events are being REFUSED`).MatchString(card) {
		t.Error("the decisions card no longer leads with a warning that events are being refused")
	}
}
