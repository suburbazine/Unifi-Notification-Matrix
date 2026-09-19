package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE BOARD IS THE THING THAT LIES, AND IT IS PUBLIC.
//
// When the daemon runs on the equipment it watches, "all clear" and "this died
// an hour ago and cannot tell you" render identically. A wall display is
// exactly who needs the caveat, and a wall display is signed out -- so this
// travels on the public status payload beside the incident counts, the way the
// demo banner does.
func TestTheSelfWatchWarningReachesASignedOutBoard(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.srv.deps.SelfWatch = func() SelfWatch {
		return SelfWatch{AtRisk: true, Detail: "cannot report its own failure"}
	}

	res, body := h.do("GET", "/api/status", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !bytes.Contains(body, []byte("cannot report its own failure")) {
		t.Errorf("a signed-out board is not told: %s", body)
	}
	var got struct {
		SelfWatch SelfWatch `json:"self_watch"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.SelfWatch.AtRisk {
		t.Error("at_risk did not survive the wire")
	}
}

// AND IT SAYS NOTHING ABOUT THE HARDWARE OR THE REMEDY.
//
// This reaches anybody who can see the board. That the installation cannot
// report its own failure is something an operator must know; which box it runs
// on, and what would fix it, is detail that belongs behind the password.
func TestThePublicWarningDoesNotDescribeTheDeployment(t *testing.T) {
	// The real sentence, taken from the daemon rather than invented here, so
	// this fails if somebody rewrites it into a topology description.
	main, err := os.ReadFile(filepath.Join("..", "..", "cmd", "notifymatrix", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	const marker = "This installation runs on the equipment it is "
	i := bytes.Index(main, []byte(marker))
	if i < 0 {
		t.Fatal("the public self-watch sentence is gone or was reworded; if it " +
			"moved, point this test at it rather than deleting the check")
	}
	sentence := string(main[i : i+600])
	if j := strings.Index(sentence, `",`); j > 0 {
		sentence = sentence[:j]
	}
	for _, leak := range []string{"UniFi", "gateway", "UCG", "UDM", "/data", "peer", "Xtremission Link"} {
		if strings.Contains(sentence, leak) {
			t.Errorf("the public banner mentions %q; it reaches anybody who can "+
				"see the board and should name the limitation, not the "+
				"deployment or the fix:\n%s", leak, sentence)
		}
	}
}

// A BUILD THAT SAYS NOTHING IS THE NORMAL CASE.
//
// Every deployment where the daemon runs somewhere other than the equipment it
// watches has nothing to warn about, and a banner that appears everywhere is a
// banner nobody reads.
func TestNothingIsSaidWhenThereIsNothingToSay(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)

	_, body := h.do("GET", "/api/status", nil)
	var got struct {
		SelfWatch SelfWatch `json:"self_watch"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.SelfWatch.AtRisk || got.SelfWatch.Detail != "" {
		t.Errorf("warned with no SelfWatch dependency wired: %+v", got.SelfWatch)
	}
}

// THE PAGE HAS TO RENDER IT, and clear it again.
//
// The server half passing while the browser drops the field is the failure
// this product has hit twice. Scoped to the banner function so the check
// cannot pass on an unrelated occurrence of the same word.
func TestTheInterfaceRendersAndClearsTheSelfWatchBanner(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	const start = "function renderSelfWatchBanner("
	const end = "// ---------- outbound webhooks ----------"
	from := bytes.Index(js, []byte(start))
	to := bytes.Index(js, []byte(end))
	if from < 0 || to <= from {
		t.Fatalf("app.js has no %q ending at %q, so either the banner is gone "+
			"or these markers were renamed and this test checks nothing", start, end)
	}
	body := string(js[from:to])

	for _, field := range []string{"at_risk", "detail"} {
		if !strings.Contains(body, field) {
			t.Errorf("the banner never reads %q, so the server's answer is dropped", field)
		}
	}
	// Clearing is the half that makes it worth fixing rather than ignoring.
	if !strings.Contains(body, "removeChild") {
		t.Error("the banner is never removed, so pairing a peer would not " +
			"clear it and an operator who fixed the problem would still be " +
			"warned about it")
	}
	// And it must be called on every poll, not once at load.
	if !bytes.Contains(js, []byte("renderSelfWatchBanner(state.selfWatch)")) {
		t.Error("the banner is not re-rendered from the status poll, so it " +
			"would neither appear nor clear without a reload")
	}
}
