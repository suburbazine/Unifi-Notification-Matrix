package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// "TAKES EFFECT WHEN THE SERVICE RESTARTS" IS NOW TRUE OF EXACTLY ONE SECTION.
//
// Every Save used to append that sentence, because it was true of every Save:
// channels, ladders, rules, quiet hours, hooks and consoles were all built once
// when the daemon started. They are rebuilt as they are saved now, and an
// instruction that is usually unnecessary is one an operator stops reading --
// which matters on the day it is necessary.
//
// The listen addresses are the real exception: a socket that is already bound
// cannot be moved under the connections using it. That section keeps the
// offer, and only when one of the address fields actually changed, because
// ack_base_url sits in the same section and needs nothing.
//
// A text assertion on a script, like its neighbours, and the real proof was a
// browser: saving Quiet hours said "Saved, and in effect now", saving Web
// after changing the listen address offered the restart, and saving Web again
// without changing it did not.
func TestOnlyTheListenAddressesStillAskForARestart(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)

	i := strings.Index(src, "var SECTION_SAVES = {")
	if i < 0 {
		t.Fatal("SECTION_SAVES is gone; this test no longer describes the page")
	}
	block := src[i:]
	if end := strings.Index(block, "\n};"); end > 0 {
		block = block[:end]
	}

	// Which sections claim a restart, by the descriptor they sit in.
	var claiming []string
	for _, m := range regexp.MustCompile(`(?m)^  (\w+): \{`).FindAllStringSubmatchIndex(block, -1) {
		name := block[m[2]:m[3]]
		body := block[m[1]:]
		if next := regexp.MustCompile(`(?m)^  \w+: \{`).FindStringIndex(body); next != nil {
			body = body[:next[0]]
		}
		if strings.Contains(body, "restart:") {
			claiming = append(claiming, name)
		}
	}

	if len(claiming) != 1 || claiming[0] != "web" {
		t.Errorf("sections still telling the operator to restart: %v, want only [web]. "+
			"Everything else is applied to the running daemon as it is saved, and a "+
			"restart notice on a change that is already in force teaches people to "+
			"ignore the one that is not.", claiming)
	}

	if !strings.Contains(block, "restartIf:") {
		t.Error("the web section offers a restart unconditionally. ack_base_url lives " +
			"in that section and takes effect immediately; only listen, ack_listen and " +
			"link_listen need the daemon stopped.")
	}
	for _, field := range []string{"listen", "ack_listen", "link_listen"} {
		if !regexp.MustCompile(`restartIf:(?s).*?\b` + field + `\b`).MatchString(block) {
			t.Errorf("restartIf does not look at %s, so changing it would say the "+
				"change is already in force while the daemon is still bound to the "+
				"old address", field)
		}
	}

	// And the other half of the sentence has to exist, or a Save that needs no
	// restart says nothing at all and reads as a Save that did not happen.
	if !strings.Contains(src, "function appliedNotice(") {
		t.Error("appliedNotice() is gone; a Save with nothing left to do now confirms nothing")
	}
}
