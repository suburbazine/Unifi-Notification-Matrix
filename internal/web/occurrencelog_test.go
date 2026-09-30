package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE BOARD SAYS HOW MANY TIMES IT HAPPENED, AND OPENS THE LIST.
//
// A per-occurrence condition -- a sale voided at a register, a reward applied
// with nothing earned -- folds every arrival into one live incident, and the
// incident's own title and detail follow the NEWEST arrival. That is right for
// the alert and exactly what hides the others: a manager reading "Sale voided
// at Register 1" with one invoice under it sees one void when there were
// seven. So the card carries the count as a chip, and the chip opens the list
// of every arrival the incident kept, from GET /api/incidents/{id}/occurrences.
//
// The board redraws every few seconds and a redraw replaces every card. An
// earlier attempt at a panel inside a card was wiped by the redraw and then
// re-inserted in the wrong place; this one is re-opened from state into a
// mount the card places for it, above its own buttons, so it stays put.
//
// As with stickytabs_test.go and savenotice_test.go these are text
// assertions on a script and a stylesheet, and the real proof was a browser:
// at 1280x720 and at phone width the void card read "7 occurrences since
// 02:24 AM", pressing it listed all seven newest first with the register chip
// and no repeated time, the list was still there in the same slot after two
// redraws, the 112-arrival card said "The latest 100 of 112. Older ones are
// not kept; the count is." with a "Show the other 90" that also survived a
// redraw, and the fresh void card said "follows an incident reviewed at 01:30
// AM". What the tests pin is what a regression would silently remove.
func TestTheCardCountsOccurrencesAndOpensTheList(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)

	card := fnBody(src, "function incidentCard(")
	if card == "" {
		t.Fatal("incidentCard() is gone; this test no longer describes the board")
	}
	// The chip, and only past one. Every ordinary incident answers
	// occurrences: 1, and "1 occurrence" on a door left open is noise that
	// would teach people to stop reading chips.
	if !regexp.MustCompile(`inc\.occurrences\s*>\s*1\b`).MatchString(card) {
		t.Error("incidentCard() does not gate the count on inc.occurrences > 1. Either the " +
			"chip is gone and a run of seven voids reads as one void, or it is on every " +
			"card and says \"1 occurrences\" about a door.")
	}
	if !strings.Contains(card, `"occ-mount"`) {
		t.Error("incidentCard() no longer places an .occ-mount for the list. Without a " +
			"fixed slot the list is appended wherever the click happens to put it, and " +
			"a redraw puts it somewhere else.")
	}
	// Re-opened from state on every redraw, like the silence panel.
	if !strings.Contains(card, "state.occurrences") || !strings.Contains(card, "occurrencePanel(") {
		t.Error("incidentCard() does not re-open the occurrence list from state.occurrences. " +
			"The board redraws every REFRESH_MS and replaces the card; a list that is " +
			"not re-opened from state is wiped five seconds after it is opened.")
	}

	panel := fnBody(src, "function occurrencePanel(")
	if panel == "" {
		t.Fatal("occurrencePanel() is gone; the count no longer opens anything")
	}
	if !strings.Contains(panel, `"/occurrences"`) || !strings.Contains(panel, "encodeURIComponent(inc.id)") {
		t.Error("occurrencePanel() does not fetch api/incidents/<id>/occurrences with the id " +
			"encoded. That route is the only place every kept arrival can be read from.")
	}

	list := fnBody(src, "function occurrenceList(")
	if list == "" {
		t.Fatal("occurrenceList() is gone")
	}
	// The count is exact and the list is capped; the page has to say so, or
	// a hundred rows read as a hundred voids.
	if !strings.Contains(list, "data.kept") || !strings.Contains(list, "not kept") {
		t.Error("occurrenceList() no longer compares the count with the API's kept cap and says " +
			"that older ones are not kept. Past a hundred arrivals the list is the newest " +
			"hundred, and a list that does not say so implies it is complete.")
	}
	// Newest first is the API's order; the row's title is shown only where it
	// differs from the row above, and the card's title is the row above the
	// first row.
	if !strings.Contains(list, "prevTitle = inc.title") {
		t.Error("occurrenceList() no longer starts the title comparison from the incident's " +
			"own title, so the first row repeats the title the card already shows")
	}

	// The predecessor is said in words, not as an id.
	if strings.Contains(card, `"recurrence of " + inc.predecessor_id`) {
		t.Error("incidentCard() prints the predecessor as a bare id again. A fresh void " +
			"card follows one that was reviewed, and \"recurrence of inc-8f3a\" says nothing " +
			"a manager can use.")
	}
	if !strings.Contains(card, "predecessorNote(inc)") {
		t.Error("incidentCard() does not call predecessorNote(); the relationship between " +
			"a reviewed run of voids and the fresh one that followed it is invisible")
	}
	note := fnBody(src, "function predecessorNote(")
	if !strings.Contains(note, "reviewed") {
		t.Error("predecessorNote() no longer distinguishes a predecessor closed by review " +
			"from one that cleared and came back")
	}

	// And boardIndex is filled before the cards are drawn, or predecessorNote
	// looks the predecessor up in an empty map every time.
	refresh := fnBody(src, "function refreshIncidents(")
	if !strings.Contains(refresh, "boardIndex[inc.id] = inc") {
		t.Error("refreshIncidents() does not fill boardIndex; predecessorNote() can never find the predecessor")
	}
}

// AND THE CHIP LOOKS LIKE THE ONE CHIP THAT DOES SOMETHING.
func TestTheOccurrenceChipIsStyledAsAControl(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("assets", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	top := cssRules(string(css))[""]
	if top[".occ-toggle"] == "" {
		t.Fatal(".occ-toggle has no rule; the count renders as an unstyled button")
	}
	if decl(top, ".occ-toggle", "cursor") != "pointer" {
		t.Error(".occ-toggle{cursor} is not pointer; the one fact chip that opens something has to say so")
	}
	if decl(top, `.occ-toggle[aria-expanded="true"]`, "background") == "" {
		t.Error(`.occ-toggle[aria-expanded="true"] does not change the fill; an open list and a closed one look the same`)
	}
	if top[".occurrences"] == "" || top[".occ"] == "" {
		t.Error("the list's rules (.occurrences, .occ) are gone")
	}
}

// fnBody returns the source of the function whose declaration starts with
// head, up to the first line that is a lone closing brace, or "" if absent.
func fnBody(src, head string) string {
	i := strings.Index(src, head)
	if i < 0 {
		return ""
	}
	body := src[i:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	return body
}
