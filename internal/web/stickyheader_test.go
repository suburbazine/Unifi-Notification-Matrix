package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE SECTION RAIL MEASURES FROM THE HEADER, SO THE HEADER HAS TO BE THERE.
//
// watchRail() marks the last Settings section whose top is above a line drawn
// just under header.bar. That is only a line on the screen while the header is
// stuck to the top of the viewport. It was not: `html,body{height:100%}` made
// BODY exactly one viewport tall, and a sticky child is confined to its
// containing block, so the header stuck for one screenful and then scrolled
// off like anything else. Measured on the running daemon at 800x600 with the
// Peer link section in view, the header's bottom edge was 5469px ABOVE the
// viewport -- and the rail said "Consoles", eight sections behind the reader.
//
// Neither of the two tests below can see a layout: they are text assertions on
// a stylesheet and a script, and the real proof is a browser. What they can do
// is pin the two specific things that were wrong, both of which read as
// harmless in a diff and neither of which fails anything else.
func TestTheBodyIsNotConfinedToOneViewport(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("assets", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	// Comments carry the word in the explanation above; strip them first.
	bare := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAll(css, []byte(" "))

	// Every rule whose selector list names BODY, checked one declaration at a
	// time: `height` and `min-height` differ by three characters and matter
	// enormously, which is more than a regexp over the whole block can be
	// trusted to tell apart.
	for _, rule := range regexp.MustCompile(`([^{}]+)\{([^}]*)\}`).FindAllStringSubmatch(string(bare), -1) {
		named := false
		for _, sel := range strings.Split(rule[1], ",") {
			if strings.TrimSpace(sel) == "body" {
				named = true
			}
		}
		if !named {
			continue
		}
		for _, decl := range strings.Split(rule[2], ";") {
			prop, value, ok := strings.Cut(decl, ":")
			if !ok || strings.TrimSpace(prop) != "height" {
				continue
			}
			t.Errorf("`%s{height:%s}` is back. It confines header.bar's sticky box to "+
				"one screenful, the header scrolls away, and watchRail() then measures the "+
				"section rail from a line thousands of pixels above the viewport. Give BODY "+
				"min-height instead, so a short page still fills the screen and a long one "+
				"is allowed to be long.", strings.TrimSpace(rule[1]), strings.TrimSpace(value))
		}
	}
	if !regexp.MustCompile(`body\s*\{[^}]*min-height\s*:\s*100%`).Match(bare) {
		t.Error("BODY no longer carries min-height:100%, so a page with little on it " +
			"stops short of the bottom of the screen.")
	}
	if !strings.Contains(string(bare), "position:sticky") {
		t.Error("nothing in the stylesheet is sticky any more; the header and the rail both were")
	}
}

// AND THE RAIL SHOULD SURVIVE THE HEADER NOT STICKING ANYWAY.
//
// Belt and braces: whatever the stylesheet does at some width nobody measured,
// a reference line is only useful inside the viewport. Clamping the header's
// bottom edge at 0 costs nothing when the header is where it should be and is
// the whole fix when it is not. With the header forced to position:static the
// clamped line marked the right section at every one of 132 scroll positions;
// the unclamped one pointed at a section that was not on screen at all at 119
// of them.
func TestTheRailsReferenceLineStaysInsideTheViewport(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(js), "function watchRail()")
	if i < 0 {
		t.Fatal("watchRail() is gone; the section rail no longer follows the page")
	}
	body := string(js)[i:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "getBoundingClientRect") {
		t.Fatal("watchRail() no longer measures the header at all")
	}
	if !regexp.MustCompile(`Math\.max\(\s*0\s*,`).MatchString(body) {
		t.Error("watchRail() takes the header's bottom edge unclamped. A header that has " +
			"scrolled away reports a negative bottom, and the rail then marks whatever " +
			"section the reader passed several screens ago. Clamp it at 0.")
	}
	// And the other end of the same page. A line at a fixed distance from the
	// top can never be reached by the last sections -- the document runs out
	// of scroll first -- so watchRail has to know where the end of the page
	// is. Without this, Password was unreachable at every width measured, and
	// on a 1280x900 window Quiet hours was too.
	if !strings.Contains(body, "scrollHeight") {
		t.Error("watchRail() no longer looks at the height of the document, so the line " +
			"it measures from cannot come down to meet the sections at the end of the " +
			"page. Those sections can never reach a line at a fixed distance from the " +
			"top, and the rail will never mark them.")
	}
}
