package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE TAB BAR IS STUCK UNDER THE HEADER, AND EVERYTHING ELSE HAS TO KNOW.
//
// The pages under the tabs are long -- Settings runs past eight thousand
// pixels -- and a tab bar at the top of the document is one the reader has to
// scroll all the way back up to. So nav.tabs is position:sticky beneath
// header.bar. That alone is a three-line change, and on its own it breaks
// three other things, each of which was keyed off the header's height alone:
//
//   - .rail, the Settings section rail, stuck at --header-h + 12px, which is
//     now under the tab bar and covered by it;
//   - [id]{scroll-margin-top}, so a rail click landed the section heading
//     behind the tabs;
//   - watchRail() in app.js, which measured its reference line from the
//     header's bottom edge -- forty pixels above the real bottom of the chrome
//     -- and so marked a section whose heading was behind the tab bar.
//
// And on a phone the header does not stick at all: three stacked bars
// (header, tabs, chip strip) on one short screen was too many, so the header
// scrolls away, the tabs stick at the very top and the chip strip under them.
// That makes the chrome a different height at phone width, which is why it is
// a token, --chrome-h, redefined in the phone media block, and why the anchor
// targets there clear the strip as well.
//
// As with stickyheader_test.go these are text assertions on a stylesheet and
// a script, and the real proof was a browser: at 1280x900 and at phone width
// the rail marked all ten sections in document order, never going back, with
// the tab bar still on screen at the very bottom of the page, and
// #settings/escalation landed its heading 12px (desktop) and 8px (phone)
// under the chrome. What the tests pin is the arithmetic, which reads as
// harmless when it drifts back.

// cssRules splits a stylesheet into rules. The top-level rules are returned
// under "", and the rules inside the phone media block under its prelude;
// other @media blocks are skipped. Comments are stripped first. Where a
// selector appears twice in the same scope the later declarations win, which
// is what the cascade does too.
func cssRules(css string) map[string]map[string]string {
	css = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, " ")
	out := map[string]map[string]string{"": {}}
	var walk func(src, scope string)
	walk = func(src, scope string) {
		for {
			open := strings.IndexByte(src, '{')
			if open < 0 {
				return
			}
			sel := strings.TrimSpace(src[:open])
			// The balancing close brace.
			depth, end := 0, -1
			for i := open; i < len(src); i++ {
				switch src[i] {
				case '{':
					depth++
				case '}':
					depth--
				}
				if depth == 0 {
					end = i
					break
				}
			}
			if end < 0 {
				return
			}
			body := src[open+1 : end]
			src = src[end+1:]
			if strings.HasPrefix(sel, "@media") {
				if sel == "@media (max-width:760px)" {
					walk(body, sel)
				}
				continue
			}
			if out[scope] == nil {
				out[scope] = map[string]string{}
			}
			for _, one := range strings.Split(sel, ",") {
				one = strings.TrimSpace(one)
				prev := out[scope][one]
				if prev != "" {
					prev += ";"
				}
				out[scope][one] = prev + strings.TrimSpace(body)
			}
		}
	}
	walk(css, "")
	return out
}

// decl is the value of one property in one rule, or "" when it is not set.
func decl(rules map[string]string, selector, prop string) string {
	for _, d := range strings.Split(rules[selector], ";") {
		p, v, ok := strings.Cut(d, ":")
		if ok && strings.TrimSpace(p) == prop {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func TestTheTabsStickUnderTheHeaderAndTheOffsetsBelowThemKnowIt(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("assets", "style.css"))
	if err != nil {
		t.Fatal(err)
	}
	sheet := cssRules(string(css))
	top := sheet[""]
	phone := sheet["@media (max-width:760px)"]
	if phone == nil {
		t.Fatal("the phone media block, @media (max-width:760px), is gone; the chip strip and the one-bar chrome live there")
	}

	// The tab bar sticks, directly under the header.
	if decl(top, "nav.tabs", "position") != "sticky" {
		t.Error("nav.tabs is not position:sticky. The tab bar scrolls off the top of an " +
			"eight-thousand-pixel Settings page and the reader has to scroll back up to " +
			"change tabs, which is the complaint this was built for.")
	}
	if got := decl(top, "nav.tabs", "top"); got != "var(--header-h)" {
		t.Errorf("nav.tabs{top:%s}; it sticks at var(--header-h), the underside of the header", got)
	}
	// Its height is a token, and it must not be allowed to grow past it,
	// because everything under it is offset by arithmetic rather than by
	// measuring. A bar that wraps to two rows is a bar twice as tall as the
	// stylesheet thinks it is.
	if got := decl(top, "nav.tabs", "height"); got != "var(--tabs-h)" {
		t.Errorf("nav.tabs{height:%s}; the bar's height is the --tabs-h token, so that --chrome-h can be arithmetic", got)
	}
	if got := decl(top, "nav.tabs", "flex-wrap"); got != "nowrap" {
		t.Errorf("nav.tabs{flex-wrap:%s}; tabs that wrap make the bar taller than --tabs-h says, and every offset under it is then wrong", got)
	}

	// The chrome token, and the two offsets that key off it.
	if decl(top, ":root", "--tabs-h") == "" {
		t.Error("--tabs-h is not defined on :root")
	}
	chrome := decl(top, ":root", "--chrome-h")
	if !strings.Contains(chrome, "--header-h") || !strings.Contains(chrome, "--tabs-h") {
		t.Errorf(":root{--chrome-h:%s}; at desktop width the chrome is the header and the tab bar together", chrome)
	}
	for sel, prop := range map[string]string{".rail": "top", "[id]": "scroll-margin-top"} {
		got := decl(top, sel, prop)
		if !strings.Contains(got, "--chrome-h") || strings.Contains(got, "--header-h") {
			t.Errorf("%s{%s:%s} is keyed off the header alone. Under a stuck tab bar that puts "+
				"the rail forty pixels behind the tabs and lands an anchored section heading "+
				"behind them; key it off --chrome-h.", sel, prop, got)
		}
	}

	// On a phone: one bar, not three. The header scrolls away, the tabs stick
	// at the top, the chrome is the tab bar alone, and the chip strip -- stuck
	// under the tabs -- is cleared by the anchor targets too.
	if got := decl(phone, "header.bar", "position"); got != "static" {
		t.Errorf("at phone width header.bar{position:%q}; it should be static so the header "+
			"scrolls away and a phone has two bars stuck to its one short screen, not three", got)
	}
	if got := decl(phone, "nav.tabs", "top"); got != "0" {
		t.Errorf("at phone width nav.tabs{top:%s}; with the header scrolling away the tabs stick at 0", got)
	}
	if got := decl(phone, ":root", "--chrome-h"); got == "" || strings.Contains(got, "--header-h") {
		t.Errorf("at phone width :root{--chrome-h:%s}; the header is not stuck there, so the chrome "+
			"must not count it, or the chip strip and every anchor land 46px too low", got)
	}
	if got := decl(phone, ".rail", "top"); !strings.Contains(got, "--chrome-h") {
		t.Errorf("at phone width .rail{top:%s}; the chip strip sticks at --chrome-h, the underside of the tabs", got)
	}
	if got := decl(phone, ".rail", "height"); got != "var(--strip-h)" {
		t.Errorf("at phone width .rail{height:%s}; the strip's height is the --strip-h token so the anchors can clear it", got)
	}
	if got := decl(phone, ".railed [id]", "scroll-margin-top"); !strings.Contains(got, "--chrome-h") || !strings.Contains(got, "--strip-h") {
		t.Errorf("at phone width .railed [id]{scroll-margin-top:%s}; a Settings anchor has to clear "+
			"the tabs AND the chip strip stuck under them, or the section heading lands behind the chips", got)
	}
}

// AND THE RAIL MEASURES FROM THE BOTTOM OF THE CHROME, NOT THE HEADER.
//
// The clamp and the scrollHeight term are pinned next door in
// stickyheader_test.go and still apply. What this pins is which element the
// line is drawn under: the tab bar is the lowest band stuck to the top at
// every width, and the header is not even stuck on a phone. Measured from the
// header, the line sat inside the tab bar and the rail marked a section whose
// heading was already hidden behind it.
func TestTheRailMeasuresFromTheTabBar(t *testing.T) {
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
	if !strings.Contains(body, `querySelector("nav.tabs")`) {
		t.Error("watchRail() no longer measures its reference line from nav.tabs, the lowest " +
			"band of the stuck chrome; the rail will mark sections whose headings are behind it")
	}
	if strings.Contains(body, `querySelector("header.bar")`) {
		t.Error("watchRail() measures from header.bar again. The header's bottom edge is forty " +
			"pixels above the bottom of the chrome at desktop width, and on a phone the header " +
			"is not stuck at all; measure from nav.tabs.")
	}
}
