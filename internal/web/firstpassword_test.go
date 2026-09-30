package web

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// A FRESH INSTALL OPENED STRAIGHT ONTO SETTINGS OFFERS THE FIRST PASSWORD.
//
// refreshAll asks for the status and the tab side by side. On Settings the
// settings request's 401 usually lands first, so the sign-in card was drawn
// while setupRequired was still its initial false -- "Password", with nowhere
// to put the setup token -- and nothing redrew it when the status said
// otherwise. Seen in a browser on a scratch install: typing the token into
// that box answered "no password is set yet; use the setup token".
//
// Text assertions, as with the other page tests; the proof was a browser,
// where a real reload onto #settings of a fresh data directory now shows "Set
// the first password" with the Setup token field.
func TestTheSignInCardIsRedrawnWhenSetupTurnsOutToBeRequired(t *testing.T) {
	js, err := os.ReadFile(filepath.Join("assets", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	status := fnBody(string(js), "function refreshStatus(")
	if status == "" {
		t.Fatal("refreshStatus() is gone; this test no longer describes the page")
	}
	if !regexp.MustCompile(`wasSetup\s*=\s*state\.setupRequired`).MatchString(status) {
		t.Error("refreshStatus() does not remember whether setup was required before " +
			"this answer, so it cannot tell that the card on screen is the wrong one")
	}
	if !regexp.MustCompile(`wasSetup\s*!==\s*state\.setupRequired\)\s*refreshTab\(\)`).MatchString(status) {
		t.Error("refreshStatus() does not redraw the tab when setup turns out to be " +
			"required, and a fresh install loaded onto Settings offers a password box " +
			"that no password can open")
	}
}
