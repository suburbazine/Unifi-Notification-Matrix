package web

import (
	"net/http"
	"testing"
)

// The current-password check has to be throttled like every other place a
// password is checked.
//
// It recorded its failures and never consulted them, so it could be guessed at
// full speed. Sitting behind requireAuth is not the protection it looks like:
// sessions die when the daemon restarts, so the prize for grinding this is
// turning a captured session -- there is no TLS listener and the cookie is not
// Secure -- into the password itself, which does not die, and which locks the
// operator out of their own installation.
func TestTheCurrentPasswordCannotBeGuessedAtFullSpeed(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	var refused bool
	for i := 0; i < freeAttempts+3; i++ {
		resp, _ := h.do("POST", "/api/password", map[string]string{
			"current":  "not-the-password",
			"password": "a-long-enough-new-one",
		})
		if resp.StatusCode == http.StatusTooManyRequests {
			refused = true
			break
		}
	}
	if !refused {
		t.Errorf("%d wrong current passwords in a row were all answered at full speed",
			freeAttempts+3)
	}
}
