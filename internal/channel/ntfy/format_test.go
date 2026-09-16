package ntfy

import (
	"fmt"
	"strings"
	"testing"
)

// Formatting a Channel must never print a credential.
//
// This is not hypothetical and it is not obvious. secret.Secret renders as
// <redacted> through %v -- but ONLY when fmt is allowed to call its String()
// method, and fmt refuses to call methods on values it reaches through an
// unexported struct field. Channel holds its Config unexported, so before
// Channel.String() existed, %v on a *Channel printed every credential in
// cleartext while %v on the same Config printed <redacted>.
//
// Nothing formats a *Channel today. The next diagnostic that dumps the
// configured channels is an entirely ordinary line to write, and it must not
// be the line that writes a credential into a log that outlives the incident.
//
// %#v is deliberately NOT asserted: it consults GoStringer rather than
// Stringer and leaks through a bare Config too. Fixing that belongs on
// secret.Secret, not on every type that holds one.
func TestFormattingAChannelNeverPrintsACredential(t *testing.T) {
	ch, canaries := channelWithCanaries(t)

	for _, verb := range []string{"%v", "%+v", "%s"} {
		for _, subject := range []any{ch, *ch} {
			got := fmt.Sprintf(verb, subject)
			for _, c := range canaries {
				if strings.Contains(got, c) {
					t.Errorf("%s leaked a credential: %s", verb, got)
				}
			}
			if !strings.Contains(got, "redacted") {
				t.Errorf("%s did not say anything was redacted: %s", verb, got)
			}
		}
	}
}

func channelWithCanaries(t *testing.T) (*Channel, []string) {
	t.Helper()
	const token = "NTFY-TOKEN-CANARY-MUST-NOT-LEAK"
	ch, err := New(Config{ServerURL: "https://ntfy.example", Topic: "alarms", Token: token}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ch, []string{token}
}
