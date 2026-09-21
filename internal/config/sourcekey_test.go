package config

import (
	"strings"
	"testing"
)

// WHAT COUNTS AS "THE SAME SOURCE" WHEN THE CONFIGURATION IS RELOADED.
//
// The daemon rebuilds its sources on every save and hands the supervisor back
// the SAME value for anything nobody changed, so an unrelated edit does not
// cost a console its WebSocket. That decision is this key, and the failure it
// has to avoid is specific: every Protect source is named "protect", so a
// source built from a corrected API key is indistinguishable by name from the
// broken one it replaces. Miss a field here and the daemon keeps the broken
// one, reports it as running, and watches nothing.
func TestTheSourceKeyChangesWhenAnythingAboutTheConnectionDoes(t *testing.T) {
	base := Console{
		Name: "Head office", Host: "10.0.0.1",
		APIKey:      "console-key-aaaaaaaaaaaa",
		Fingerprint: "AA:BB:CC",
		Sources:     []string{"protect", "access"},
	}
	start := sourceKey(base, "protect")

	if start == "" {
		t.Fatal("the key is empty, so every source looks like every other")
	}
	if got := sourceKey(base, "protect"); got != start {
		t.Fatal("the same console produced two different keys, so nothing would " +
			"ever be treated as unchanged and every save would drop every connection")
	}

	for _, tc := range []struct {
		what   string
		change func(*Console)
		why    string
	}{
		{"the host", func(c *Console) { c.Host = "10.0.0.2" },
			"a different console entirely"},
		{"the console key", func(c *Console) { c.APIKey = "console-key-bbbbbbbbbbbb" },
			"the credential it authenticates with"},
		{"this application's own key", func(c *Console) { c.ProtectKey = "protect-key-cccccccccccc" },
			"Protect is given its own key, and it is a different credential"},
		{"the pinned fingerprint", func(c *Console) { c.Fingerprint = "DD:EE:FF" },
			"a different certificate is trusted"},
		{"skipping verification", func(c *Console) { c.InsecureSkipVerify = true },
			"the connection is no longer checked"},
	} {
		next := base
		tc.change(&next)
		if sourceKey(next, "protect") == start {
			t.Errorf("changing %s did not change the key, so a reload would keep the "+
				"source built from the OLD one running -- %s", tc.what, tc.why)
		}
	}

	// Two applications on one console are two connections.
	if sourceKey(base, "protect") == sourceKey(base, "access") {
		t.Error("Protect and Access on the same console share a key, so reloading " +
			"one would be taken for the other")
	}

	// And the key must not be the credential. It goes into a map, a log line
	// and an audit field; a secret that travels in those is a secret leaked by
	// the mechanism meant to avoid touching it.
	if strings.Contains(start, "console-key") || strings.Contains(start, base.Host) {
		t.Errorf("the key carries the credential or the host verbatim: %q", start)
	}
}
