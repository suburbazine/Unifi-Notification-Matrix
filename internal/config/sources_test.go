package config

import (
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

func consoleWith(sources ...string) *Config {
	return &Config{Consoles: []Console{{
		Name: "site", Host: "10.0.0.1", APIKey: secret.Secret("k"), Sources: sources,
	}}}
}

// The whole reason this file exists: a source that is never constructed is a
// product that looks healthy while watching nothing.
func TestEveryEnabledSourceIsBuilt(t *testing.T) {
	got, problems := BuildSources(consoleWith("protect", "access"))
	if len(problems) != 0 {
		t.Fatalf("problems = %v", problems)
	}
	names := []string{}
	for _, s := range got {
		names = append(names, s.Name())
	}
	if len(names) != 2 || names[0] != "access" || names[1] != "protect" {
		t.Errorf("built %v, want both sources", names)
	}
}

// One broken entry must not remove coverage that works: a site whose Access
// key is wrong still wants its cameras watched.
func TestABrokenEntryDoesNotCostTheConsoleItsOtherSources(t *testing.T) {
	c := consoleWith("protect", "access")
	c.Consoles = append(c.Consoles, Console{Name: "broken", Host: "", Sources: []string{"access"}})

	got, problems := BuildSources(c)
	if len(got) != 2 {
		t.Errorf("built %d source(s), want the two that could be built", len(got))
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly the one that failed", problems)
	}
	if !strings.Contains(problems[0].Error(), "broken") {
		t.Errorf("the problem does not name the console: %v", problems[0])
	}
}

// `network` is warned about by Config.Warnings and must not be reported twice.
func TestTheUnimplementedNetworkSourceIsNotReportedTwice(t *testing.T) {
	got, problems := BuildSources(consoleWith("protect", "network"))
	if len(got) != 1 {
		t.Errorf("built %d source(s), want protect", len(got))
	}
	if len(problems) != 0 {
		t.Errorf("problems = %v; Config.Warnings already says this, and a fact "+
			"printed twice in one second teaches the reader that warnings repeat", problems)
	}
}

// A typo IS reported here: it is not a known source at all, and a typo
// silently watching nothing is the failure this guards against.
func TestAMisspelledSourceIsReported(t *testing.T) {
	_, problems := BuildSources(consoleWith("protekt"))
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want one naming the typo", problems)
	}
	if !strings.Contains(problems[0].Error(), "protekt") {
		t.Errorf("problem = %v", problems[0])
	}
}
