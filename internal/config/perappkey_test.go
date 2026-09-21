package config

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// UniFi issues an API key PER APPLICATION. A console field that holds one key
// can therefore be right for at most one of Protect, Access and Network -- and
// on a real site the Protect key was accepted by Protect and answered 401 by
// Access, which looks from the board like Access being broken rather than like
// this product having nowhere to put its key.
func TestAConsoleCanCarryAKeyPerApplication(t *testing.T) {
	c := Console{
		APIKey:     secret.Secret("shared"),
		ProtectKey: secret.Secret("protect-only"),
		AccessKey:  secret.Secret("access-only"),
	}

	for _, tc := range []struct{ product, want string }{
		{"protect", "protect-only"},
		{"access", "access-only"},
		// Not overridden, so the console key stands: one key is still the
		// common case and must keep working untouched.
		{"network", "shared"},
	} {
		got, _ := c.KeyFor(tc.product)
		if got.Reveal() != tc.want {
			t.Errorf("KeyFor(%q) = %q, want %q", tc.product, got.Reveal(), tc.want)
		}
	}
}

// Where the key came from is shown to the operator, so it has to name the
// field they would go and edit.
func TestKeyForSaysWhereTheKeyCameFrom(t *testing.T) {
	c := Console{APIKey: secret.Secret("shared"), ProtectKey: secret.Secret("p")}

	if _, where := c.KeyFor("protect"); where == "" {
		t.Error("an application key reported no origin")
	}
	if _, where := c.KeyFor("network"); where == "" {
		t.Error("the console key reported no origin")
	}
}

// An application with no key anywhere is a source that cannot work, and the
// caller has to be able to tell that from "we have one".
func TestKeyForReportsNothingWhenThereIsNothing(t *testing.T) {
	c := Console{ProtectKey: secret.Secret("p")}
	if got, _ := c.KeyFor("access"); !got.IsZero() {
		t.Errorf("KeyFor(access) = %q, want nothing", got.Reveal())
	}
}

// The sources must actually be BUILT with them, which is the half that
// matters: a key stored and not used is the same as no key at all.
//
// Observed at the one seam where it shows. A source refuses to construct
// without a key, so a console carrying ONLY a per-application key builds that
// application and nothing else -- which is false unless BuildSources asks for
// the application's key rather than the console's.
func TestASourceIsBuiltFromItsOwnApplicationKey(t *testing.T) {
	c := Default()
	c.Consoles = []Console{{
		Name: "site", Host: "10.0.0.1",
		ProtectKey: secret.Secret("protect-only"),
		Sources:    []string{"protect"},
	}}

	srcs, problems := BuildSources(&c)
	if len(problems) != 0 {
		t.Fatalf("a console with only a Protect key could not build Protect: %v", problems)
	}
	if len(srcs) != 1 || srcs[0].Name() != "protect" {
		t.Fatalf("built %d sources %v, want protect", len(srcs), srcs)
	}
}

// And the application whose key is missing is still refused, rather than
// quietly built with somebody else's.
func TestAnApplicationWithNoKeyOfItsOwnIsStillRefused(t *testing.T) {
	c := Default()
	c.Consoles = []Console{{
		Name: "site", Host: "10.0.0.1",
		ProtectKey: secret.Secret("protect-only"),
		Sources:    []string{"protect", "access"},
	}}

	srcs, problems := BuildSources(&c)
	if len(srcs) != 1 {
		t.Errorf("built %d sources, want only the one with a key", len(srcs))
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want one naming access", problems)
	}
}

// Validation has to name the state that cost a site an evening: a source
// switched on with no key that belongs to it.
func TestValidationNamesAnApplicationWithNoKey(t *testing.T) {
	c := Default()
	c.Consoles = []Console{{
		Name: "site", Host: "10.0.0.1",
		ProtectKey: secret.Secret("protect-only"),
		Sources:    []string{"protect", "access"},
	}}

	err := c.Validate()
	if err == nil {
		t.Fatal("a source with no key of its own passed validation")
	}
	if !contains(err.Error(), "access") || !contains(err.Error(), "no key") {
		t.Errorf("validation said nothing about Access having no key: %v", err)
	}
}

// And says nothing when the console key covers what is not overridden, which
// is the configuration almost every site has.
func TestValidationIsQuietWhenOneKeyCoversEverything(t *testing.T) {
	c := Default()
	c.Consoles = []Console{{
		Name: "site", Host: "10.0.0.1",
		APIKey:  secret.Secret("one-key"),
		Sources: []string{"protect", "access", "network"},
	}}

	if err := c.Validate(); err != nil && contains(err.Error(), "no key") {
		t.Errorf("a single-key console was warned about: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return len(sub) == 0
}
