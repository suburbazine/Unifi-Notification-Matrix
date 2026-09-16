package config

import (
	"os"
	"strings"
	"testing"
)

func hookConfig(h ...Hook) *Config {
	c := workable()
	c.Hooks = h
	return &c
}

// A hook needs BOTH credentials or it is not served at all.
//
// The token in the URL says which hook; the bearer header says the caller is
// really the console. Either one missing means an endpoint that is either
// unreachable or unauthenticated, and an unauthenticated one is a URL anybody
// who learns it can feed false alarms to.
func TestAHookNeedsBothCredentialsToBeServed(t *testing.T) {
	const tok = "a-perfectly-long-token-value"
	const bearer = "a-perfectly-long-bearer-value"

	got := BuildHooks(hookConfig(
		Hook{Name: "wan", Token: tok, Bearer: bearer},
		Hook{Name: "no-token", Bearer: bearer},
		Hook{Name: "no-bearer", Token: tok},
		Hook{Name: "neither"},
	))
	if len(got) != 1 {
		names := []string{}
		for _, h := range got {
			names = append(names, h.Name)
		}
		t.Fatalf("built %v, want only the fully-credentialled hook", names)
	}
	if got[0].Name != "wan" {
		t.Errorf("built %q", got[0].Name)
	}
	if got[0].Bearer.Reveal() != bearer {
		t.Error("the bearer did not reach the receiver, so the hook would refuse everything")
	}
}

// Generated tokens are 32 random bytes. A short one is the operator having
// invented their own, and inventing one is how short secrets happen.
func TestAShortTokenIsRefused(t *testing.T) {
	c := hookConfig(Hook{Name: "wan", Token: "short"})
	err := c.Validate()
	if err == nil {
		t.Fatal("a five-character token was accepted on an endpoint that can raise an alarm")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error = %v", err)
	}

	// An absent token is fine: one is generated on save.
	if err := hookConfig(Hook{Name: "wan"}).Validate(); err != nil {
		t.Errorf("a hook awaiting a generated token was refused: %v", err)
	}
}

// THE ONE THAT MAKES A HAND-ADDED HOOK WORK. Without this, an operator adds a
// hook, restarts, and gets a configuration that looks complete and silently
// receives nothing -- no token, no URL, no endpoint.
func TestSavingGeneratesAMissingHookToken(t *testing.T) {
	dir := t.TempDir()
	c := hookConfig(Hook{Name: "wan", Product: "network"})

	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	if c.Hooks[0].Token.IsZero() {
		t.Fatal("no token was generated, so the hook has no URL and will never receive anything")
	}
	if c.Hooks[0].Bearer.IsZero() {
		t.Fatal("no bearer was generated, so the hook would refuse everything the console sends")
	}
	if c.Hooks[0].Token.Reveal() == c.Hooks[0].Bearer.Reveal() {
		t.Error("the URL token and the bearer are the same value; two credentials " +
			"that are one credential is one credential")
	}
	if n := len(c.Hooks[0].Token.Reveal()); n < 32 {
		t.Errorf("token is %d characters; it is the only thing protecting this endpoint", n)
	}

	// And it is stable across a reload -- a token that changed on every start
	// would invalidate the URL already pasted into the Alarm Manager rule.
	first := c.Hooks[0].Token.Reveal()
	back, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Hooks) != 1 || back.Hooks[0].Token.Reveal() != first {
		t.Errorf("the token changed across a reload; the URL in the console would stop working")
	}
}

// LoadOrCreate mints one for a hook added by hand, because reading a config
// must have no side effect but opening one to USE it may.
//
// Written as raw YAML on purpose: Save always mints tokens, so the only way to
// produce a tokenless file is the way an operator does -- by editing it.
func TestOpeningAConfigMintsATokenForAHandAddedHook(t *testing.T) {
	dir := t.TempDir()
	const handEdited = `version: 1
hooks:
  - name: wan
    product: network
    condition: wan-down
web:
  listen: 127.0.0.1:8322
`

	if err := os.WriteFile(Path(dir), []byte(handEdited), 0o600); err != nil {
		t.Fatal(err)
	}

	back, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Hooks) != 1 {
		t.Fatalf("hooks = %d", len(back.Hooks))
	}
	if back.Hooks[0].Token.IsZero() || back.Hooks[0].Bearer.IsZero() {
		t.Fatalf("a hand-added hook was left without both credentials, so it "+
			"silently receives nothing: %+v", back.Hooks[0])
	}
	if len(BuildHooks(back)) != 1 {
		t.Error("the hook still is not served")
	}
}
