package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

const hookTokenCanary = "TOKEN-CANARY-must-never-appear-in-settings"
const hookBearerCanary = "BEARER-CANARY-must-never-appear-in-settings"

func configWithHook() *config.Config {
	c := testConfig()
	c.Hooks = []config.Hook{{
		Name: "wan", Product: "network", Condition: "wan_down",
		Severity: "high", Entity: "WAN",
		Token: hookTokenCanary, Bearer: hookBearerCanary,
	}}
	return c
}

// The URL carries the token and the header carries the bearer. Both are shown
// on the setup checklist, behind a session, and deliberately nowhere else: a
// credential with two ways out has two ways to leak, and every extra copy is
// another thing to get the gating right on.
func TestTheSettingsViewCarriesNoHookCredentials(t *testing.T) {
	v := viewSettings(configWithHook())

	if len(v.Hooks) != 1 {
		t.Fatalf("got %d hooks, want 1", len(v.Hooks))
	}
	if !v.Hooks[0].TokenSet || !v.Hooks[0].BearerSet {
		t.Error("the view does not report that the credentials exist, so the " +
			"operator cannot tell a configured hook from a broken one")
	}

	rendered := renderToString(t, v)
	for _, canary := range []string{hookTokenCanary, hookBearerCanary} {
		if strings.Contains(rendered, canary) {
			t.Errorf("a hook credential reached the settings response:\n%s", rendered)
		}
	}
}

// A hook added through the interface is given only a name. Its credentials are
// minted on save, because asking a person to invent a secret is how short
// secrets happen -- and a hook without both is not served at all, so it would
// silently accept nothing.
func TestAHookAddedWithOnlyANameKeepsNoCredentialsUntilSaved(t *testing.T) {
	cur := testConfig()
	hooks := []hookUpdate{{Name: "front-door", Product: "access", Condition: "door_forced"}}

	next, _ := applyUpdate(cur, settingsUpdate{Hooks: &hooks})

	if len(next.Hooks) != 1 {
		t.Fatalf("got %d hooks, want 1", len(next.Hooks))
	}
	if next.Hooks[0].Name != "front-door" || next.Hooks[0].Condition != "door_forced" {
		t.Errorf("the hook did not survive the update: %+v", next.Hooks[0])
	}
	// config.Save is what mints them, so there is one place deciding how long
	// a hook credential is; applyUpdate must not invent its own.
	if !next.Hooks[0].Token.IsZero() || !next.Hooks[0].Bearer.IsZero() {
		t.Error("applyUpdate minted credentials itself, so there are now two " +
			"places that decide what a hook credential is")
	}
}

// Editing a hook must not disturb the credentials the Alarm Manager rule is
// already using. Losing them mid-edit breaks a live endpoint and the console
// keeps posting into a refusal.
func TestEditingAHookKeepsTheCredentialsItsRuleIsUsing(t *testing.T) {
	cur := configWithHook()
	hooks := []hookUpdate{{
		Name: "wan", Product: "network", Condition: "wan_down",
		Severity: "critical", // the only change
		Entity:   "WAN",
	}}

	next, _ := applyUpdate(cur, settingsUpdate{Hooks: &hooks})

	if next.Hooks[0].Token != cur.Hooks[0].Token {
		t.Error("editing a hook changed its token, breaking the Alarm Manager rule")
	}
	if next.Hooks[0].Bearer != cur.Hooks[0].Bearer {
		t.Error("editing a hook changed its bearer, breaking the Alarm Manager rule")
	}
	if next.Hooks[0].Severity != "critical" {
		t.Errorf("the edit did not apply: %+v", next.Hooks[0])
	}
}

// Regenerating is the deliberate opposite: it is what an operator asks for
// when a URL has been somewhere it should not, and it is SUPPOSED to break the
// old rule.
func TestRegeneratingClearsTheCredentialsSoSaveMintsNewOnes(t *testing.T) {
	cur := configWithHook()
	hooks := []hookUpdate{{Name: "wan", Product: "network", Condition: "wan_down", Regenerate: true}}

	next, touched := applyUpdate(cur, settingsUpdate{Hooks: &hooks})

	if !next.Hooks[0].Token.IsZero() || !next.Hooks[0].Bearer.IsZero() {
		t.Error("regenerate left the old credentials in place")
	}
	var named bool
	for _, s := range touched {
		if strings.Contains(s, "credentials") {
			named = true
		}
	}
	if !named {
		t.Errorf("regenerating was not recorded for the audit record: %v", touched)
	}
}

// A client that never mentions hooks must leave them alone. Conflating "not
// sent" with "deleted" would remove every Alarm Manager endpoint the site
// depends on the first time an older page saved a channel.
func TestHooksLeftOutOfAnUpdateAreKept(t *testing.T) {
	cur := configWithHook()
	next, _ := applyUpdate(cur, settingsUpdate{})

	if len(next.Hooks) != 1 || next.Hooks[0].Token != cur.Hooks[0].Token {
		t.Fatalf("hooks were dropped by an update that never mentioned them: %+v", next.Hooks)
	}
}

// Two hooks sharing a name make the receipts ambiguous, and the receipts are
// how an operator knows their rule works at all.
func TestTwoHooksWithOneNameAreRefused(t *testing.T) {
	cur := testConfig()
	hooks := []hookUpdate{{Name: "wan", Condition: "wan_down"}, {Name: "wan", Condition: "threat"}}

	next, _ := applyUpdate(cur, settingsUpdate{Hooks: &hooks})
	if err := next.Validate(); err == nil {
		t.Fatal("two hooks with the same name were accepted")
	}
}

// The dropdown is fed from the validator's own list, so it cannot drift into
// offering a condition that would be refused -- or worse, accepted and turned
// into a dedup key that never merges with itself.
func TestTheConditionChoicesComeFromTheValidatorsList(t *testing.T) {
	v := viewSettings(testConfig())
	if len(v.HookConditions) == 0 {
		t.Fatal("no conditions were offered, so the dropdown would be empty")
	}
	for i, got := range v.HookConditions {
		if got != config.KnownConditions[i] {
			t.Fatalf("the offered conditions differ from the validator's list at %d: %q vs %q",
				i, got, config.KnownConditions[i])
		}
	}
}

// renderToString serialises the view exactly as the endpoint would, so the
// check is on the bytes that would reach a browser rather than on the struct.
func renderToString(t *testing.T, v settingsView) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
