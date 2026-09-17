package config

import (
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
	"sigs.k8s.io/yaml"
)

// workableVoice is a voice channel with nothing wrong with it, so that each
// test below can break exactly one thing and nothing else.
func workableVoice() *Voice {
	return &Voice{
		Enabled:    true,
		AccountSID: secret.Secret("ACnotarealaccountsid"),
		AuthToken:  secret.Secret("not-a-real-auth-token"),
		From:       "+15552223214",
		Recipients: []string{"+15558675310"},
	}
}

func TestAVoiceChannelWithEverythingItNeedsValidates(t *testing.T) {
	c := workable()
	c.Channels.Voice = workableVoice()
	c.ApplyDefaults()

	if err := c.Validate(); err != nil {
		t.Fatalf("a complete voice channel was refused: %v", err)
	}

	// And it is addressable, which is what makes it opt-in rather than
	// unreachable: a channel that validates but cannot be named on a rung is a
	// channel with no way to do its job.
	var named bool
	for _, n := range c.EnabledChannelNames() {
		if n == "voice" {
			named = true
		}
	}
	if !named {
		t.Errorf("an enabled voice channel is not in EnabledChannelNames: %v",
			c.EnabledChannelNames())
	}

	c.Policies = map[string]Policy{
		"critical": {Stages: []Stage{{After: "10m", Channels: []string{"voice"}}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("a ladder naming voice was refused: %v", err)
	}
}

// Each of these would produce a channel that cannot place a call. Every one is
// a PROBLEM rather than a warning: the operator has said "call me", and the
// honest answer is that this configuration would not, which is worth refusing
// the save for rather than starting up and finding out during an alarm.
func TestAnIncompleteVoiceChannelIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(*Voice)
		want  string
	}{
		{"no account sid", func(v *Voice) { v.AccountSID = "" }, "account SID"},
		{"the auth token pasted into the account sid box",
			func(v *Voice) { v.AccountSID = secret.Secret("not-a-real-auth-token") },
			"must begin"},
		{"no auth token", func(v *Voice) { v.AuthToken = "" }, "auth token"},
		{"no from number", func(v *Voice) { v.From = "" }, "needs a from number"},
		{"a from number typed the way people say it",
			func(v *Voice) { v.From = "(555) 222-3214" }, "E.164"},
		{"a from number with no country code",
			func(v *Voice) { v.From = "5552223214" }, "E.164"},
		{"a recipient with no country code",
			func(v *Voice) { v.Recipients = []string{"07700900123"} }, "E.164"},
		{"no recipients at all",
			func(v *Voice) { v.Recipients = nil }, "would call nobody"},
		{"a recipient list that is only blanks",
			func(v *Voice) { v.Recipients = []string{"", "   "} }, "would call nobody"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := workable()
			v := workableVoice()
			tc.spoil(v)
			c.Channels.Voice = v
			c.ApplyDefaults()

			err := c.Validate()
			if err == nil {
				t.Fatalf("a voice channel with %s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say %q, so the operator cannot fix it: %v",
					tc.want, err)
			}
		})
	}
}

// A voice channel that is CONFIGURED AND SWITCHED OFF is not a problem, however
// incomplete it is. Half-filled settings are what the form looks like while
// somebody is still typing, and refusing to save them is refusing to let them
// finish.
func TestAnIncompleteVoiceChannelThatIsSwitchedOffIsNotAProblem(t *testing.T) {
	c := workable()
	c.Channels.Voice = &Voice{Enabled: false}
	c.ApplyDefaults()

	if err := c.Validate(); err != nil {
		t.Fatalf("an empty, disabled voice channel was refused: %v", err)
	}
}

// The refusal must not echo the value it was given. If the auth token really is
// in the account_sid field -- which is the whole reason that check exists --
// quoting it publishes the credential into the startup log and into the UI's
// problem list.
func TestTheAccountSIDRefusalDoesNotQuoteWhatItWasGiven(t *testing.T) {
	const canaryToken = "twilio-auth-token-do-not-print-me"

	c := workable()
	v := workableVoice()
	v.AccountSID = secret.Secret(canaryToken)
	c.Channels.Voice = v
	c.ApplyDefaults()

	err := c.Validate()
	if err == nil {
		t.Fatal("an account SID that is plainly an auth token was accepted")
	}
	if strings.Contains(err.Error(), canaryToken) {
		t.Errorf("the refusal printed the credential it was handed: %v", err)
	}
}

// An operator cannot name an outbound webhook "voice": both would register
// under the same key in Delivery, and the rung would address whichever the map
// happened to keep -- a misdelivery with no error anywhere.
func TestAWebhookCannotBeCalledVoice(t *testing.T) {
	c := workable()
	c.Channels.Webhooks = []Webhook{
		{Name: "voice", Enabled: true, URL: "https://example.com/hook"},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("a webhook named after the voice channel was accepted: %v", err)
	}
}

// Validate refuses an incomplete voice channel, so a config that reaches
// BuildDelivery broken was hand-edited or written by an older build. The reply
// to that is a channel reported as broken, never a daemon that will not start:
// nothing watched, nothing ingested, no incidents raised, over a phone number.
func TestABrokenVoiceChannelDoesNotStopTheDaemon(t *testing.T) {
	c := workable()
	v := workableVoice()
	v.From = "not a phone number"
	c.Channels.Voice = v

	d, err := BuildDelivery(&c, nil)
	if err != nil {
		t.Fatalf("a malformed voice channel aborted the whole construction: %v", err)
	}
	defer d.Close()

	if _, broken := d.Broken()["voice"]; !broken {
		t.Errorf("the malformed voice channel was not reported as broken: %v", d.Broken())
	}
	// The channels that are fine are still built, which is the point.
	var haveNtfy bool
	for _, n := range d.Names() {
		if n == "ntfy" {
			haveNtfy = true
		}
	}
	if !haveNtfy {
		t.Error("a broken voice channel cost the site the channel that worked")
	}
}

func TestAGoodVoiceChannelIsBuilt(t *testing.T) {
	c := workable()
	c.Channels.Voice = workableVoice()
	c.ApplyDefaults()

	d, err := BuildDelivery(&c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if len(d.Broken()) != 0 {
		t.Fatalf("a good voice channel was reported broken: %v", d.Broken())
	}
	var have bool
	for _, n := range d.Names() {
		if n == "voice" {
			have = true
		}
	}
	if !have {
		t.Errorf("voice was not built: %v", d.Names())
	}
}

// Blank means the default everywhere else in this file, and ApplyDefaults runs
// on the save path as well as the load path -- so a form that posts an empty
// voice name must come back with the one that will actually be spoken, rather
// than with a blank the operator cannot tell from a choice.
func TestApplyDefaultsFillsInTheSpokenVoiceAndLanguage(t *testing.T) {
	c := workable()
	c.Channels.Voice = workableVoice()
	c.ApplyDefaults()

	if c.Channels.Voice.Voice == "" || c.Channels.Voice.Language == "" {
		t.Fatalf("ApplyDefaults left the spoken voice or language blank: %+v",
			c.Channels.Voice)
	}

	// An explicit choice survives, or the operator's setting is silently
	// overwritten every time anything is saved.
	c.Channels.Voice.Voice = "woman"
	c.Channels.Voice.Language = "en-GB"
	c.ApplyDefaults()
	if c.Channels.Voice.Voice != "woman" || c.Channels.Voice.Language != "en-GB" {
		t.Errorf("ApplyDefaults overwrote a chosen voice: %+v", c.Channels.Voice)
	}
}

// The Twilio auth token is stored under the YAML key "token" and not
// "auth_token" for exactly one reason: PlaintextSecrets looks for the literal
// names api_key, token and password, and a credential it cannot see is one the
// operator is never told to rotate. If somebody renames the key to match
// Twilio's own documentation, this fails and says why.
func TestAVoiceTokenPastedInTheClearIsReportedAsExposed(t *testing.T) {
	raw := []byte("channels:\n  voice:\n    enabled: true\n    token: pasted-in-the-clear\n")
	got := PlaintextSecrets(raw)
	if len(got) != 1 || got[0] != "token" {
		t.Fatalf("PlaintextSecrets(%q) = %v -- a Twilio auth token sitting readable "+
			"on disk was not reported, so nobody is told to rotate it", raw, got)
	}
}

// The instructions in the file have to be instructions that work. The header
// test parses every example strictly; this one proves the voice example is
// actually in there and is a complete, usable channel rather than a fragment.
func TestTheHeaderExampleConfiguresAUsableVoiceChannel(t *testing.T) {
	var found *Voice
	for _, block := range exampleBlocks(fileHeader) {
		var cfg Config
		if err := yaml.UnmarshalStrict([]byte(block), &cfg); err != nil {
			continue // the strict test in header_example_test.go reports this
		}
		if cfg.Channels.Voice != nil {
			found = cfg.Channels.Voice
		}
	}
	if found == nil {
		t.Fatal("the file header does not show anybody how to configure the voice channel")
	}
	if found.From == "" || len(found.Recipients) == 0 {
		t.Errorf("the header's voice example is missing the numbers: %+v", found)
	}
	// A number the header prints unquoted is a number YAML reads as an integer,
	// which reaches the file as something Twilio refuses.
	if !validE164(found.From) {
		t.Errorf("the header's example from number %q is not E.164 once parsed -- "+
			"quote it, or YAML turns it into a number", found.From)
	}
	for _, to := range found.Recipients {
		if !validE164(to) {
			t.Errorf("the header's example recipient %q is not E.164 once parsed", to)
		}
	}
}

// Enabling voice is not enough, and the difference is invisible: no shipped
// ladder names it, so a site that switches it on and writes no rung has a
// channel that tests green and never calls. Saying so is a warning, never a
// refusal -- the configuration is valid and everything else still delivers.
func TestVoiceEnabledButOnNoRungIsWarnedAbout(t *testing.T) {
	c := workable()
	c.Channels.Voice = workableVoice()
	c.ApplyDefaults()

	if err := c.Validate(); err != nil {
		t.Fatalf("enabling voice without a rung refused the whole config: %v", err)
	}
	var said bool
	for _, w := range c.Warnings() {
		if strings.Contains(w, "voice") && strings.Contains(w, "no escalation rung") {
			said = true
		}
	}
	if !said {
		t.Errorf("nothing warned that voice will never be used: %v", c.Warnings())
	}

	// And the warning goes away once a rung names it, or it is noise that
	// teaches the operator to ignore the warning list.
	c.Policies = map[string]Policy{
		"critical": {Stages: []Stage{
			{After: "0s", Channels: []string{"ntfy"}},
			{After: "10m", Channels: []string{"voice"}},
		}},
	}
	for _, w := range c.Warnings() {
		if strings.Contains(w, "no escalation rung") {
			t.Errorf("a ladder that names voice still warns about it: %s", w)
		}
	}
}
