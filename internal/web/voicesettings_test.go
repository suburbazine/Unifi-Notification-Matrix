package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// Voice is the only channel that costs money and the only one with TWO
// credentials in one card, so it is the easiest to half-carry: an operator
// retypes the auth token, the account SID is quietly dropped, and the channel
// that was going to ring somebody at 3am can no longer authenticate. These
// tests exist for that, and for the plainer version of it -- a save from
// another tab deleting the channel outright.

// A save that never mentions voice must leave it exactly as it was.
//
// The payload is what the Webhooks tab actually posts: it names hooks and
// channels.webhooks and nothing else. As a plain value rather than a pointer,
// channels.voice would arrive as the zero voiceUpdate -- enabled false, no
// credentials -- and the save would report "Saved." while switching off the
// phone calls.
func TestASaveFromAnotherTabLeavesVoiceAlone(t *testing.T) {
	cur := testConfig()

	const webhooksTabPayload = `{"hooks":[],"channels":{"webhooks":[` +
		`{"name":"homeassistant","enabled":true,"url":"http://10.0.0.5/hook"}]}}`

	var upd settingsUpdate
	if err := json.Unmarshal([]byte(webhooksTabPayload), &upd); err != nil {
		t.Fatal(err)
	}
	next, touched := applyUpdate(cur, upd)

	v := next.Channels.Voice
	if v == nil {
		t.Fatal("voice was deleted by a save that never mentioned it")
	}
	if !v.Enabled {
		t.Error("voice was switched off by a save that never mentioned it")
	}
	if v.AccountSID.Reveal() != "AC"+canary+"-sid" || v.AuthToken.Reveal() != canary+"-twilio" {
		t.Error("a Twilio credential was lost by a save that never mentioned voice")
	}
	if v.From != cur.Channels.Voice.From || len(v.Recipients) != len(cur.Channels.Voice.Recipients) {
		t.Errorf("the numbers changed under a save that never mentioned voice: %+v", v)
	}
	for _, s := range touched {
		if strings.Contains(s, "voice") {
			t.Errorf("a save that never mentioned voice claimed to have changed it: %q", s)
		}
	}
}

// A save that DOES mention voice, without resending either credential, keeps
// both. This is the common case: somebody corrects a mistyped phone number.
func TestVoiceCredentialsSurviveASaveThatDidNotResendThem(t *testing.T) {
	cur := testConfig()

	next, touched := applyUpdate(cur, settingsUpdate{
		Channels: ptrChannels(channelsUpdate{
			Voice: &voiceUpdate{
				Enabled:    true,
				From:       "+15552223214",
				Recipients: []string{"+15558675311"},
				Voice:      "woman",
				Language:   "en-GB",
			},
		}),
	})

	v := next.Channels.Voice
	if v == nil {
		t.Fatal("voice disappeared from a save that was editing it")
	}
	if v.AccountSID.Reveal() != "AC"+canary+"-sid" {
		t.Error("the Twilio account SID was wiped by a save that did not resend it")
	}
	if v.AuthToken.Reveal() != canary+"-twilio" {
		t.Error("the Twilio auth token was wiped by a save that did not resend it")
	}
	// And the edit the operator actually made landed.
	if len(v.Recipients) != 1 || v.Recipients[0] != "+15558675311" {
		t.Errorf("the corrected number did not land: %+v", v.Recipients)
	}
	if v.Voice != "woman" || v.Language != "en-GB" {
		t.Errorf("the spoken voice and language did not land: %q / %q", v.Voice, v.Language)
	}
	if len(touched) != 0 {
		t.Errorf("a save that replaced no credential claimed it had: %v", touched)
	}
}

// One credential resent must replace only that one, and the audit record must
// name WHICH -- never the value. "channels changed" tells an operator reading
// the log a week later nothing about what to re-check.
func TestResendingOneVoiceCredentialReplacesOnlyThatOne(t *testing.T) {
	cur := testConfig()

	next, touched := applyUpdate(cur, settingsUpdate{
		Channels: ptrChannels(channelsUpdate{
			Voice: &voiceUpdate{
				Enabled:      true,
				AuthTokenNew: "a-rotated-auth-token",
				From:         "+15552223214",
				Recipients:   []string{"+15558675310"},
			},
		}),
	})

	v := next.Channels.Voice
	if v.AuthToken.Reveal() != "a-rotated-auth-token" {
		t.Errorf("the rotated auth token was not stored: %v", v.AuthToken)
	}
	if v.AccountSID.Reveal() != "AC"+canary+"-sid" {
		t.Error("rotating the auth token also wiped the account SID")
	}

	var named bool
	for _, s := range touched {
		if strings.Contains(s, "a-rotated-auth-token") || strings.Contains(s, canary) {
			t.Errorf("the audit record carried a credential VALUE: %q", s)
		}
		if s == "voice twilio auth token" {
			named = true
		}
		if strings.Contains(s, "account sid") {
			t.Errorf("the audit record claimed a credential changed that did not: %q", s)
		}
	}
	if !named {
		t.Errorf("the audit record did not say which credential was replaced: %v", touched)
	}

	// The mirror image: the SID alone.
	next, touched = applyUpdate(cur, settingsUpdate{
		Channels: ptrChannels(channelsUpdate{
			Voice: &voiceUpdate{
				Enabled: true, AccountSIDNew: "ACa-different-account",
				From: "+15552223214", Recipients: []string{"+15558675310"},
			},
		}),
	})
	if next.Channels.Voice.AccountSID.Reveal() != "ACa-different-account" {
		t.Error("the replaced account SID was not stored")
	}
	if next.Channels.Voice.AuthToken.Reveal() != canary+"-twilio" {
		t.Error("replacing the account SID also wiped the auth token")
	}
	if len(touched) != 1 || touched[0] != "voice twilio account sid" {
		t.Errorf("the audit record did not name the account SID alone: %v", touched)
	}
}

// The settings API reports that the Twilio credentials EXIST and never what
// they are. The account SID is the one at risk here: it reads like an
// identifier rather than a password, and it is exactly what a form wants to
// show back so the operator can see what is stored.
func TestTheSettingsAPINeverReturnsAVoiceCredential(t *testing.T) {
	h := newHarness(t)
	h.setPassword(testPassword)
	h.signIn()

	res, body := h.do("GET", "/api/settings", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/settings: %d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), canary) {
		t.Fatalf("the settings response carried a Twilio credential:\n%s", body)
	}

	var got settingsView
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Channels.Voice == nil {
		t.Fatal("the configured voice channel is not in the settings response at all")
	}
	if !got.Channels.Voice.AccountSIDSet || !got.Channels.Voice.AuthTokenSet {
		t.Error("the settings response hid the EXISTENCE of the Twilio credentials" +
			" as well as their values, so an operator cannot tell a configured" +
			" channel from an empty one")
	}
	// The numbers ARE returned, deliberately: this response is behind the
	// session gate and somebody has to be able to check what they typed.
	if got.Channels.Voice.From == "" || len(got.Channels.Voice.Recipients) == 0 {
		t.Errorf("the numbers were not returned, so the form cannot show them: %+v",
			got.Channels.Voice)
	}

	// Asserted against the unparsed JSON as well, because "this must never
	// appear" is only provable against the bytes: a key called account_sid or
	// token in this object would be a value, whatever the Go type says.
	var raw struct {
		Channels struct {
			Voice map[string]any `json:"voice"`
		} `json:"channels"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"account_sid", "auth_token", "token", "password"} {
		if _, ok := raw.Channels.Voice[banned]; ok {
			t.Errorf("the voice settings object carries a %q key, which can only be a value", banned)
		}
	}
}

// A save must be able to ADD voice to a config that has never had it, or the
// only way to configure the one channel that telephones somebody is to hand-
// edit YAML -- which is the operator this interface exists for.
func TestVoiceCanBeAddedFromTheInterface(t *testing.T) {
	cur := testConfig()
	cur.Channels.Voice = nil

	next, touched := applyUpdate(cur, settingsUpdate{
		Channels: ptrChannels(channelsUpdate{
			Voice: &voiceUpdate{
				Enabled:       true,
				AccountSIDNew: "ACbrand-new-account",
				AuthTokenNew:  "brand-new-token",
				From:          "+15552223214",
				Recipients:    []string{"+15558675310"},
			},
		}),
	})

	v := next.Channels.Voice
	if v == nil {
		t.Fatal("a voice channel added from the interface was not stored")
	}
	if v.AccountSID.Reveal() != "ACbrand-new-account" || v.AuthToken.Reveal() != "brand-new-token" {
		t.Errorf("the new credentials were not stored: %+v", v)
	}
	// ApplyDefaults runs on this path as well as on load, so a form that left
	// the two dropdowns alone still produces a config that says what goes on
	// the wire rather than leaving it to a Twilio console setting nobody here
	// can see.
	if v.Voice == "" || v.Language == "" {
		t.Errorf("the spoken voice and language were left blank: %+v", v)
	}
	if len(touched) != 2 {
		t.Errorf("adding a channel with two credentials recorded %d of them: %v", len(touched), touched)
	}
}

// The view is projected from the config, so the card cannot show a stale
// enabled flag or a stale number after a save.
func TestTheVoiceViewMirrorsTheStoredChannel(t *testing.T) {
	c := testConfig()
	c.Channels.Voice = &config.Voice{
		Enabled:    false,
		From:       "+15552223214",
		Recipients: []string{"+15558675310", "+15558675311"},
		Voice:      "woman",
		Language:   "en-GB",
	}

	v := viewSettings(c).Channels.Voice
	if v == nil {
		t.Fatal("a configured-but-switched-off voice channel vanished from the view")
	}
	if v.Enabled {
		t.Error("a switched-off channel was shown as enabled")
	}
	// Configured and switched off is not the same as not configured, and the
	// difference has to survive to the card or an operator cannot tell why
	// nobody is being telephoned.
	if v.AccountSIDSet || v.AuthTokenSet {
		t.Error("credentials that do not exist were reported as set")
	}
	if len(v.Recipients) != 2 || v.Voice != "woman" || v.Language != "en-GB" {
		t.Errorf("the view did not mirror the stored channel: %+v", v)
	}
}

// The JSON KEYS the page posts have to be the ones this package reads.
//
// app.js posts the draft object verbatim -- the view it was given, plus the
// "_new" keys the password boxes write into. A key that does not match a json
// tag here does not fail: encoding/json drops it in silence, so the field
// simply never changes and the save still reports "Saved." This payload is
// what the voice card produces, so the two cannot drift apart unnoticed.
func TestTheVoiceCardsPayloadIsReadByThisPackage(t *testing.T) {
	cur := testConfig()

	const voiceCardPayload = `{"channels":{"voice":{` +
		`"enabled":true,` +
		`"account_sid_set":true,"auth_token_set":true,` +
		`"auth_token_new":"typed-into-the-form",` +
		`"from":"+15552223215",` +
		`"recipients":["+15558675310","+15558675311"],` +
		`"voice":"woman","language":"en-GB"}}}`

	var upd settingsUpdate
	if err := json.Unmarshal([]byte(voiceCardPayload), &upd); err != nil {
		t.Fatal(err)
	}
	next, touched := applyUpdate(cur, upd)

	v := next.Channels.Voice
	if v == nil {
		t.Fatal("the payload the card posts did not reach the config at all")
	}
	if !v.Enabled {
		t.Error("the enabled box did not reach the config")
	}
	if v.From != "+15552223215" {
		t.Errorf("the caller ID did not reach the config: %q", v.From)
	}
	if len(v.Recipients) != 2 {
		t.Errorf("the numbers did not reach the config: %+v", v.Recipients)
	}
	if v.Voice != "woman" || v.Language != "en-GB" {
		t.Errorf("the two dropdowns did not reach the config: %q / %q", v.Voice, v.Language)
	}
	if v.AuthToken.Reveal() != "typed-into-the-form" {
		t.Errorf("the typed auth token did not reach the config: %v", v.AuthToken)
	}
	// The set-flags the page sends back are the view's own, and must not be
	// mistaken for values: the account SID was not retyped, so it is carried.
	if v.AccountSID.Reveal() != "AC"+canary+"-sid" {
		t.Error("the account SID was not carried across the card's own payload")
	}
	if len(touched) != 1 || touched[0] != "voice twilio auth token" {
		t.Errorf("the audit record did not name exactly what changed: %v", touched)
	}
}

// THE RECORD MUST NOT CLAIM A DELIVERY THAT DID NOT HAPPEN.
//
// Every other channel's test button delivers a message, so "test message sent
// to ntfy" and "Sent." are true for them. Voice places no call -- a test that
// costs money and rings somebody is not the harmless message the Channel
// interface describes -- so those words were the product's own append-only
// record asserting something that never occurred. Painting over it in the
// browser would have left the record still lying.
func TestAChannelWhoseTestSendsNothingSaysSoInTheRecord(t *testing.T) {
	const summary = "Checked the credentials. NO CALL WAS PLACED."

	h := newHarness(t)
	h.testChannel = func(context.Context, string) (string, error) { return summary, nil }
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/channels/voice/test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("NO CALL WAS PLACED")) {
		t.Errorf("the reply did not say what the test actually did: %s", body)
	}
	if bytes.Contains(body, []byte("If it does not arrive")) {
		t.Errorf("the reply used the generic delivered-a-message wording: %s", body)
	}

	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	var found bool
	for _, e := range h.log.entries {
		if strings.Contains(e.Summary, "voice") {
			found = true
			if strings.Contains(e.Summary, "test message sent") {
				t.Errorf("the audit record claims a delivery that never happened: %q", e.Summary)
			}
			if !strings.Contains(e.Summary, "NO CALL WAS PLACED") {
				t.Errorf("the audit record does not say what the test did: %q", e.Summary)
			}
		}
	}
	if !found {
		t.Error("the test was not recorded at all")
	}
}

// A channel that DOES deliver keeps the generic wording, which is true for it.
func TestAChannelWhoseTestDeliversKeepsTheGenericWording(t *testing.T) {
	h := newHarness(t)
	h.testChannel = func(context.Context, string) (string, error) { return "", nil }
	h.setPassword(testPassword)
	h.signIn()

	resp, body := h.do("POST", "/api/channels/ntfy/test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("If it does not arrive")) {
		t.Errorf("a channel that really delivers lost its wording: %s", body)
	}
}
