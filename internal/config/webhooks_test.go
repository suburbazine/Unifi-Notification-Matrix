package config

import (
	"strings"
	"testing"
)

// Outbound webhooks are a LIST, because pushing to a home-automation box and
// to an on-call service are different jobs wanted at different severities. A
// single endpoint forced a site to pick one.
func TestSeveralOutboundWebhooksAreEachAddressableByName(t *testing.T) {
	c := workable()
	c.Channels.Webhooks = []Webhook{
		{Name: "home-assistant", Enabled: true, URL: "http://10.0.0.5:8123/api/webhook/x"},
		{Name: "oncall", Enabled: true, URL: "https://events.example.com/hook"},
	}

	names := c.EnabledChannelNames()
	for _, want := range []string{"home-assistant", "oncall"} {
		var found bool
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not addressable as a channel: %v", want, names)
		}
	}

	// And a rung can name one.
	c.Policies = map[string]Policy{
		"critical": {Stages: []Stage{{After: "0s", Channels: []string{"oncall"}}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("a ladder naming a webhook by name was refused: %v", err)
	}
}

// A configuration written before the list existed keeps working, and keeps the
// name every policy already refers to.
func TestTheOriginalSingleWebhookBecomesTheOneCalledWebhook(t *testing.T) {
	c := Default()
	c.Channels.Webhook = &Webhook{Enabled: true, URL: "https://example.com/hook"}
	c.ApplyDefaults()

	if c.Channels.Webhook != nil {
		t.Error("the singular field survived the migration, so it would be written back")
	}
	if len(c.Channels.Webhooks) != 1 {
		t.Fatalf("got %d endpoints after migration, want 1", len(c.Channels.Webhooks))
	}
	if got := c.Channels.Webhooks[0].Name; got != "webhook" {
		t.Errorf("the migrated endpoint is called %q, want \"webhook\" -- every "+
			"policy written before this refers to that name", got)
	}
	if c.Channels.Webhooks[0].URL != "https://example.com/hook" {
		t.Error("the migration lost the URL")
	}
}

// Two endpoints sharing a name make a rung ambiguous, and a name shared with a
// built-in channel is worse: the rung would address whichever the map kept.
func TestWebhookNamesMustBeUniqueAndNotShadowABuiltIn(t *testing.T) {
	c := workable()
	c.Channels.Webhooks = []Webhook{
		{Name: "alerts", Enabled: true, URL: "https://a.example.com/h"},
		{Name: "alerts", Enabled: true, URL: "https://b.example.com/h"},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "both called") {
		t.Errorf("two endpoints with one name were accepted: %v", err)
	}

	c.Channels.Webhooks = []Webhook{
		{Name: "ntfy", Enabled: true, URL: "https://a.example.com/h"},
	}
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("a webhook named after a built-in channel was accepted: %v", err)
	}
}

// One broken endpoint must not take the others down, matching what a broken
// channel does everywhere else.
func TestABrokenEndpointDoesNotStopTheOthersBeingBuilt(t *testing.T) {
	c := workable()
	c.Channels.Webhooks = []Webhook{
		{Name: "good", Enabled: true, URL: "https://good.example.com/h"},
		{Name: "bad", Enabled: true, URL: "not-a-url"},
	}
	d, err := BuildDelivery(&c, nil)
	if err != nil {
		t.Fatalf("one malformed endpoint aborted the whole construction: %v", err)
	}
	defer d.Close()

	var haveGood bool
	for _, n := range d.Names() {
		if n == "good" {
			haveGood = true
		}
	}
	if !haveGood {
		t.Error("the good endpoint was not built")
	}
	if _, broken := d.Broken()["bad"]; !broken {
		t.Errorf("the malformed endpoint was not reported as broken: %v", d.Broken())
	}
}

// The shipped default ladders name ntfy and email. A site whose only channel
// is something else -- a Pushover account, a webhook called "home-assistant" --
// filtered every default away to nothing and was refused with one error per
// severity and no obvious action.
//
// A DEFAULT means "tell me on whatever exists". Only the operator's own policy
// means "these channels and no others".
func TestADefaultLadderFallsBackToWhateverChannelsExist(t *testing.T) {
	c := Default()
	c.Consoles = nil
	c.Channels.Ntfy = nil
	c.Channels.Webhooks = []Webhook{
		{Name: "home-assistant", Enabled: true, URL: "http://10.0.0.5:8123/api/webhook/x"},
	}

	if err := c.Validate(); err != nil {
		for _, prob := range err.(Problems) {
			if strings.Contains(prob, "no escalation stage left") {
				t.Fatalf("a site whose only channel is a named webhook was refused: %s", prob)
			}
		}
	}

	built, err := c.BuildPolicies(c.EnabledChannelNames())
	if err != nil {
		t.Fatal(err)
	}
	crit, ok := built["critical"]
	if !ok {
		t.Fatal("critical has no ladder at all")
	}
	if len(crit.Stages) == 0 || crit.Stages[0].Channels[0] != "home-assistant" {
		t.Fatalf("the fallback ladder does not use the channel that exists: %+v", crit.Stages)
	}
	// The timing is about severity, not about which services are set up, so it
	// survives.
	if crit.RepeatEvery == 0 {
		t.Error("the fallback dropped critical's repeat interval")
	}
}
