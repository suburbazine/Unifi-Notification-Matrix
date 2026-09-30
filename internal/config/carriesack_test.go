package config

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// WHICH CHANNELS GET THE TEST THAT PRESSES THE BUTTON.
//
// The daemon sends a real alert, and waits for it to be acknowledged, only for
// a channel a person acknowledges from. Get this wrong one way and ntfy's test
// goes back to proving nothing about its button; the other way and voice --
// whose test deliberately places no call -- telephones somebody, and a webhook
// test sits on the settings page waiting for a human who will never press
// anything.
func TestOnlyChannelsAPersonAcknowledgesFromCarryTheAck(t *testing.T) {
	c := workable()
	c.Channels.Pushover = &Pushover{Enabled: true,
		Token: secret.Secret("azGDORePK8gMaC0QOYAMyEEuzJnyUi"),
		User:  secret.Secret("uQiRzpo4DXghDmr9QzzfQu27cmVRsG")}
	c.Channels.Email = &Email{Enabled: true, Host: "mail.example.com", Port: 587,
		From: "nm@example.com", Recipients: []string{"ops@example.com"}}
	c.Channels.Voice = workableVoice()
	c.Channels.Webhooks = []Webhook{{Name: "ops", Enabled: true, URL: "https://hooks.example.com/h"}}

	d, err := BuildDelivery(&c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if b := d.Broken(); len(b) != 0 {
		t.Fatalf("setup: channels failed to build: %v", b)
	}

	for name, want := range map[string]bool{
		"ntfy": true, "pushover": true, "email": true,
		"voice": false, "ops": false,
		"not-configured": false,
	} {
		if got := d.CarriesAck(name); got != want {
			t.Errorf("CarriesAck(%q) = %v, want %v", name, got, want)
		}
	}
}
