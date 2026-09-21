package network

import (
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// A SWITCH GOING OFFLINE IS NOT A SECURITY EVENT BY ITSELF.
//
// It was raised High, which on the default ladders wakes somebody. Most of
// what this source sees is an access point rebooting, a PoE port cycling or a
// switch being moved -- ordinary operational noise that says nothing about a
// door or a camera. Paged at 3am for it, an operator either stops trusting the
// product or turns the source off, and both cost more than the alert was ever
// worth.
//
// What makes a Network device going offline serious is the company it keeps:
// the same outage taking Protect or Access hardware with it. That pairing is
// not something this source can see on its own -- it polls one API and knows
// nothing about the others -- so raising it here would be guessing.
//
// So: Low by default. An operator who knows a particular switch carries the
// door controllers can raise that one with a rule.
func TestADeviceGoingOfflineIsNotHigh(t *testing.T) {
	sev := offlineSeverity()
	switch sev {
	case incident.SeverityLow, incident.SeverityInfo:
	default:
		t.Errorf("a Network device offline raises %q; on the default ladders "+
			"that wakes somebody for an access point rebooting", sev)
	}
}
