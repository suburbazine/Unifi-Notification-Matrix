package web

import (
	"reflect"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// Escalation policies were readable and not writable at all: settingsUpdate
// had no field for them, so the only way to change the ladder that decides
// whether anybody is told a SECOND time was to hand-edit YAML.
func TestAPolicyCanBeSavedFromTheInterface(t *testing.T) {
	cur := testConfig()
	want := map[string]config.Policy{
		"critical": {
			Stages: []config.Stage{
				{After: "0s", Channels: []string{"ntfy"}},
				{After: "2m", Channels: []string{"ntfy", "email"}},
			},
			RepeatEvery: "5m",
			GiveUpAfter: "never",
		},
	}

	next, _ := applyUpdate(cur, settingsUpdate{Channels: ptrChannels(channelsAsUpdate(cur)), Policies: &want})

	if !reflect.DeepEqual(next.Policies, want) {
		t.Fatalf("policies did not survive the save:\n  got  %+v\n  want %+v",
			next.Policies, want)
	}
}

// A client that does not mention policies must leave them alone. The absent
// case and the cleared case are different intentions, and conflating them
// would delete every customised ladder the first time an older page saved a
// channel.
func TestPoliciesLeftOutOfAnUpdateAreKept(t *testing.T) {
	cur := testConfig()
	cur.Policies = map[string]config.Policy{
		"high": {Stages: []config.Stage{{After: "0s", Channels: []string{"ntfy"}}}},
	}

	next, _ := applyUpdate(cur, settingsUpdate{})

	if !reflect.DeepEqual(next.Policies, cur.Policies) {
		t.Fatalf("policies were dropped by an update that never mentioned them:\n"+
			"  got  %+v\n  want %+v", next.Policies, cur.Policies)
	}
}

// Clearing every override means "use the shipped defaults", which is a real
// thing to want and is where a config starts. Stored as nil rather than an
// empty map, so the file says nothing instead of saying {}.
func TestClearingEveryPolicyReturnsToTheDefaults(t *testing.T) {
	cur := testConfig()
	cur.Policies = map[string]config.Policy{
		"high": {Stages: []config.Stage{{After: "0s", Channels: []string{"ntfy"}}}},
	}
	empty := map[string]config.Policy{}

	next, _ := applyUpdate(cur, settingsUpdate{Channels: ptrChannels(channelsAsUpdate(cur)), Policies: &empty})

	if next.Policies != nil {
		t.Fatalf("clearing the overrides left %+v, want nil", next.Policies)
	}
}

// A policy naming a channel that is not enabled is refused by Validate, and it
// has to stay refused when it arrives through the interface: a ladder whose
// rungs point at nothing is an escalation that silently stops.
func TestAPolicyNamingAnUnknownChannelIsRefused(t *testing.T) {
	cur := testConfig()
	bad := map[string]config.Policy{
		"critical": {Stages: []config.Stage{{After: "0s", Channels: []string{"carrier-pigeon"}}}},
	}

	next, _ := applyUpdate(cur, settingsUpdate{Channels: ptrChannels(channelsAsUpdate(cur)), Policies: &bad})
	if err := next.Validate(); err == nil {
		t.Fatal("a policy naming a channel that does not exist was accepted")
	}
}

// A stage delay has to be a duration. "5" is not five minutes, and a config
// that accepted it would escalate five nanoseconds after the first alert.
func TestAStageWithAnUnparseableDelayIsRefused(t *testing.T) {
	cur := testConfig()
	bad := map[string]config.Policy{
		"critical": {Stages: []config.Stage{{After: "5", Channels: []string{"ntfy"}}}},
	}
	next, _ := applyUpdate(cur, settingsUpdate{Channels: ptrChannels(channelsAsUpdate(cur)), Policies: &bad})
	if err := next.Validate(); err == nil {
		t.Fatal(`a stage delay of "5" was accepted`)
	}
}

// The audit record has to name what moved. A changed escalation ladder that
// records as "nothing" is a change nobody can account for afterwards.
func TestAChangedPolicyIsNamedInTheAuditRecord(t *testing.T) {
	cur := testConfig()
	changed := map[string]config.Policy{
		"critical": {Stages: []config.Stage{{After: "0s", Channels: []string{"ntfy"}}}},
	}
	next, touched := applyUpdate(cur, settingsUpdate{Channels: ptrChannels(channelsAsUpdate(cur)), Policies: &changed})

	sections := changedSections(viewSettings(cur), viewSettings(next), touched)
	var found bool
	for _, s := range sections {
		if s == "policies" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a changed escalation ladder recorded as %v", sections)
	}
}
