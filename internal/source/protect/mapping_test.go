package protect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func TestEventTypesMapToConditionAndSeverity(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantCond string
		wantSev  incident.Severity
		wantClrs bool
	}{
		{
			"a doorbell ring is not an emergency",
			`{"type":"ring","device":"cam-1"}`,
			ConditionRing, incident.SeverityLow, false,
		},
		{
			"a person detection outranks bare motion",
			`{"type":"smartDetectZone","smartDetectTypes":["person"]}`,
			ConditionSmartDetect, incident.SeverityMedium, false,
		},
		{
			"a package on the porch does not page anyone",
			`{"type":"smartDetectZone","smartDetectTypes":["package"]}`,
			ConditionSmartDetect, incident.SeverityLow, false,
		},
		{
			"smoke is critical",
			`{"type":"sensorAlarm","metadata":{"alarmType":{"text":"smoke"}}}`,
			ConditionSmoke, incident.SeverityCritical, false,
		},
		{
			"carbon monoxide is critical and arrives upper-cased",
			`{"type":"sensorAlarm","metadata":{"alarmType":{"text":"CO"}}}`,
			ConditionCarbonMonoxide, incident.SeverityCritical, false,
		},
		{
			"glass break is critical and arrives camel-cased",
			`{"type":"sensorAlarm","metadata":{"alarmType":{"text":"glassBreak"}}}`,
			ConditionGlassBreak, incident.SeverityCritical, false,
		},
		{
			"an unreadable alarm type stays an alarm instead of becoming a guess",
			`{"type":"sensorAlarm","metadata":{"alarmType":{"text":"somethingNew"}}}`,
			ConditionSensorAlarm, incident.SeverityHigh, false,
		},
		{
			"an alarm with no metadata at all is still an alarm",
			`{"type":"sensorAlarm"}`,
			ConditionSensorAlarm, incident.SeverityHigh, false,
		},
		{
			"sensor tamper is critical",
			`{"type":"sensorTamper"}`,
			ConditionTamper, incident.SeverityCritical, false,
		},
		{
			"alarm hub device tamper is the same condition as sensor tamper",
			`{"type":"alarmHubDeviceTamper"}`,
			ConditionTamper, incident.SeverityCritical, false,
		},
		{
			"alarm hub smoke is critical without needing metadata",
			`{"type":"alarmHubSmoke"}`,
			ConditionSmoke, incident.SeverityCritical, false,
		},
		{
			"alarm hub glass break is critical",
			`{"type":"alarmHubGlassBreak"}`,
			ConditionGlassBreak, incident.SeverityCritical, false,
		},
		{
			"sensorClosed is the clear of sensorOpened, not its own condition",
			`{"type":"sensorClosed"}`,
			ConditionContactOpen, incident.SeverityMedium, true,
		},
		{
			"alarmHubEntryClosed clears alarmHubEntryOpened",
			`{"type":"alarmHubEntryClosed"}`,
			ConditionEntryOpen, incident.SeverityMedium, true,
		},
		{
			"water leak escalates",
			`{"type":"sensorWaterLeak"}`,
			ConditionWaterLeak, incident.SeverityHigh, false,
		},
		{
			"a smoke detector at end of life is a hazard, not an FYI",
			`{"type":"sensorSmokeEndOfLife"}`,
			ConditionSmokeFault, incident.SeverityHigh, false,
		},
		{
			"a CO detector fault escalates",
			`{"type":"sensorCoFault"}`,
			ConditionCOFault, incident.SeverityHigh, false,
		},
		{
			"a smoke test is not a fire",
			`{"type":"sensorSmokeTest"}`,
			ConditionSmokeTest, incident.SeverityLow, false,
		},
		{
			"battery low on a sensor is worth knowing",
			`{"type":"sensorBatteryLow"}`,
			ConditionBatteryLow, incident.SeverityMedium, false,
		},
		{
			"a UP Sense opening is a contact open",
			`{"type":"sensorOpened"}`,
			ConditionContactOpen, incident.SeverityMedium, false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var it item
			if err := json.Unmarshal([]byte(tc.raw), &it); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			m, ok := classify(&it)
			if !ok {
				t.Fatalf("event type %q was not recognised at all", it.Type)
			}
			if m.condition != tc.wantCond {
				t.Errorf("condition = %q, want %q", m.condition, tc.wantCond)
			}
			if m.severity != tc.wantSev {
				t.Errorf("severity = %q, want %q", m.severity, tc.wantSev)
			}
			if m.clears != tc.wantClrs {
				t.Errorf("clears = %v, want %v", m.clears, tc.wantClrs)
			}
			if !m.severity.Valid() {
				t.Errorf("severity %q is not in the fixed vocabulary", m.severity)
			}
		})
	}
}

// Every event type SOURCES.md records for v7.3.53 must map to something, or a
// hazard class silently stops being covered when a console is upgraded.
func TestTheDocumentedEventVocabularyIsFullyCovered(t *testing.T) {
	documented := []string{
		"ring", "motion", "smartDetectZone", "smartDetectLine", "smartDetectLoiterZone",
		"smartAudioDetect", "lightMotion", "sensorMotion", "sensorOpened", "sensorClosed",
		"sensorButtonPressed", "sensorWaterLeak", "sensorTamper", "sensorBatteryLow",
		"sensorAlarm", "sensorVape", "sensorExtremeValues", "sensorSmokeTest",
		"sensorSmokeBatteryLow", "sensorSmokeNeedsCleaning", "sensorSmokeFault",
		"sensorCoFault", "sensorSmokeEndOfLife", "relayInputChanged",
		"cameraDigitalInputChanged", "alarmHubMotion", "alarmHubEntryOpened",
		"alarmHubEntryClosed", "alarmHubSmoke", "alarmHubGlassBreak", "alarmHubButtonPress",
		"alarmHubTamper", "alarmHubDeviceTamper", "alarmHubRelaySwitched",
		"alarmHubBatteryLow", "alarmHubBatteryConnected", "nfcCardScanned",
		"fingerprintIdentified",
	}
	for _, typ := range documented {
		if _, ok := baseMappings[typ]; !ok {
			t.Errorf("documented event type %q has no mapping; it would be counted unrecognised and never alert", typ)
		}
	}
}

// Camera disconnect is not an event type. It is this enum flipping, which is
// the whole reason the source opens a second socket.
func TestCameraStateTransitions(t *testing.T) {
	tests := []struct {
		name      string
		prev, now string
		wantCond  string
		wantClear bool
		wantEmit  bool
	}{
		{"a camera going dark opens an offline condition", stateConnected, stateDisconnected, ConditionOffline, false, true},
		{"a camera coming back clears the same condition", stateDisconnected, stateConnected, ConditionOffline, true, true},
		{"a camera we never saw fail does not get a clear invented for it", stateConnected, stateConnected, "", false, false},
		{"first sight of a healthy camera says nothing", "", stateConnected, "", false, false},
		{"first sight of a dark camera is an open alarm", "", stateDisconnected, ConditionOffline, false, true},
		{"a camera that is still dark is not re-reported", stateDisconnected, stateDisconnected, "", false, false},
		{"CONNECTING is a transient and claims nothing either way", stateConnected, stateConnecting, "", false, false},
		{"an unreadable state yields no information rather than a guess", stateConnected, "SOMETHING_NEW", "", false, false},
		{"an absent state yields no information", stateDisconnected, "", "", false, false},
		{"lower case from a future firmware still parses", stateConnected, "disconnected", ConditionOffline, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cond, clears, emit := classifyState(tc.prev, tc.now)
			if emit != tc.wantEmit {
				t.Fatalf("emit = %v, want %v", emit, tc.wantEmit)
			}
			if cond != tc.wantCond || clears != tc.wantClear {
				t.Fatalf("got (%q, clears=%v), want (%q, clears=%v)", cond, clears, tc.wantCond, tc.wantClear)
			}
		})
	}
}

func TestAnUnknownEventTypeIsNotClassified(t *testing.T) {
	var it item
	if err := json.Unmarshal([]byte(`{"type":"sensorSomethingFromNextFirmware"}`), &it); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, ok := classify(&it); ok {
		t.Fatal("an unmapped type must report itself unknown so it can be counted, not invented into a condition")
	}
}

// The battery-connected pairing is deliberately NOT modelled as a clear: a
// wrong clear silently resolves a live incident, which is the one failure this
// product cannot have.
func TestAlarmHubBatteryConnectedDoesNotResolveBatteryLow(t *testing.T) {
	var it item
	if err := json.Unmarshal([]byte(`{"type":"alarmHubBatteryConnected"}`), &it); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	m, ok := classify(&it)
	if !ok {
		t.Fatal("alarmHubBatteryConnected should be recognised")
	}
	if m.clears {
		t.Fatal("alarmHubBatteryConnected must not clear anything on an unverified pairing")
	}
	if m.condition == ConditionBatteryLow {
		t.Fatal("alarmHubBatteryConnected must not share battery-low's dedup key")
	}
}

// `end` on an update frame may resolve ONLY motion-shaped conditions.
//
// For an alarm, a contact or a leak the end of the event WINDOW means the
// detection stopped being RECORDED -- not that the smoke cleared, the door
// shut or the water stopped. A clear there silently resolves an incident
// nobody has looked at, which is the one failure this product cannot have.
// This is asserted over the whole table rather than on one example, because
// the damage is done by the entry somebody adds later.
func TestOnlyMotionShapedConditionsAreResolvedByTheirOwnEnd(t *testing.T) {
	motionShaped := map[string]bool{
		"motion":                true,
		"lightMotion":           true,
		"sensorMotion":          true,
		"alarmHubMotion":        true,
		"smartDetectZone":       true,
		"smartDetectLine":       true,
		"smartDetectLoiterZone": true,
		"smartAudioDetect":      true,
	}

	for typ, m := range baseMappings {
		switch {
		case m.endClears && !motionShaped[typ]:
			t.Errorf("%q resolves itself on its own `end`; the end of an event window is not the end of the condition", typ)
		case motionShaped[typ] && !m.endClears:
			t.Errorf("%q has a real duration and must be resolved by its own `end`, or the incident never closes", typ)
		}
	}

	// The refined sensorAlarm mappings are a separate table and classify
	// returns them WHOLE, so a stray endClears there would not show up above.
	for alarmType, m := range alarmTypeMappings {
		if m.endClears {
			t.Errorf("alarmType %q resolves itself on its own `end`; a smoke alarm's window ending is not the smoke stopping", alarmType)
		}
	}
}

// A CAMERA THAT COMES BACK THROUGH CONNECTING STILL CLEARS ITS INCIDENT.
//
// CONNECTING emits nothing, because it is a transient on the way to a state we
// do not know yet -- but the registry was STORING it, which threw away the one
// state we did know. DISCONNECTED, CONNECTING, CONNECTED left prev=CONNECTING
// at the final step, and a clear only fires from DISCONNECTED, so the offline
// incident never resolved: it nagged at HIGH until a human closed it by hand,
// and the reconnect sweep could not repair it either, because by then the
// stored state was CONNECTED and there was no transition left to notice.
func TestAnOfflineCameraClearsWhenItReturnsThroughConnecting(t *testing.T) {
	r := newRegistry()
	base := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)

	type step struct {
		state      string
		wantCond   string
		wantClears bool
		wantEmit   bool
	}
	steps := []step{
		{"CONNECTED", "", false, false},
		{"DISCONNECTED", ConditionOffline, false, true},
		{"CONNECTING", "", false, false},
		{"CONNECTED", ConditionOffline, true, true},
	}
	for i, s := range steps {
		prev := r.observe(DeviceState{ID: "cam-1", State: s.state}, base.Add(time.Duration(i)*time.Second))
		cond, clears, emit := classifyState(prev, s.state)
		if cond != s.wantCond || clears != s.wantClears || emit != s.wantEmit {
			t.Errorf("step %d (%s, prev %s) = (%q, %v, %v), want (%q, %v, %v)",
				i, s.state, prev, cond, clears, emit, s.wantCond, s.wantClears, s.wantEmit)
		}
	}
}

// And a camera that was never seen to fail must still not announce a clear.
// CONNECTING must carry no information in EITHER direction, or it would
// resolve an incident opened by the Alarm Manager route on no evidence of our
// own.
func TestConnectingAloneDoesNotClearAnything(t *testing.T) {
	r := newRegistry()
	base := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)

	for i, state := range []string{"CONNECTING", "CONNECTED"} {
		prev := r.observe(DeviceState{ID: "cam-2", State: state}, base.Add(time.Duration(i)*time.Second))
		if _, clears, emit := classifyState(prev, state); clears || emit {
			t.Errorf("%s (prev %q) announced something: clears=%v emit=%v",
				state, prev, clears, emit)
		}
	}
}
