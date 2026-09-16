package protect

import (
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// The condition vocabulary now lives in internal/event, shared by every
// source, because a dedup key that differs by a typo is two incidents for one
// problem. These aliases keep this package's call sites readable without
// re-declaring the strings.
const (
	ConditionOffline          = event.ConditionOffline
	ConditionRing             = event.ConditionRing
	ConditionMotion           = event.ConditionMotion
	ConditionSmartDetect      = event.ConditionSmartDetect
	ConditionLoitering        = event.ConditionLoitering
	ConditionAudioDetect      = event.ConditionAudioDetect
	ConditionContactOpen      = event.ConditionContactOpen
	ConditionEntryOpen        = event.ConditionEntryOpen
	ConditionWaterLeak        = event.ConditionWaterLeak
	ConditionTamper           = event.ConditionTamper
	ConditionBatteryLow       = event.ConditionBatteryLow
	ConditionSmoke            = event.ConditionSmoke
	ConditionCarbonMonoxide   = event.ConditionCarbonMonoxide
	ConditionGlassBreak       = event.ConditionGlassBreak
	ConditionSensorAlarm      = event.ConditionSensorAlarm
	ConditionSmokeTest        = event.ConditionSmokeTest
	ConditionSmokeFault       = event.ConditionSmokeFault
	ConditionCOFault          = event.ConditionCOFault
	ConditionVape             = event.ConditionVape
	ConditionExtremeValues    = event.ConditionExtremeValues
	ConditionButtonPress      = event.ConditionButtonPress
	ConditionPanic            = event.ConditionPanic
	ConditionInputChanged     = event.ConditionInputChanged
	ConditionRelaySwitched    = event.ConditionRelaySwitched
	ConditionBatteryConnected = event.ConditionBatteryConnected
	ConditionCredentialScan   = event.ConditionCredentialScan
	ConditionStreamMute       = event.ConditionStreamMute
)

// mapping is what one Protect event type means in this product's vocabulary.
type mapping struct {
	condition string
	severity  incident.Severity

	// clears marks an event type that IS the end of a condition rather than
	// its start: sensorClosed is sensorOpened's clear, and without it a door
	// that closed stays open on the board forever.
	clears bool

	// endClears says the event's own `end` timestamp genuinely means the
	// condition stopped. True for motion-shaped things, which have a real
	// duration; FALSE for alarms, where the end of the event window says the
	// detection stopped being recorded, not that the smoke stopped.
	endClears bool
}

// baseMappings covers the v7.3.53 vocabulary (39 types). v6.2.83 carried 16 --
// everything alarmHub, NFC, fingerprint, vape and smoke-fault arrived later --
// so an older console simply never sends the rest rather than needing a gate
// here.
//
// Types absent from this table are NOT emitted; they are counted as
// unrecognised and their names are exposed through Health, because a firmware
// that invents an event type must show up as something an operator can see
// rather than as a source that quietly stopped covering a hazard.
var baseMappings = map[string]mapping{
	"ring": {condition: ConditionRing, severity: incident.SeverityLow},

	"motion":         {condition: ConditionMotion, severity: incident.SeverityLow, endClears: true},
	"lightMotion":    {condition: ConditionMotion, severity: incident.SeverityLow, endClears: true},
	"sensorMotion":   {condition: ConditionMotion, severity: incident.SeverityLow, endClears: true},
	"alarmHubMotion": {condition: ConditionMotion, severity: incident.SeverityLow, endClears: true},

	"smartDetectZone":       {condition: ConditionSmartDetect, severity: incident.SeverityMedium, endClears: true},
	"smartDetectLine":       {condition: ConditionSmartDetect, severity: incident.SeverityMedium, endClears: true},
	"smartDetectLoiterZone": {condition: ConditionLoitering, severity: incident.SeverityMedium, endClears: true},
	"smartAudioDetect":      {condition: ConditionAudioDetect, severity: incident.SeverityMedium, endClears: true},

	"sensorOpened": {condition: ConditionContactOpen, severity: incident.SeverityMedium},
	"sensorClosed": {condition: ConditionContactOpen, severity: incident.SeverityMedium, clears: true},

	"sensorWaterLeak": {condition: ConditionWaterLeak, severity: incident.SeverityHigh},
	"sensorTamper":    {condition: ConditionTamper, severity: incident.SeverityCritical},

	"sensorBatteryLow": {condition: ConditionBatteryLow, severity: incident.SeverityMedium},

	// sensorAlarm is refined by metadata.alarmType (smoke | CO | glassBreak);
	// see classify. This entry is the floor for an alarmType we cannot read --
	// an unreadable alarm is still an alarm, so it degrades to High rather
	// than to a plausible-looking guess at which kind.
	"sensorAlarm": {condition: ConditionSensorAlarm, severity: incident.SeverityHigh},

	"sensorVape":          {condition: ConditionVape, severity: incident.SeverityMedium},
	"sensorExtremeValues": {condition: ConditionExtremeValues, severity: incident.SeverityMedium},
	"sensorButtonPressed": {condition: ConditionButtonPress, severity: incident.SeverityLow},

	// The smoke-fault family is about a detector that cannot be relied on.
	// That is not an alarm, but it is not informational either: a smoke
	// detector at end of life is a hazard nobody notices until the fire.
	"sensorSmokeTest":          {condition: ConditionSmokeTest, severity: incident.SeverityLow},
	"sensorSmokeBatteryLow":    {condition: ConditionSmokeFault, severity: incident.SeverityHigh},
	"sensorSmokeNeedsCleaning": {condition: ConditionSmokeFault, severity: incident.SeverityMedium},
	"sensorSmokeFault":         {condition: ConditionSmokeFault, severity: incident.SeverityHigh},
	"sensorSmokeEndOfLife":     {condition: ConditionSmokeFault, severity: incident.SeverityHigh},
	"sensorCoFault":            {condition: ConditionCOFault, severity: incident.SeverityHigh},

	"relayInputChanged":         {condition: ConditionInputChanged, severity: incident.SeverityLow},
	"cameraDigitalInputChanged": {condition: ConditionInputChanged, severity: incident.SeverityLow},

	"alarmHubEntryOpened": {condition: ConditionEntryOpen, severity: incident.SeverityMedium},
	"alarmHubEntryClosed": {condition: ConditionEntryOpen, severity: incident.SeverityMedium, clears: true},

	"alarmHubSmoke":      {condition: ConditionSmoke, severity: incident.SeverityCritical},
	"alarmHubGlassBreak": {condition: ConditionGlassBreak, severity: incident.SeverityCritical},

	// A button on an alarm hub cannot be distinguished from a panic button on
	// the wire, and the two errors are not symmetric: a false page costs an
	// operator a minute, a missed panic press costs what panic buttons exist
	// to prevent. It escalates; a site that finds it noisy downgrades it in
	// rules, which is a decision they get to make knowingly.
	"alarmHubButtonPress": {condition: ConditionPanic, severity: incident.SeverityHigh},

	"alarmHubTamper":       {condition: ConditionTamper, severity: incident.SeverityCritical},
	"alarmHubDeviceTamper": {condition: ConditionTamper, severity: incident.SeverityCritical},

	"alarmHubRelaySwitched": {condition: ConditionRelaySwitched, severity: incident.SeverityLow},
	"alarmHubBatteryLow":    {condition: ConditionBatteryLow, severity: incident.SeverityMedium},

	// NOT modelled as the clear of alarmHubBatteryLow. The pairing is
	// plausible and unverified, and a wrong clear silently resolves a live
	// incident -- the one failure this product cannot have. It is emitted as
	// its own informational condition until somebody confirms it on hardware.
	"alarmHubBatteryConnected": {condition: ConditionBatteryConnected, severity: incident.SeverityInfo},

	"nfcCardScanned":        {condition: ConditionCredentialScan, severity: incident.SeverityInfo},
	"fingerprintIdentified": {condition: ConditionCredentialScan, severity: incident.SeverityInfo},
}

// alarmTypeMappings refines sensorAlarm by metadata.alarmType.text.
//
// Smoke, CO and glass break are the three that wake somebody up. Keys are
// matched lower-cased because Protect sends "CO" upper-case and "glassBreak"
// camel-case in the same field.
var alarmTypeMappings = map[string]mapping{
	"smoke":      {condition: ConditionSmoke, severity: incident.SeverityCritical},
	"co":         {condition: ConditionCarbonMonoxide, severity: incident.SeverityCritical},
	"glassbreak": {condition: ConditionGlassBreak, severity: incident.SeverityCritical},
}

// smartDetectSeverity raises a smart detection based on what was detected. A
// package on the porch and a person in the yard at 3am arrive as the same
// event type and are not the same alert.
func smartDetectSeverity(types []string) incident.Severity {
	sev := incident.SeverityLow
	for _, t := range types {
		switch strings.ToLower(t) {
		case "person", "vehicle", "animal":
			sev = incident.SeverityMedium
		}
	}
	return sev
}

// classify turns one decoded event item into this product's vocabulary.
// ok=false means the type is not in the table, which is a counted,
// operator-visible unknown rather than a silent drop.
func classify(it *item) (mapping, bool) {
	m, ok := baseMappings[it.Type]
	if !ok {
		return mapping{}, false
	}

	switch it.Type {
	case "sensorAlarm":
		if t, present := it.Metadata.Text("alarmType"); present {
			if refined, known := alarmTypeMappings[strings.ToLower(strings.TrimSpace(t))]; known {
				return refined, true
			}
		}
		// An unreadable alarmType keeps the High floor above: no information,
		// never a guess at which hazard it was.
	case "smartDetectZone", "smartDetectLine":
		m.severity = smartDetectSeverity(it.SmartDetectTypes)
	}
	return m, true
}

// The device connection enum. Camera disconnect is not an event type anywhere
// in Protect's 39-entry vocabulary; it is this field flipping on the devices
// channel, which is the whole reason this source opens two sockets.
const (
	stateConnected    = "CONNECTED"
	stateConnecting   = "CONNECTING"
	stateDisconnected = "DISCONNECTED"
)

// classifyState maps a device state transition to an event, or reports that
// there is nothing to say.
//
// CONNECTING deliberately produces nothing. It is a transient on the way to
// one of the other two, and reporting it either way reports a state we do not
// know yet.
func classifyState(prev, now string) (cond string, clears bool, emit bool) {
	switch normaliseState(now) {
	case stateDisconnected:
		if normaliseState(prev) == stateDisconnected {
			// Already reported. The devices channel re-sends a device's whole
			// record whenever anything about it changes, and the sweep re-reads
			// every device on every reconnect, so without this an outage that
			// lasts an hour emits an offline event every time either happens.
			return "", false, false
		}
		return ConditionOffline, false, true
	case stateConnected:
		// Only a return FROM a known-bad state clears. Announcing a clear for
		// a camera we never saw fail would resolve an incident opened by the
		// Alarm Manager route on no evidence of our own.
		if normaliseState(prev) == stateDisconnected {
			return ConditionOffline, true, true
		}
		return "", false, false
	default:
		return "", false, false
	}
}

// normaliseState returns the canonical enum value, or "" for a state this
// build does not recognise. "" means no information, and every caller treats
// it as such rather than defaulting to "probably online".
func normaliseState(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case stateConnected:
		return stateConnected
	case stateConnecting:
		return stateConnecting
	case stateDisconnected:
		return stateDisconnected
	default:
		return ""
	}
}
