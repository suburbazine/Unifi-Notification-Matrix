package event

// The normalised condition vocabulary, shared by every source.
//
// These strings are part of the dedup key (see Event.DedupKey), so the same
// real-world problem reported by two different routes has to use the SAME
// string or it becomes two incidents that both nag. That is not hypothetical:
// a camera going offline can arrive on Protect's devices WebSocket and again
// as an Alarm Manager "Device Issue" webhook, and Access hub-offline arrives
// on a third path entirely.
//
// They live HERE, not in any one source package, for exactly that reason. A
// source that retypes the literal instead of referencing the constant has
// introduced a dedup key that differs by a typo, and a dedup key that differs
// by a typo is two incidents for one problem — which is the failure mode this
// product exists to avoid, arriving through the back door.
//
// Adding a condition is cheap. Renaming one is not: the string is persisted in
// every stored incident's dedup key, so a rename splits open incidents from
// their own history and needs a migration.
const (
	// Reachability and health.
	ConditionOffline          = "offline"
	ConditionBatteryLow       = "battery-low"
	ConditionBatteryConnected = "battery-connected"

	// Detections.
	ConditionRing        = "doorbell-ring"
	ConditionMotion      = "motion"
	ConditionSmartDetect = "smart-detect"
	ConditionLoitering   = "loitering"
	ConditionAudioDetect = "audio-detect"

	// Openings. ConditionContactOpen is a sensor on a door or window;
	// ConditionEntryOpen is an alarm-hub entry point. They are distinct
	// because the alarm hub arms and disarms and a bare contact does not.
	ConditionContactOpen = "contact-open"
	ConditionEntryOpen   = "entry-open"

	// Life safety. These are the reason the product exists, and they are the
	// severities that must never be mutable into silence (see escalate.Policy).
	ConditionSmoke          = "smoke"
	ConditionCarbonMonoxide = "carbon-monoxide"
	ConditionGlassBreak     = "glass-break"
	ConditionWaterLeak      = "water-leak"
	ConditionSensorAlarm    = "sensor-alarm"
	ConditionPanic          = "panic-button"
	ConditionTamper         = "tamper"

	// Detector self-reporting: the smoke detector telling us it is unwell.
	// Distinct from an actual alarm, and far from unimportant — a detector in
	// fault is a detector that will not alarm.
	ConditionSmokeTest     = "smoke-test"
	ConditionSmokeFault    = "smoke-fault"
	ConditionCOFault       = "co-fault"
	ConditionExtremeValues = "extreme-values"
	ConditionVape          = "vape"

	// I/O and credentials.
	ConditionButtonPress    = "button-press"
	ConditionInputChanged   = "input-changed"
	ConditionRelaySwitched  = "relay-switched"
	ConditionCredentialScan = "credential-scan"

	// ConditionStreamMute is a source reporting on ITSELF: a stream that
	// connected and whose traffic has never been understood. See
	// DESIGN-RULES.md §2 — a live-but-mute stream is a fault, not a success,
	// and on unfamiliar hardware it is silent total failure of that source.
	ConditionStreamMute = "stream-unintelligible"

	// ConditionSourceSilent is the deadman: a source that has said nothing for
	// longer than its declared liveness window. Raised by the supervisor, not
	// by the source, because a source that has stopped working is in no
	// position to report it.
	ConditionSourceSilent = "source-silent"

	// ConditionUncleanShutdown is the product reporting its own crash, raised
	// at start when the previous exit left no clean-shutdown marker
	// (ARCHITECTURE.md §9a). Without it a crash loop is invisible: the service
	// restarts, the UI looks healthy, and the only evidence is a gap in the
	// history that nobody reads.
	ConditionUncleanShutdown = "unclean-shutdown"
)
