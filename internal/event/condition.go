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

	// Access. Doors, not cameras, and the failure modes do not overlap.
	//
	// Three alarm classes that a reader might expect here are deliberately
	// absent, because UniFi Access does not represent them and inventing a
	// condition for something no surface reports would put a permanently
	// silent entry on the board:
	//
	//   - TAMPER has no confirmed representation on any Access surface.
	//   - BATTERY-LOW does not apply: the line is PoE end to end, and the only
	//     battery is an external backup on the Enterprise hub.
	//   - ANTI-PASSBACK is not a shipping feature. It has been requested since
	//     2022 and acknowledged three times by Ubiquiti staff without ever
	//     appearing. An earlier research pass reported it as real; that was
	//     wrong (SOURCES.md §2). Do not add a rule for it.
	ConditionDoorForced   = "door-forced-open"
	ConditionDoorHeld     = "door-held-open"
	ConditionAccessDenied = "access-denied"

	// ConditionDoorUnlocked is a door in Access's "remain unlocked" state.
	//
	// Emitted at a low severity on purpose. Nothing on any Access surface
	// distinguishes a SCHEDULED unlock from one somebody set by hand -- unlock
	// schedule events never reach the log API at all -- so a site with an
	// ordinary business-hours schedule would be paged every morning. It goes
	// on the board, and a site that has no schedules can raise it with a rule,
	// which is a decision they get to make knowingly.
	ConditionDoorUnlocked = "door-remain-unlocked"

	// ConditionAccessCritical relays a row from Access's own `critical` log
	// topic.
	//
	// ONE condition for the whole topic rather than one per log key. The key
	// vocabulary has never been enumerated from hardware, and a condition
	// minted from an unrecognised key would put an unbounded, unreviewable set
	// of strings into stored dedup keys -- which is the one thing in this
	// vocabulary that cannot be undone cheaply. The key travels in the event's
	// Kind and Detail instead, where it is readable without being load-bearing.
	ConditionAccessCritical = "access-critical"

	// Network. Its Integration API carries no events of any kind -- the
	// OpenAPI spec contains zero occurrences of "event", "alarm", "webhook" or
	// "subscribe" -- so everything here arrives either by polling device state
	// or through an Alarm Manager webhook the operator configured by hand.
	ConditionWANDown    = "wan-down"
	ConditionThreat     = "threat-detected"
	ConditionPoEFault   = "poe-fault"
	ConditionClientLost = "client-lost"

	// ConditionInboundAlarm is an alarm that arrived on a webhook the operator
	// did not give a specific meaning to.
	//
	// Deliberately generic rather than parsed out of the body. Alarm Manager's
	// payload is undocumented and has spelled its message field four different
	// ways across firmware, so a condition derived from it would be a guess
	// baked into a stored dedup key. The operator attaches meaning by pointing
	// each Alarm Manager rule at its own hook URL; this is what a hook means
	// until they do.
	ConditionInboundAlarm = "inbound-alarm"

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
