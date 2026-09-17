package event

import "sort"

// The catalogue: what every condition MEANS, and which surface produces it.
//
// It exists because the interface asked operators to type a condition into a
// free-text box. The vocabulary was finite, documented in the comments beside
// the constants above, and already loaded in the browser for inbound hooks --
// and nowhere near the Rules editor, where Source and Severity both got a
// dropdown and the one field with a fixed vocabulary did not.
//
// A mistyped condition does not fail loudly. The rule simply never matches, so
// a rule meant to silence a noisy camera does not silence it and a rule meant
// to escalate does not escalate, and nothing anywhere says so.
//
// WHAT THIS LIST IS: every condition a rule can match, because rules match
// this build's vocabulary and this is all of it.
//
// WHAT IT IS NOT: everything UniFi might send. Firmware emits types this build
// does not map, and those arrive as an unrecognised-type count rather than as
// a condition. "notifymatrix probe" asks a console what it actually exposes,
// which is the only honest answer for a particular site. A picker quietly
// implies completeness, so the interface has to say which of those two
// questions it is answering.
const (
	SurfaceProtect  = "protect"
	SurfaceAccess   = "access"
	SurfaceNetwork  = "network"
	SurfaceInbound  = "inbound"
	SurfaceInternal = "internal"
)

// ConditionDoc is one entry in the catalogue.
type ConditionDoc struct {
	// Name is the string a rule matches on, and the string stored in every
	// dedup key that uses it.
	Name string `json:"name"`

	// Group orders the list for a human reader.
	Group string `json:"group"`

	// Meaning is one sentence an operator can act on, rather than a
	// restatement of the name. "motion: motion was detected" helps nobody.
	Meaning string `json:"meaning"`

	// Sources are the surfaces observed to emit it in THIS build, read off the
	// mapping tables rather than from intent. Empty means no source emits it
	// directly and it reaches this product only through an inbound webhook the
	// operator points at it.
	Sources []string `json:"sources"`
}

// Groups, in the order somebody would want to read them.
const (
	GroupHealth     = "Reachability and health"
	GroupDetection  = "Detections"
	GroupOpening    = "Openings"
	GroupLifeSafety = "Life safety"
	GroupDetector   = "Detector self-reporting"
	GroupIO         = "Inputs and credentials"
	GroupDoors      = "Doors"
	GroupNetwork    = "Network"
	GroupSelf       = "This product reporting on itself"
)

// catalogue is the single table. Every Condition* constant must appear here:
// TestEveryConditionIsInTheCatalogue fails if one is added without a meaning,
// which is what keeps this from becoming a list that is quietly wrong.
var catalogue = []ConditionDoc{
	{ConditionOffline, GroupHealth,
		"A device stopped being reachable -- a camera, a sensor, an Access hub, a Network device.",
		[]string{SurfaceProtect, SurfaceAccess, SurfaceNetwork}},
	{ConditionBatteryLow, GroupHealth,
		"A battery-powered sensor is running out. It will stop reporting before it tells you again.",
		[]string{SurfaceProtect}},
	{ConditionBatteryConnected, GroupHealth,
		"A sensor went back onto external power. The clear for a battery warning.",
		[]string{SurfaceProtect}},

	{ConditionRing, GroupDetection,
		"Somebody pressed a doorbell.",
		[]string{SurfaceProtect}},
	{ConditionMotion, GroupDetection,
		"Plain motion, with no judgement about what moved. On most sites this is the noisiest condition there is.",
		[]string{SurfaceProtect}},
	{ConditionSmartDetect, GroupDetection,
		"Protect classified what it saw -- person, vehicle, animal, package. Which one travels in the detail, not in the condition.",
		[]string{SurfaceProtect}},
	{ConditionLoitering, GroupDetection,
		"Somebody stayed in a zone longer than that camera's loitering setting allows.",
		[]string{SurfaceProtect}},
	{ConditionAudioDetect, GroupDetection,
		"The camera recognised a sound it was told to listen for.",
		[]string{SurfaceProtect}},

	{ConditionContactOpen, GroupOpening,
		"A contact sensor on a door or window opened. No arming state is involved.",
		[]string{SurfaceProtect}},
	{ConditionEntryOpen, GroupOpening,
		"An alarm hub entry point opened. Unlike a bare contact, the hub knows whether it is armed.",
		[]string{SurfaceProtect}},

	{ConditionSmoke, GroupLifeSafety,
		"A smoke detector is alarming.",
		[]string{SurfaceProtect}},
	{ConditionCarbonMonoxide, GroupLifeSafety,
		"A carbon monoxide detector is alarming.",
		[]string{SurfaceProtect}},
	{ConditionGlassBreak, GroupLifeSafety,
		"A glass-break sensor fired.",
		[]string{SurfaceProtect}},
	{ConditionWaterLeak, GroupLifeSafety,
		"A leak sensor is wet.",
		[]string{SurfaceProtect}},
	{ConditionSensorAlarm, GroupLifeSafety,
		"A sensor alarmed in a way this build could not classify further. Treated as serious rather than discarded.",
		[]string{SurfaceProtect}},
	{ConditionPanic, GroupLifeSafety,
		"A panic button was pressed.",
		[]string{SurfaceProtect}},
	{ConditionTamper, GroupLifeSafety,
		"A device reported being interfered with -- opened, removed, or covered.",
		[]string{SurfaceProtect}},

	{ConditionSmokeTest, GroupDetector,
		"A smoke detector ran its self-test. Routine, and usually worth silencing with a rule.",
		[]string{SurfaceProtect}},
	{ConditionSmokeFault, GroupDetector,
		"A smoke detector says it is faulty. A detector in fault is a detector that will not alarm.",
		[]string{SurfaceProtect}},
	{ConditionCOFault, GroupDetector,
		"A carbon monoxide detector says it is faulty.",
		[]string{SurfaceProtect}},
	{ConditionExtremeValues, GroupDetector,
		"A sensor is reading outside its sane range -- a temperature or humidity the room could not actually be.",
		[]string{SurfaceProtect}},
	{ConditionVape, GroupDetector,
		"A vape or air-quality sensor tripped.",
		[]string{SurfaceProtect}},

	{ConditionButtonPress, GroupIO,
		"A hardware button on a device was pressed.",
		[]string{SurfaceProtect}},
	{ConditionInputChanged, GroupIO,
		"A wired input on a device changed state.",
		[]string{SurfaceProtect}},
	{ConditionRelaySwitched, GroupIO,
		"A relay output was switched.",
		[]string{SurfaceProtect}},
	{ConditionCredentialScan, GroupIO,
		"A credential was presented to a reader -- a card, a fob, a code, a face.",
		[]string{SurfaceProtect}},

	{ConditionDoorForced, GroupDoors,
		"A door opened without being unlocked. NEEDS A POSITION SENSOR fitted, and most doors do not have one.",
		[]string{SurfaceAccess}},
	{ConditionDoorHeld, GroupDoors,
		"A door was left open longer than allowed. Also needs a position sensor.",
		[]string{SurfaceAccess}},
	{ConditionAccessDenied, GroupDoors,
		"Somebody presented a credential and was refused.",
		[]string{SurfaceAccess}},
	{ConditionDoorUnlocked, GroupDoors,
		"A door was put into remain-unlocked state, so it is standing open to anybody.",
		[]string{SurfaceAccess}},
	{ConditionAccessCritical, GroupDoors,
		"A row from Access's own critical log. One condition for the whole topic; which row it was travels in the detail.",
		[]string{SurfaceAccess}},

	{ConditionWANDown, GroupNetwork,
		"The site's internet connection dropped. Reaches this product only through an Alarm Manager webhook.",
		[]string{SurfaceInbound}},
	{ConditionThreat, GroupNetwork,
		"Threat management flagged traffic. Webhook only.",
		[]string{SurfaceInbound}},
	{ConditionPoEFault, GroupNetwork,
		"A PoE port faulted, so whatever it powers is now off. Webhook only, and nothing points a hook at it by default.",
		nil},
	{ConditionClientLost, GroupNetwork,
		"A client this site watches disappeared from the network. Webhook only, and nothing points a hook at it by default.",
		nil},
	{ConditionInboundAlarm, GroupNetwork,
		"An alarm arrived on a webhook that was never given a more specific meaning.",
		[]string{SurfaceInbound}},

	{ConditionStreamMute, GroupSelf,
		"A source connected and nothing it sent could be understood. A live-but-mute stream is silent total failure of that source.",
		[]string{SurfaceProtect, SurfaceAccess}},
	{ConditionSourceSilent, GroupSelf,
		"A source stopped being in contact with its console for longer than it promised.",
		[]string{SurfaceInternal}},
	{ConditionUncleanShutdown, GroupSelf,
		"The daemon did not shut down cleanly last time, so alarms may have been missed while it was down.",
		[]string{SurfaceInternal}},
}

// Catalogue returns every condition a rule can match, with what it means.
//
// A copy each time. The caller renders it into JSON for a browser, and a
// package-level slice handed out by reference is a table anybody can rewrite.
func Catalogue() []ConditionDoc {
	out := make([]ConditionDoc, len(catalogue))
	copy(out, catalogue)
	return out
}

// ConditionNames returns the bare vocabulary, sorted.
func ConditionNames() []string {
	out := make([]string, 0, len(catalogue))
	for _, c := range catalogue {
		out = append(out, c.Name)
	}
	sort.Strings(out)
	return out
}
