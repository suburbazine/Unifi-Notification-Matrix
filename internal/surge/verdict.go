package surge

// The surge test, over two dimensions.
//
// SPREAD CARRIES THE VERDICT AND VOLUME NEVER DOES ALONE. Every case where
// volume is high by itself is a case this product must not call a surge -- a
// flapping camera, a busy driveway, one door being worked on -- and every case
// that IS a surge shows in spread: nine devices dropping, a person crossing
// six fields of view. Volume is still reported, because "9 devices, 14 events"
// (things going quiet) and "9 devices, 400 events" (a lot happening) are
// different situations, but that is information and not a decision.
const (
	// MinDevices is the hard floor. One flapping camera is one device and the
	// dedup key already says so; two is a camera and a coincidence. Below
	// three, nothing is ever a surge whatever the volume.
	MinDevices = 3

	// The margins. Spread needs a smaller one than volume, and that is forced
	// by the data rather than chosen: event counts are over-dispersed -- one
	// person triggers twenty motion events, so counts cluster -- while a
	// distinct-device count is a sum of per-device yes/no outcomes with
	// variance at most its mean, and is capped by the number of devices on
	// site. On a site where fifteen devices are normally active, the device
	// count CANNOT double, so a 2x spread rule would be blind on exactly the
	// busiest sites.
	DeviceFactor = 1.5
	DeviceFloor  = 3
	EventFactor  = 3
	EventFloor   = 10

	// QuietMinDevices is the floor below which quiet means nothing.
	//
	// On a slot that is normally silent, silence carries no information and
	// the detector cannot tell "jammed at 3am" from "3am". This is why the
	// jamming case is caught as a BUSY verdict -- the disconnect burst the
	// jamming causes -- rather than as the silence that follows it.
	QuietMinDevices = 4
	QuietFloor      = 3
)

// Judge decides what a stretch of activity was, given what is typical.
//
// Returns Ordinary when the baseline has not been earned: a comparison this
// product has not earned is one it does not state.
func Judge(events, devices int, st Stats) Verdict {
	if !st.Earned {
		return Ordinary
	}

	// Path A -- spread. The primary signal, and the one the jamming case
	// arrives on.
	if devices >= MinDevices &&
		devices > st.P90Devices &&
		float64(devices) >= DeviceFactor*float64(st.MedianDevices) &&
		devices >= st.MedianDevices+DeviceFloor {
		return Busy
	}

	// Path B -- volume, and only when it is not concentrated. The honest
	// exception: the usual set of devices, all far busier than usual. The
	// device clause is what stops one noisy thing carrying it.
	if devices >= MinDevices && devices >= st.MedianDevices &&
		events > st.P90Events &&
		float64(events) >= EventFactor*float64(st.MedianEvents) &&
		events >= st.MedianEvents+EventFloor {
		return Busy
	}

	// Quiet is a spread verdict, with one clause the design did not have and
	// its own test case demanded: A SITE PRODUCING MORE EVENTS THAN USUAL IS
	// NOT QUIET, whatever the spread.
	//
	// Found by 210 events across 4 devices against a typical 20 across 9 --
	// written down as "neutral, concentrated" and judged QUIET by the
	// formula, because four devices is below the tenth percentile and nothing
	// was looking at the volume. An alert decorated "unusually quiet" while
	// ten times the usual traffic goes through it is worse than no
	// decoration: it is the product asserting the opposite of the truth.
	if events <= st.MedianEvents &&
		st.MedianDevices >= QuietMinDevices &&
		devices < st.P10Devices &&
		float64(devices) <= float64(st.MedianDevices)/2 &&
		devices <= st.MedianDevices-QuietFloor {
		return Quiet
	}

	return Ordinary
}
