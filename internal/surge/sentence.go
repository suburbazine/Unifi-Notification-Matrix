package surge

import "fmt"

// The sentence.
//
// THE VERDICT IS THE PREFIX, so a push notification truncated after forty
// characters still carries it. Counts are integers that occurred; "typical" is
// the median; and the justification clause names the quantile in words an
// operator can check against the numbers in front of them.
//
// NO RATIO EVER APPEARS. "6x normal" is unreadable at the small end -- two
// events against a typical of 0.3 -- and invites an argument about the
// arithmetic instead of a look at the site. Both numbers are shown; whoever
// reads it can divide, or not.
func Sentence(events, devices int, st Stats, slot Slot, v Verdict) string {
	switch {
	case !st.Earned:
		return learning(events, devices, st)
	case v == Busy:
		return busy(events, devices, st, slot)
	case v == Quiet:
		return quiet(events, devices, st, slot)
	default:
		return fmt.Sprintf("Site activity: %s in the last 10 minutes; typical for %s is %s.",
			countPhrase(events, devices), slot.Name(), typicalPhrase(st))
	}
}

// learning says what it is waiting for rather than being vague about it. A
// count with no comparison is still a fact; a comparison from four days of
// history is not.
func learning(events, devices int, st Stats) string {
	if st.LearnedDays < MinDays {
		return fmt.Sprintf("Site activity: %s in the last 10 minutes; no typical "+
			"figure yet (%d of %d days learned).",
			countPhrase(events, devices), st.LearnedDays, MinDays)
	}
	return fmt.Sprintf("Site activity: %s in the last 10 minutes; no typical figure "+
		"for this hour yet (%d of %d comparable stretches seen).",
		countPhrase(events, devices), st.Samples, MinSamples)
}

func busy(events, devices int, st Stats, slot Slot) string {
	// Which clause carried it decides which number is quoted: quoting the
	// device quantile on a volume verdict would print a justification the
	// count in the same sentence does not satisfy.
	why := fmt.Sprintf("9 of 10 such stretches see %s or fewer", devicePhrase(st.P90Devices))
	if devices <= st.P90Devices {
		why = fmt.Sprintf("9 of 10 such stretches see %s or fewer", eventPhrase(st.P90Events))
	}
	return fmt.Sprintf("Site unusually busy: %s in the last 10 minutes; typical for %s is %s, and %s.",
		countPhrase(events, devices), slot.Name(), typicalPhrase(st), why)
}

func quiet(events, devices int, st Stats, slot Slot) string {
	return fmt.Sprintf("Site unusually quiet: %s in the last 10 minutes; typical for %s is %s, "+
		"and 9 of 10 such stretches see at least %s.",
		countPhrase(events, devices), slot.Name(), typicalPhrase(st), devicePhrase(st.P10Devices))
}

// countPhrase is "no events", "1 event across 1 device", "14 events across 9
// devices". Zero reads as a sentence rather than as "0 events across 0
// devices", which is the shape of a bug report.
func countPhrase(events, devices int) string {
	if events == 0 {
		return "no events"
	}
	return fmt.Sprintf("%s across %s", eventPhrase(events), devicePhrase(devices))
}

// typicalPhrase is "3 across 2", or "none" for a slot that is normally silent.
func typicalPhrase(st Stats) string {
	if st.MedianEvents == 0 && st.MedianDevices == 0 {
		return "none"
	}
	return fmt.Sprintf("%d across %d", st.MedianEvents, st.MedianDevices)
}

func eventPhrase(n int) string {
	if n == 1 {
		return "1 event"
	}
	return fmt.Sprintf("%d events", n)
}

func devicePhrase(n int) string {
	if n == 1 {
		return "1 device"
	}
	return fmt.Sprintf("%d devices", n)
}
