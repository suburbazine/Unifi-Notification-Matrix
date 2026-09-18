package link

import "time"

// Delivery states reported back to a peer on an accepted event.
const (
	DeliveryOK       = "ok"
	DeliveryDegraded = "degraded"
)

// ChannelState is the health of one delivery channel, as the reply needs it.
//
// A local shape rather than the web layer's, so this package does not depend
// on the interface to answer a question about the engine.
type ChannelState struct {
	Name             string
	Enabled          bool
	ConsecutiveFails int
	BackingOffUntil  time.Time
}

// DeliveryStatus reports whether this product's channels can currently deliver.
//
// WHAT IT MEANS, PRECISELY: the notifier's channels are sick right now. It is
// NOT a receipt. The reply is written at INGEST, before the event has been
// through a rule, opened an incident, or reached a ladder -- so at the moment
// it is written nothing has happened to that alert at all, and saying "your
// alert was not delivered" would be a claim about the future.
//
// The peer uses it to decide whether to ALSO tell the human through its own
// channels. Because it is a snapshot rather than an outcome, a peer acting on
// it may duplicate an alert this product then delivers perfectly well. That is
// the safe direction and is deliberate.
//
// DEGRADED MEANS BROKEN, NEVER "CHOSE NOT TO SEND". Quiet hours, a ladder that
// has given up, an acknowledged incident, a rule that silenced something --
// every one of those is the operator's policy working exactly as configured.
// Reporting any of them as degraded would have a peer second-guessing the
// operator's own quiet hours with duplicate alerts at 3am, which is the same
// inversion as importing a watch window as quiet hours. Channel failures only.
func DeliveryStatus(channels []ChannelState, now time.Time) string {
	enabled := 0
	for _, c := range channels {
		if !c.Enabled {
			continue
		}
		enabled++
		// Backing off is not "fine": a channel being held back after repeated
		// failures is not being attempted, and a channel that is not being
		// attempted must not read as healthy.
		if c.ConsecutiveFails > 0 || now.Before(c.BackingOffUntil) {
			return DeliveryDegraded
		}
	}
	if enabled == 0 {
		// Nothing can be delivered at all. Reported as degraded on purpose,
		// including for a freshly paired install whose channels are not
		// configured yet: pairing early must not create a silent gap. The
		// operator sees doubled notifications until setup is finished, which
		// the setup checklist should say rather than leave looking like a bug.
		return DeliveryDegraded
	}
	return DeliveryOK
}
