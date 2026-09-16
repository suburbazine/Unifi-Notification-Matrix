package access

import (
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// severities proposed by this source.
//
// Proposals, not decisions -- rules may override them, because a source knows
// what happened and not how much a particular site cares. The ordering between
// them is the part worth arguing about:
//
//   - FORCED is critical. It is the alarm an access-control system exists for
//     and the one UniFi does not re-notify about.
//   - HELD is high, not critical. A propped door is a real breach of a
//     controlled boundary, but it is far more often a delivery than an
//     intrusion, and a site whose deliveries page somebody at critical will
//     switch the product off.
//   - DENIED is medium. One refused badge is somebody with the wrong card;
//     the dedup key collapses repeats at one door into one incident, so a
//     sustained attempt escalates as a single thing that keeps nagging rather
//     than as fifty alerts.
//   - REMAIN-UNLOCKED is informational. See event.ConditionDoorUnlocked: this
//     source cannot tell a scheduled unlock from a manual one, so anything
//     higher pages every site with business hours, every morning.
var severities = map[string]incident.Severity{
	event.ConditionDoorForced:     incident.SeverityCritical,
	event.ConditionDoorHeld:       incident.SeverityHigh,
	event.ConditionAccessDenied:   incident.SeverityMedium,
	event.ConditionAccessCritical: incident.SeverityHigh,
	event.ConditionDoorUnlocked:   incident.SeverityInfo,
	event.ConditionStreamMute:     incident.SeverityHigh,
}

var titles = map[string]string{
	event.ConditionDoorForced:     "Door opened while locked",
	event.ConditionDoorHeld:       "Door held open",
	event.ConditionAccessDenied:   "Access denied",
	event.ConditionAccessCritical: "Access reported a critical event",
	event.ConditionDoorUnlocked:   "Door set to remain unlocked",
}

// eventFromTransition renders a derived door-state change.
func (s *Source) eventFromTransition(t transition) event.Event {
	now := s.cfg.Now()
	name := t.door.name
	if name == "" {
		name = "door " + t.door.id
	}
	title := titles[t.condition]
	if t.clears {
		title = "Cleared: " + title
	}
	return event.Event{
		Source:    SourceName,
		Kind:      t.condition,
		Condition: t.condition,
		Clears:    t.clears,
		Entity:    event.Entity{ID: t.door.id, Name: name, Kind: "door"},
		Severity:  severities[t.condition],
		Title:     title + " — " + name,
		Detail:    t.detail,

		// Derived conditions have no console timestamp: nothing on any Access
		// surface reports them, which is why this package derives them. The
		// time is when WE noticed, and saying so keeps an alert from sending
		// somebody to the wrong point in the footage.
		At:              now,
		ReceivedAt:      now,
		AtIsArrivalTime: true,
	}
}

// eventFromLog renders a system-log row, or reports that no rule matched it.
//
// The false return is not a failure path. The log key vocabulary has never
// been enumerated from hardware, so rows this source has no rule for are
// expected -- they are counted by name in Health and surfaced, which is how
// the vocabulary gets established, rather than being silently dropped or
// guessed into a condition.
func (s *Source) eventFromLog(r logRow) (event.Event, bool) {
	var (
		condition string
		severity  incident.Severity
	)
	switch {
	case r.topic == topicDoorOpenings && isDenial(r.hit):
		condition = event.ConditionAccessDenied
	case r.topic == topicCritical:
		condition = event.ConditionAccessCritical
	default:
		// A successful door opening is not an incident. It is the system
		// working, and putting it on a board that exists for things that need
		// a human would bury the denials in them.
		return event.Event{}, false
	}
	severity = severities[condition]

	src := r.hit.Source
	ent := event.Entity{Kind: "door"}
	if d, ok := src.door(); ok {
		ent.ID = d.ID
		ent.Name = s.doors.nameOf(d.ID, strings.TrimSpace(d.DisplayName))
	}
	if ent.ID == "" {
		// No door on the row. Attributed to the console rather than invented,
		// so the incident still exists and still nags, and still says what it
		// does and does not know.
		ent = event.Entity{ID: "site", Name: "UniFi Access", Kind: "site"}
	}
	if ent.Name == "" {
		ent.Name = "door " + ent.ID
	}

	at, known := r.hit.at()
	now := s.cfg.Now()
	if !known {
		at = now
	}

	detail := strings.TrimSpace(src.Event.DisplayMessage)
	if detail == "" {
		detail = strings.TrimSpace(src.Event.LogKey)
	}
	who := src.Actor.who()
	if actorIsHardware(src.Actor) {
		// The row is actored by the hub, not by a person. Naming it would put
		// the reader's name on somebody else's refusal -- hubs carry display
		// names and are frequently named after the door they serve.
		who = "a credential"
	}
	if condition == event.ConditionAccessDenied {
		detail = who + " was refused at " + ent.Name
		if p := strings.TrimSpace(src.Authentication.CredentialProvider); p != "" {
			detail += " (" + p + ")"
		}
		if msg := strings.TrimSpace(src.Event.DisplayMessage); msg != "" {
			detail += ": " + msg
		}
	}

	return event.Event{
		// The row id suppresses re-processing when an overlapping window
		// returns the same row twice. Belt and braces with the poller's own
		// de-duplication, because the two protect different things: the poller
		// stops a re-read, this stops a re-emit after a restart.
		ID:        r.hit.ID,
		Source:    SourceName,
		Kind:      r.topic + "/" + strings.TrimSpace(src.Event.LogKey),
		Condition: condition,
		Entity:    ent,
		Severity:  severity,
		Title:     titles[condition] + " — " + ent.Name,
		Detail:    detail,

		At:         at,
		ReceivedAt: now,
		// The system log lags by up to three and a half minutes, so At is
		// genuinely the event time when the row carried one -- and genuinely
		// minutes stale when it did not. The flag is the difference.
		AtIsArrivalTime: !known,
	}, true
}

// actorIsHardware reports whether a log row was actored by a hub rather than a
// person.
//
// Kept as a named helper because the discrimination is easy to get wrong:
// hubs have display names too, and they are frequently named after the door
// they serve, so a name test attributes a hardware event to a person who was
// nowhere near the building.
func actorIsHardware(a logActor) bool { return !a.isPerson() }
