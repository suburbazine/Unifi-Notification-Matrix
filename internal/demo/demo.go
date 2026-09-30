// Package demo serves the real interface over fabricated data, so the product
// can be seen -- or screenshotted -- without a UniFi console, an API key, or a
// single real camera.
//
// The value is adoption: the whole claim of this product is that an alarm
// reaches somebody and keeps asking until it does, and that is not a claim a
// README can make convincingly. Somebody should be able to look at the board
// before deciding whether to point it at their doors.
//
// # What demo mode must never do
//
// It fabricates security alarms. That makes it dangerous in three specific
// ways, and each one is guarded rather than discouraged:
//
//   - It must never DELIVER. A fabricated "door forced open" arriving on
//     somebody's phone is indistinguishable from a real one, and the second
//     time it happens they stop believing the first. The daemon wires a
//     delivery function that refuses, so no channel is constructed at all.
//
//   - It must never run against a real installation. Demo incidents in a real
//     store are noise mixed into the record an operator is supposed to trust,
//     and noise is how alarms get ignored. Refuse() checks the data directory
//     and stops before anything is written.
//
//   - It must be impossible to mistake for the real thing. Everything here is
//     marked, in the incidents themselves and on every screen.
//
// A demo mode that can be switched on by editing a config file would be a
// persistence mechanism; this one is a command-line verb and nothing else
// reads it.
package demo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// Banner is shown on every screen, and says the one thing a viewer has to
// know.
const Banner = "DEMO — these alarms are fabricated. Nothing is being watched and nothing will be delivered."

// ErrRealInstall refuses a demo run that would write into a real one.
var ErrRealInstall = errors.New("demo: this data directory belongs to a real installation")

// Refuse reports why a demo must not run against this data directory.
//
// The test is for evidence of a real installation rather than for a marker
// this package writes: a marker would be missing on exactly the directory that
// matters, the one somebody points at by accident with --data-dir.
func Refuse(dataDir string) error {
	for _, name := range []string{"config.yaml", "incidents.db", "audit.jsonl"} {
		p := filepath.Join(dataDir, name)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%w: %s already exists. Demo mode fabricates alarms, "+
				"and mixing those into a real record is how real ones stop being "+
				"believed. Run it with --data-dir pointing somewhere new", ErrRealInstall, p)
		}
	}
	return nil
}

// RefuseDelivery is the delivery function a demo run uses.
//
// Not "a channel that silently drops": there is no channel. If anything ever
// reaches here it is a bug, and it says so rather than looking like a delivery
// that worked.
func RefuseDelivery(context.Context, *incident.Incident, int, []string) error {
	return errors.New("demo: nothing is delivered in demo mode")
}

// Seed fills a store with a board that looks like a real site mid-incident.
//
// Chosen to show the things that distinguish this product rather than a
// plausible average: an unacknowledged critical still escalating, one that was
// acknowledged but whose condition has NOT cleared, a delivery that is
// failing, and a recurrence. Those are the states a notification list cannot
// represent, and they are the argument for incidents existing at all.
func Seed(ctx context.Context, st incident.Store, now time.Time) error {
	keeper, keeps := st.(occurrenceStore)
	for _, s := range board(now) {
		if err := st.Put(ctx, s.inc); err != nil {
			return fmt.Errorf("demo: seeding: %w", err)
		}
		if !keeps {
			continue
		}
		for _, o := range s.occ {
			if err := keeper.AddOccurrence(ctx, s.inc.ID, o, 0); err != nil {
				return fmt.Errorf("demo: seeding occurrences of %s: %w", s.inc.ID, err)
			}
		}
	}
	return nil
}

// occurrenceStore is the part of a store that keeps each arrival of a
// per-occurrence condition in full. Optional, as it is in the web package: a
// store without it still gets the incident and its count.
type occurrenceStore interface {
	AddOccurrence(ctx context.Context, incidentID string, o incident.Occurrence, keep int) error
}

// seeded is one fabricated incident and, for a per-occurrence condition, every
// arrival that was folded into it.
type seeded struct {
	inc *incident.Incident
	occ []incident.Occurrence
}

func script(now time.Time) []*incident.Incident {
	var out []*incident.Incident
	for _, s := range board(now) {
		out = append(out, s.inc)
	}
	return out
}

// board is the script with the per-occurrence incidents' arrivals beside them.
func board(now time.Time) []seeded {
	var out []seeded
	for _, inc := range ordinary(now) {
		out = append(out, seeded{inc: inc})
	}
	return append(out, perOccurrence(now)...)
}

// perOccurrence fabricates the incidents a paired point-of-sale peer raises:
// conditions where every arrival is a new fact, folded into one live incident
// that keeps each of them.
//
// Three states, because each is a thing the board has to show: a run of voids
// that was acknowledged and then CLOSED by the next void arriving -- reviewed
// once does not mean reviewed for ever -- and the fresh incident that void
// opened, linked back to it; and a condition that has happened more times
// than the incident keeps the detail of, so the board has to say that the
// older ones are gone rather than imply the list is complete.
func perOccurrence(now time.Time) []seeded {
	var out []seeded

	// The voids that were reviewed. Three of them, acknowledged from the web,
	// and then a fourth arrived: that one closed this and opened the next.
	voidKey := incident.Key("lsprotect", "Register 1", "sale-voided")
	reviewed := incident.Open(
		"demo-0007", voidKey, incident.SeverityMedium, "lsprotect",
		"[DEMO] Sale voided at Register 1",
		voidDetail(10418, 18.00, "Dana M", now.Add(-2*time.Hour)),
		now.Add(-2*time.Hour))
	_ = reviewed.RecordAlert(now.Add(-2*time.Hour), 0)
	occ := []incident.Occurrence{reviewed.FirstOccurrence()}
	for i, v := range []struct {
		ago     time.Duration
		invoice int
		amount  float64
	}{{113 * time.Minute, 10421, 9.50}, {104 * time.Minute, 10427, 61.20}} {
		at := now.Add(-v.ago)
		o, _ := reviewed.Occur(at, incident.SeverityMedium, "[DEMO] Sale voided at Register 1",
			voidDetail(v.invoice, v.amount, "Dana M", at))
		occ = append(occ, o)
		if i == 0 {
			_ = reviewed.RecordAlert(at, 1)
		}
	}
	_ = reviewed.Acknowledge(now.Add(-95*time.Minute), "web")
	reviewed.Close(now.Add(-41*time.Minute), "reviewed: a new occurrence arrived after it was acknowledged")
	out = append(out, seeded{inc: reviewed, occ: occ})

	// The void that closed it opened this, and six more have followed. The
	// register has been voiding a sale every few minutes for most of an hour
	// and nobody has looked yet.
	fresh := reviewed.Recur("demo-0008", now.Add(-41*time.Minute))
	fresh.Title = "[DEMO] Sale voided at Register 1"
	fresh.Detail = voidDetail(10433, 42.50, "Dana M", now.Add(-41*time.Minute))
	_ = fresh.RecordAlert(now.Add(-41*time.Minute), 0)
	_ = fresh.RecordAlert(now.Add(-26*time.Minute), 1)
	occ = []incident.Occurrence{fresh.FirstOccurrence()}
	for _, v := range []struct {
		ago     time.Duration
		invoice int
		amount  float64
		who     string
	}{
		{34 * time.Minute, 10436, 7.25, "Dana M"},
		{29 * time.Minute, 10438, 128.00, "Dana M"},
		{22 * time.Minute, 10440, 12.75, "Sam K"},
		{15 * time.Minute, 10441, 340.00, "Sam K"},
		{8 * time.Minute, 10443, 5.00, "Sam K"},
		{2 * time.Minute, 10444, 42.50, "Sam K"},
	} {
		at := now.Add(-v.ago)
		o, _ := fresh.Occur(at, incident.SeverityMedium, "[DEMO] Sale voided at Register 1",
			voidDetail(v.invoice, v.amount, v.who, at))
		occ = append(occ, o)
	}
	out = append(out, seeded{inc: fresh, occ: occ})

	// More arrivals than the incident keeps the detail of. The count is exact;
	// the oldest details have been dropped, and the board has to say so.
	// Acknowledged, so it also shows a reviewed per-occurrence incident that
	// is still open: the next arrival will close it and open another.
	rewards := incident.Open(
		"demo-0009",
		incident.Key("lightspeed-rewards", "Register 2", "unearned-reward"),
		incident.SeverityLow, "lightspeed-rewards",
		"[DEMO] Reward applied with nothing earned — Register 2",
		"", now.Add(-9*time.Hour))
	const rewardsTotal = 112
	occ = nil
	for i := 0; i < rewardsTotal; i++ {
		// Roughly every five minutes across the day, drifting so the times
		// do not read as a clock.
		at := now.Add(-9*time.Hour + time.Duration(i)*283*time.Second)
		amount := []float64{4.50, 6.00, 3.25, 9.75, 4.50, 12.00}[i%6]
		detail := rewardDetail(70210+i*3, amount, at)
		if i == 0 {
			rewards.Detail = detail
			occ = append(occ, rewards.FirstOccurrence())
			continue
		}
		o, _ := rewards.Occur(at, incident.SeverityLow, rewards.Title, detail)
		occ = append(occ, o)
	}
	_ = rewards.RecordAlert(now.Add(-9*time.Hour), 0)
	_ = rewards.Acknowledge(now.Add(-6*time.Minute), "pushover")
	out = append(out, seeded{inc: rewards, occ: occ})

	return out
}

// voidDetail is a void as the LSProtect peer describes one: its own prose,
// then the actor, the context and the entity as "key: value" lines, in the
// shape the link envelope renders them.
func voidDetail(invoice int, amount float64, cashier string, at time.Time) string {
	return fmt.Sprintf("Sale %d was voided after it was tendered.\n"+
		"Cashier: %s\namount: %.2f\ninvoice: %d\nRegister: Register 1\nAt: %s",
		invoice, cashier, amount, invoice, at.UTC().Format(time.RFC3339))
}

func rewardDetail(ticket int, amount float64, at time.Time) string {
	return fmt.Sprintf("A reward discount was applied under an account with no reward earned.\n"+
		"amount: %.2f\nticket: %d\nRegister: Register 2\nAt: %s",
		amount, ticket, at.UTC().Format(time.RFC3339))
}

func ordinary(now time.Time) []*incident.Incident {
	var out []*incident.Incident

	// Still shouting. Nobody has acknowledged it, and it has alerted four
	// times -- which is the behaviour the product exists for.
	forced := incident.Open(
		"demo-0001",
		incident.Key("access", "Warehouse side door", "door-forced-open"),
		incident.SeverityCritical, "access",
		"[DEMO] Door forced open — Warehouse side door",
		"The door opened while it was locked, and no unlock was recorded in the "+
			"preceding 10 seconds. UniFi Access does not report this; it is derived "+
			"from the lock state and the door position at the moment of the change.",
		now.Add(-7*time.Minute))
	for i := 0; i < 4; i++ {
		_ = forced.RecordAlert(now.Add(time.Duration(-7+i*2)*time.Minute), min(i, 1))
	}
	out = append(out, forced)

	// Acknowledged, NOT resolved. A notification would be gone; this is still
	// an open obligation and the board says so.
	camera := incident.Open(
		"demo-0002",
		incident.Key("protect", "Car park (east)", "offline"),
		incident.SeverityHigh, "protect",
		"[DEMO] Camera offline — Car park (east)",
		"Last seen 31 minutes ago. A camera that went dark before something "+
			"happened is the recording nobody has.",
		now.Add(-31*time.Minute))
	_ = camera.RecordAlert(now.Add(-31*time.Minute), 0)
	_ = camera.RecordAlert(now.Add(-16*time.Minute), 1)
	_ = camera.Acknowledge(now.Add(-12*time.Minute), "ntfy")
	out = append(out, camera)

	// Delivery is failing. The most useful line on the whole screen when it
	// applies, and the one a status page usually hides.
	wan := incident.Open(
		"demo-0003",
		incident.Key("network", "WAN1", "wan-down"),
		incident.SeverityCritical, "network",
		"[DEMO] WAN down — WAN1",
		"Reported by a UniFi Network Alarm Manager rule. The Integration API "+
			"publishes no events at all, so this arrived over an inbound webhook.",
		now.Add(-3*time.Minute))
	_ = wan.RecordAlert(now.Add(-3*time.Minute), 0)
	wan.RecordDeliveryFailure(now.Add(-2*time.Minute),
		"smtp: dial tcp: lookup smtp.example.com: no such host")
	out = append(out, wan)

	// Held open: the second alarm UniFi Access does not report either.
	held := incident.Open(
		"demo-0004",
		incident.Key("access", "Loading bay", "door-held-open"),
		incident.SeverityMedium, "access",
		"[DEMO] Door held open — Loading bay",
		"Open for longer than the configured threshold. Derived, not reported.",
		now.Add(-19*time.Minute))
	_ = held.RecordAlert(now.Add(-19*time.Minute), 0)
	_ = held.Acknowledge(now.Add(-17*time.Minute), "web")
	_ = held.Resolve(now.Add(-15 * time.Minute))
	held.Close(now.Add(-15*time.Minute), "the door was closed")
	out = append(out, held)

	// A recurrence, so the board can show that this has happened before.
	prev := incident.Open(
		"demo-0005",
		incident.Key("protect", "Front gate", "motion-after-hours"),
		incident.SeverityLow, "protect",
		"[DEMO] Motion after hours — Front gate",
		"Outside the configured quiet hours this would have been delivered "+
			"immediately; inside them, low and informational alarms wait.",
		now.Add(-4*time.Hour))
	_ = prev.RecordAlert(now.Add(-4*time.Hour), 0)
	_ = prev.Acknowledge(now.Add(-3*time.Hour-50*time.Minute), "ntfy")
	_ = prev.Resolve(now.Add(-3*time.Hour - 45*time.Minute))
	prev.Close(now.Add(-3*time.Hour-45*time.Minute), "cleared")
	out = append(out, prev)

	smoke := incident.Open(
		"demo-0006",
		incident.Key("protect", "Plant room", "smoke"),
		incident.SeverityCritical, "protect",
		"[DEMO] Smoke alarm — Plant room",
		"A UniFi Protect smart detection. The alarm type is what separates "+
			"smoke from CO from glass breaking, and it is the field most likely "+
			"to be thrown away by a generic parser.",
		now.Add(-2*time.Hour))
	_ = smoke.RecordAlert(now.Add(-2*time.Hour), 0)
	_ = smoke.Acknowledge(now.Add(-2*time.Hour+90*time.Second), "pushover")
	_ = smoke.Resolve(now.Add(-100 * time.Minute))
	smoke.Close(now.Add(-100*time.Minute), "acknowledged and cleared")
	out = append(out, smoke)

	return out
}

// Health is the diagnostic surface a working site would report.
func Health(now time.Time) web.Health {
	return web.Health{
		StartedAt: now.Add(-6*time.Hour - 12*time.Minute),
		Sources: []web.SourceHealth{
			{Name: "protect", LastSeen: now.Add(-14 * time.Second), ExpectedWithin: 5 * time.Minute},
			{Name: "access", LastSeen: now.Add(-42 * time.Second), ExpectedWithin: 5 * time.Minute},
			{
				Name: "network", LastSeen: now.Add(-9 * time.Minute),
				ExpectedWithin: 30 * time.Minute,
				Detail:         "polled; the Integration API publishes no events",
			},
		},
		Channels: []web.ChannelHealth{
			{Name: "ntfy", Enabled: true, Depth: 256},
			{Name: "pushover", Enabled: true, Depth: 256},
			{
				Name: "email", Enabled: true, Depth: 256,
				LastError: "dial tcp: lookup smtp.example.com: no such host",
			},
		},
		Service: web.ServiceHealth{
			State:              "running",
			PID:                os.Getpid(),
			StartType:          "automatic",
			RestartsAfterCrash: true,
		},
	}
}
