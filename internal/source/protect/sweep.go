package protect

import (
	"context"
	"fmt"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// runSweeper owns the reconciliation sweep for the life of the source.
//
// It is a goroutine of its own, fed by a request channel, rather than a call
// made at the end of the connect path, because the sweep has to be a
// first-class part of reconnect: it runs when either socket reconnects, it
// runs on a timer regardless of what the sockets are doing, and it retries on
// its own backoff when the console is not answering yet. A sweep that only
// happens if the connect path remembers to call it is a sweep that stops
// happening the first time somebody restructures the connect path.
func (s *Source) runSweeper(ctx context.Context, out event.Sink) {
	ticker := time.NewTicker(s.cfg.SweepEvery)
	defer ticker.Stop()

	var (
		retry   <-chan time.Time
		attempt int
	)

	run := func() {
		// Bounded, because this loop is single-threaded: a read that never
		// returns takes the periodic backstop down with it, and the failure
		// looks exactly like a quiet site. The exported Reconcile still honours
		// whatever deadline ITS caller chose.
		sctx, cancel := context.WithTimeout(ctx, s.cfg.SweepTimeout)
		err := s.Reconcile(sctx, out)
		cancel()

		if err != nil && ctx.Err() == nil {
			attempt++
			d := s.backoff.Delay(attempt)
			s.cfg.Logf("protect: reconciliation sweep failed: %v; retrying in %s", err, d.Round(time.Millisecond))
			retry = time.After(d)
			return
		}
		attempt = 0
		retry = nil
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-s.sweepReq:
			// Coalesce: both sockets reconnect together after a console reboot
			// and want one sweep between them, not one each against a console
			// that is still re-initialising.
			if !s.debounce(ctx) {
				return
			}
			run()

		case <-retry:
			run()

		case <-ticker.C:
			// The periodic sweep is a permanent backstop rather than a
			// fallback. Every push path here can fail without saying so, and a
			// socket that is up and silent is indistinguishable from a quiet
			// site until something re-reads the truth.
			run()
		}
	}
}

func (s *Source) debounce(ctx context.Context) bool {
	if s.cfg.SweepDebounce <= 0 {
		return true
	}
	timer := time.NewTimer(s.cfg.SweepDebounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-s.sweepReq:
		case <-timer.C:
			return true
		}
	}
}

// Reconcile re-reads device state over REST and emits what the stream could
// not have told us.
//
// This exists because neither socket accepts a resume cursor. Everything that
// happened while a socket was down is gone, with no gap marker and no sequence
// number to notice the loss by -- so after a reconnect the only honest source
// of truth about what is CURRENTLY wrong is a fresh read, and open state is
// re-derived from that rather than assumed to have been observed.
//
// Only transitions are emitted. Re-announcing every connected camera on every
// sweep would bury the one that is not.
func (s *Source) Reconcile(ctx context.Context, out event.Sink) error {
	started := s.cfg.Now()

	devices, err := s.cfg.States.Devices(ctx)
	now := s.cfg.Now()

	// Applied even on a partial error: the records that did arrive are real,
	// and a device that is missing from the response is simply never spoken
	// about. Absence is not evidence here and is never read as one.
	transitions := s.reg.applySweep(devices, started, now)

	for _, t := range transitions {
		ent := event.Entity{ID: t.Device.ID, Name: t.Device.Name, Kind: t.Device.Kind, MAC: t.Device.MAC}
		s.emitSweepTransition(out, ent, t, now)
	}

	s.mu.Lock()
	// CONTACT IS WHAT CAME BACK, NOT WHAT WAS ATTEMPTED. This used to stamp
	// unconditionally, so a console with no Protect installed -- which answers
	// these paths with the UniFi OS web page, failing every read -- reported
	// "in contact; nothing to report yet" on the health board for as long as
	// the daemon ran. A source that has never reached anything must not look
	// like a quiet one.
	//
	// A PARTIAL read still counts: devices that arrived are devices the
	// console sent, and the sweep applies them above for the same reason.
	if err == nil || len(devices) > 0 {
		s.health.LastSweepAt = now
	}
	s.health.SweepTransitions += int64(len(transitions))
	if err != nil {
		s.health.LastSweepErr = err.Error()
	} else {
		s.health.LastSweepErr = ""
	}
	s.mu.Unlock()

	return err
}

func (s *Source) emitSweepTransition(out event.Sink, ent event.Entity, t transition, now time.Time) {
	prev := t.Previous
	if prev == "" {
		prev = "unknown"
	}
	detail := fmt.Sprintf(
		"Reconciliation sweep found state %s (previously %s). The transition time is unknown: it happened while the stream was not being read, and neither socket carries a resume cursor.",
		t.Device.State, prev)

	s.emit(out, event.Event{
		ID:        fmt.Sprintf("sweep:%s:%s:%d", ent.ID, normaliseState(t.Device.State), now.UnixMilli()),
		Source:    SourceName,
		Kind:      "reconcile",
		Entity:    ent,
		Condition: t.Condition,
		Clears:    t.Clears,
		At:        now,
		// Emphatically arrival time. The sweep knows what is true now and
		// nothing whatsoever about when it became true, and an alert that
		// presents this as an observation time sends somebody scrubbing to a
		// moment where nothing happened.
		AtIsArrivalTime: true,
		ReceivedAt:      now,
		Severity:        incident.SeverityHigh,
		Title:           buildTitle(t.Condition, t.Clears, ent),
		Detail:          detail,
		Raw: map[string]any{
			"source":   "reconcile",
			"state":    t.Device.State,
			"previous": t.Previous,
		},
	})
}
