package escalate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// DefaultTickInterval is how often the scheduler re-evaluates active
// incidents.
//
// It only needs to be well under the smallest escalation granularity an
// operator can express (stages are configured in seconds but meant in
// minutes), because the tick does not decide anything -- Policy.NextDue does,
// from persisted timestamps. The tick only decides how late a due alert is,
// bounded by this interval. The cost of a tick is one scan of the ACTIVE
// incidents, which is small by construction: an installation with thousands of
// simultaneously unacknowledged alarms has a problem this product cannot fix.
const DefaultTickInterval = 5 * time.Second

// DeliverFunc sends one alert for one incident through the named channels and
// reports whether anything got through.
//
// Injected rather than reached for directly so the scheduler is testable with
// no channels, no network and no clock. The contract that matters: return nil
// only if at least one channel ACCEPTED the alert. Returning nil on a failure
// silently advances the escalation ladder and the incident stops nagging about
// a condition nobody was told about.
type DeliverFunc func(ctx context.Context, inc *incident.Incident, stage int, channels []string) error

// Scheduler drives re-alerts off the store.
//
// It owns no timers of record and no in-memory schedule. Everything it decides
// is a pure function of the incident's persisted timestamps and the policy, so
// a restart reconstructs the schedule exactly rather than losing it -- which
// for a product whose job is nagging until acknowledged is the difference
// between working and not.
type Scheduler struct {
	store    incident.Store
	policies map[incident.Severity]Policy
	deliver  DeliverFunc

	now      func() time.Time
	interval time.Duration
	onError  func(error)
	quiet    QuietHours

	mu    sync.Mutex
	stats Stats
}

// Stats is what the scheduler can tell an operator about itself. §9 of the
// architecture: a security product that silently stops working is worse than
// no product, so the counters exist to be shown rather than only logged.
type Stats struct {
	Ticks     int
	Delivered int
	Failed    int
	GaveUp    int

	// Held counts alerts withheld by quiet hours. Counted separately from
	// Failed because they are not failures and must not read as breakage --
	// but counted at all, and surfaced, because "it was quiet hours" is the
	// answer to "why did I not get paged" and an operator must be able to
	// find it without reading the config.
	Held int

	Errors     int
	LastTickAt time.Time
}

// Option configures a Scheduler.
type Option func(*Scheduler)

// WithClock injects the clock. Tests use it to move time without sleeping;
// production never sets it.
func WithClock(now func() time.Time) Option {
	return func(s *Scheduler) {
		if now != nil {
			s.now = now
		}
	}
}

// WithInterval sets the tick interval.
func WithInterval(d time.Duration) Option {
	return func(s *Scheduler) {
		if d > 0 {
			s.interval = d
		}
	}
}

// WithErrorHandler receives per-incident faults that did not stop the pass.
// Without one they are counted and dropped, which is the wrong default for
// anything long-lived -- wire it to the log and to the diagnostics page.
func WithErrorHandler(f func(error)) Option {
	return func(s *Scheduler) { s.onError = f }
}

// NewScheduler builds a scheduler. It does not start anything; call Run.
func NewScheduler(store incident.Store, policies map[incident.Severity]Policy, deliver DeliverFunc, opts ...Option) (*Scheduler, error) {
	if store == nil {
		return nil, errors.New("escalate: scheduler needs a store")
	}
	if deliver == nil {
		return nil, errors.New("escalate: scheduler needs a delivery function")
	}
	if len(policies) == 0 {
		return nil, errors.New("escalate: scheduler needs at least one policy")
	}
	// Validate up front. A policy that cannot express itself -- unordered
	// stages, a critical policy that gives up -- must fail at start, where
	// somebody is watching, not at 3am when it decides not to page.
	for sev, p := range policies {
		if err := p.Validate(sev); err != nil {
			return nil, fmt.Errorf("escalate: policy for %s: %w", sev, err)
		}
	}
	s := &Scheduler{
		store:    store,
		policies: policies,
		deliver:  deliver,
		now:      time.Now,
		interval: DefaultTickInterval,
	}
	for _, o := range opts {
		o(s)
	}
	// Validated after the options, since that is where the window arrives. A
	// malformed quiet-hours window must refuse at startup: the failure mode of
	// accepting it is alerts going silent at times nobody chose, which is
	// invisible until an alert someone needed did not arrive.
	if err := s.quiet.Validate(); err != nil {
		return nil, fmt.Errorf("escalate: %w", err)
	}
	return s, nil
}

// Run drives the scheduler until ctx is cancelled.
//
// The first pass happens immediately, before any timer, and that pass IS the
// reconciliation from the store: every active incident is re-evaluated from
// its persisted LastAlertAt.
//
// There is deliberately no separate "catch up on what we missed while we were
// down" code path. A bespoke catch-up routine is exactly where a restart-burst
// bug gets written -- replaying every interval that elapsed during a reboot
// and firing six alerts for one still-open door. Policy.NextDue answers "when
// is the next alert due" rather than "how many were missed", so an incident
// whose alert fell due during downtime returns a due time in the past and
// fires ONCE on this pass. A burst during a power event, when restarts are
// most likely, is precisely how an operator learns to mute the product.
//
// Returns nil on cancellation: shutdown is not a failure.
func (s *Scheduler) Run(ctx context.Context) error {
	// Tick has already reported every fault it collected; the joined error it
	// returns is for callers that step it by hand.
	_ = s.Tick(ctx)

	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = s.Tick(ctx)
		}
	}
}

// Tick runs one pass over the active incidents.
//
// Exported so tests can step the scheduler without waiting on a timer, and so
// an operator's "check now" button can reuse exactly the code path that runs
// in production rather than a lookalike.
func (s *Scheduler) Tick(ctx context.Context) error {
	// One timestamp for the whole pass. Reading the clock per incident would
	// let two incidents in the same pass disagree about what "now" is, which
	// makes a failure at the interval boundary depend on scan order.
	now := s.now()

	active, err := s.store.Active(ctx)
	if err != nil {
		err = fmt.Errorf("escalate: list active incidents: %w", err)
		s.report(err)
		return err
	}

	var errs []error
	for _, inc := range active {
		if ctx.Err() != nil {
			break
		}
		if err := s.process(ctx, inc, now); err != nil {
			// One bad incident must not take out the pass. An unparseable
			// severity or a store hiccup on one row would otherwise stop every
			// other incident in the list from being evaluated, and the ones
			// after it in scan order go silent.
			s.report(err)
			errs = append(errs, err)
		}
	}

	s.count(func(st *Stats) {
		st.Ticks++
		st.LastTickAt = now
	})
	return errors.Join(errs...)
}

// process evaluates and, where due, alerts on one incident.
func (s *Scheduler) process(ctx context.Context, inc *incident.Incident, now time.Time) error {
	pol, ok := s.policies[inc.Severity]
	if !ok {
		// An incident with no policy can never alert. Surfaced as a fault on
		// every pass rather than skipped, because a silently unschedulable
		// incident is the exact failure mode §9 exists to prevent.
		//
		// Deliberately NOT defaulted to the critical policy: promoting an
		// unknown severity would turn one configuration typo into a 3am phone
		// call for every info-level event, and an operator who is woken by
		// noise mutes the product.
		return fmt.Errorf("escalate: incident %s has severity %q with no policy", inc.ID, inc.Severity)
	}

	// Give-up is checked BEFORE delivery so an incident past its horizon does
	// not get one last alert on the way out the door. Policy.ShouldGiveUp is
	// always false when GiveUpAfter is zero, which is the critical default:
	// critical never gives up.
	if pol.ShouldGiveUp(inc, now) {
		reason := fmt.Sprintf("gave up after %s without acknowledgement (policy %s)", pol.GiveUpAfter, pol.Name)
		changed, err := s.commit(ctx, inc.ID, func(fresh *incident.Incident) (bool, error) {
			// Re-checked against the fresh copy: an ack that landed since the
			// scan means the policy no longer gives up at all.
			if !pol.ShouldGiveUp(fresh, now) {
				return false, nil
			}
			fresh.Close(now, reason)
			return true, nil
		})
		if err != nil {
			return err
		}
		if changed {
			s.count(func(st *Stats) { st.GaveUp++ })
		}
		return nil
	}

	due, stage, channels := pol.DueNow(inc, now)
	if !due {
		return nil
	}

	// Quiet hours: hold, do not drop.
	//
	// The incident stays exactly as it is -- LastAlertAt untouched, no failure
	// recorded -- so NextDue still returns a time in the past and it is due on
	// the first tick after the window ends. A held alert is deferred, never
	// cancelled.
	//
	// Critical cannot reach this branch: Policy.Validate refuses a critical
	// policy with RespectQuietHours set, and NewScheduler validates every
	// policy at construction. The guard is still written as a policy check
	// rather than a severity check, so the rule lives in one place.
	if pol.RespectQuietHours && s.quiet.Contains(now) {
		s.count(func(st *Stats) { st.Held++ })
		return nil
	}

	derr := s.deliver(ctx, inc, stage, channels)

	if derr != nil {
		// A failed delivery is NOT an alert. RecordDeliveryFailure leaves
		// LastAlertAt alone on purpose, so NextDue still returns a time in the
		// past and the incident is due again on the very next tick -- sooner,
		// not later. If every channel failed, nobody has been told.
		msg := derr.Error()
		if _, err := s.commit(ctx, inc.ID, func(fresh *incident.Incident) (bool, error) {
			fresh.RecordDeliveryFailure(now, msg)
			return true, nil
		}); err != nil {
			return err
		}
		s.count(func(st *Stats) { st.Failed++ })
		return fmt.Errorf("escalate: deliver incident %s stage %d: %w", inc.ID, stage, derr)
	}

	// Delivery succeeded, so the alert happened whatever the store now says.
	// If this write fails the incident stays due and will be alerted again:
	// a duplicate alert is the right direction to fail in, silence is not.
	if _, err := s.commit(ctx, inc.ID, func(fresh *incident.Incident) (bool, error) {
		if fresh.Terminal() {
			// Acknowledged and resolved (or closed) while we were delivering.
			// Nothing left to record on it, and RecordAlert would refuse.
			return false, nil
		}
		if err := fresh.RecordAlert(now, stage); err != nil {
			return false, err
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("escalate: record alert for %s: %w", inc.ID, err)
	}
	s.count(func(st *Stats) { st.Delivered++ })
	return nil
}

// commitAttempts bounds the compare-and-swap retry.
//
// A conflict means somebody else wrote between our read and our write, and the
// overwhelmingly likely somebody is a human acknowledging the alert we just
// sent. Re-reading picks up their change, and the re-run of mutate then
// usually decides there is nothing to do — so this converges in one extra
// pass. The bound exists so a pathological writer cannot spin the tick.
const commitAttempts = 3

// commit applies mutate to a FRESH copy of the incident under a
// compare-and-swap, retrying if the row moved under us.
//
// Not a nicety. Delivery takes real time — an SMTP handshake, a voice call
// being placed — and an acknowledgement arrives precisely during that window,
// because the alert that prompted it has just gone out. Writing back the copy
// we scanned before delivery would erase the ack and keep paging a human who
// already responded.
//
// Re-reading alone narrows that window but does not close it: an ack landing
// between the re-read and the write is still lost. incident.Store.Put is
// last-write-wins, so the fix is PutIfUnchanged — the comparison happens inside
// the UPDATE's WHERE clause, while SQLite holds the write lock, leaving no gap
// for anything to land in.
//
// mutate MUST be idempotent and must re-derive its decision from the copy it is
// handed, because on a conflict it runs again against newer state. That is the
// point: on the second pass it sees the ack and declines to record the alert.
func (s *Scheduler) commit(ctx context.Context, id string, mutate func(*incident.Incident) (bool, error)) (bool, error) {
	for attempt := 0; attempt < commitAttempts; attempt++ {
		fresh, err := s.store.Get(ctx, id)
		if err != nil {
			if errors.Is(err, incident.ErrNotFound) {
				// Removed under us. Nothing to record, and nothing wrong.
				return false, nil
			}
			return false, fmt.Errorf("escalate: reload incident %s: %w", id, err)
		}
		// Captured BEFORE mutate, which advances UpdatedAt on the copy.
		expect := fresh.UpdatedAt

		changed, err := mutate(fresh)
		if err != nil || !changed {
			return false, err
		}

		err = s.store.PutIfUnchanged(ctx, fresh, expect)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, incident.ErrConflict):
			continue // somebody wrote; re-read and let mutate decide again
		case errors.Is(err, incident.ErrNotFound):
			// Deleted between our read and our write. Not an error, and
			// explicitly not something to recreate: resurrecting a deleted
			// incident would also resurrect its acknowledgement.
			return false, nil
		default:
			return false, fmt.Errorf("escalate: persist incident %s: %w", id, err)
		}
	}
	// Persistent contention. Reported rather than swallowed, but not fatal:
	// the incident is still in the store and the next tick will try again.
	return false, fmt.Errorf("escalate: incident %s changed under every one of %d write attempts: %w",
		id, commitAttempts, incident.ErrConflict)
}

// WithQuietHours holds non-critical alerts during a window.
//
// It cannot mute critical: Policy.Validate refuses RespectQuietHours on a
// critical policy, so there is no configuration in which this silences an
// alarm.
func WithQuietHours(q QuietHours) Option {
	return func(s *Scheduler) { s.quiet = q }
}

// Stats returns a snapshot of the counters.
func (s *Scheduler) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *Scheduler) count(f func(*Stats)) {
	s.mu.Lock()
	f(&s.stats)
	s.mu.Unlock()
}

func (s *Scheduler) report(err error) {
	if err == nil {
		return
	}
	s.count(func(st *Stats) { st.Errors++ })
	if s.onError != nil {
		s.onError(err)
	}
}
