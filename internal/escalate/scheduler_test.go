package escalate

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// fakeStore is an in-memory incident.Store for the scheduler's tests.
//
// A real store is not used here on purpose: these tests are about timing and
// about what the scheduler does with a delivery result, and the failures they
// have to be able to stage -- an ack landing in the middle of a delivery, a
// write that fails after the alert has already gone out -- are awkward or
// impossible to provoke through a durable store's API.
type fakeStore struct {
	mu   sync.Mutex
	byID map[string]incident.Incident

	putErr    error
	activeErr error

	// beforeGet runs inside Get, which is where the scheduler re-reads an
	// incident after delivering. It is how a test stages an acknowledgement
	// that arrives while the SMTP handshake is still going.
	beforeGet func(id string)

	// beforePut runs inside the write, AFTER the scheduler has re-read and
	// mutated its copy. This is the narrower race, and the only one a
	// compare-and-swap is needed for: an ack landing here is invisible to the
	// re-read, so a last-write-wins Put erases it.
	beforePut func(id string)
}

func newFakeStore(incs ...*incident.Incident) *fakeStore {
	f := &fakeStore{byID: map[string]incident.Incident{}}
	for _, inc := range incs {
		f.byID[inc.ID] = *clone(inc)
	}
	return f
}

// clone deep-copies, pointers included. Sharing a *time.Time with a caller
// would let a test mutate "stored" state without going through Put, which is
// the one thing a store must never allow.
func clone(in *incident.Incident) *incident.Incident {
	out := *in
	cp := func(p *time.Time) *time.Time {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	out.FirstAlertAt = cp(in.FirstAlertAt)
	out.LastAlertAt = cp(in.LastAlertAt)
	out.AckedAt = cp(in.AckedAt)
	out.ResolvedAt = cp(in.ResolvedAt)
	out.ClosedAt = cp(in.ClosedAt)
	return &out
}

func (f *fakeStore) Put(_ context.Context, inc *incident.Incident) error {
	if f.beforePut != nil {
		f.beforePut(inc.ID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.byID[inc.ID] = *clone(inc)
	return nil
}

func (f *fakeStore) PutIfUnchanged(_ context.Context, inc *incident.Incident, expect time.Time) error {
	if f.beforePut != nil {
		f.beforePut(inc.ID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	cur, ok := f.byID[inc.ID]
	if !ok {
		return incident.ErrNotFound
	}
	if !cur.UpdatedAt.Equal(expect) {
		return incident.ErrConflict
	}
	f.byID[inc.ID] = *clone(inc)
	return nil
}

func (f *fakeStore) Get(_ context.Context, id string) (*incident.Incident, error) {
	if f.beforeGet != nil {
		f.beforeGet(id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	inc, ok := f.byID[id]
	if !ok {
		return nil, incident.ErrNotFound
	}
	return clone(&inc), nil
}

func (f *fakeStore) OpenByDedupKey(_ context.Context, key string) (*incident.Incident, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, inc := range f.byID {
		if inc.DedupKey == key && !inc.Terminal() {
			return clone(&inc), nil
		}
	}
	return nil, incident.ErrNotFound
}

func (f *fakeStore) Active(_ context.Context) ([]*incident.Incident, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.activeErr != nil {
		return nil, f.activeErr
	}
	var out []*incident.Incident
	for _, inc := range f.byID {
		if !inc.Terminal() {
			out = append(out, clone(&inc))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) Recent(_ context.Context, _ int) ([]*incident.Incident, error) {
	return nil, errors.New("not used")
}

func (f *fakeStore) Close() error { return nil }

func (f *fakeStore) must(t *testing.T, id string) *incident.Incident {
	t.Helper()
	inc, err := f.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("store.Get(%s): %v", id, err)
	}
	return inc
}

// delivery records what the scheduler asked for and what it was told.
type delivery struct {
	incidentID string
	stage      int
	channels   []string
}

type recorder struct {
	mu   sync.Mutex
	got  []delivery
	err  error // returned to the scheduler when non-nil
	hook func(inc *incident.Incident)
}

func (r *recorder) deliver(_ context.Context, inc *incident.Incident, stage int, channels []string) error {
	if r.hook != nil {
		r.hook(inc)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, delivery{incidentID: inc.ID, stage: stage, channels: channels})
	return r.err
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *recorder) all() []delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]delivery, len(r.got))
	copy(out, r.got)
	return out
}

// clock is the injected time source. Tests move it by hand; nothing sleeps.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// sched0 is this file's reference instant. Deliberately not named t0:
// policy_test.go already declares that in this same package.
var sched0 = time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)

// repeatingPolicy: one stage at open, then nag forever every five minutes.
func repeatingPolicy() map[incident.Severity]Policy {
	return map[incident.Severity]Policy{
		incident.SeverityHigh: {
			Name:        "test-high",
			Stages:      []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RepeatEvery: 5 * time.Minute,
		},
	}
}

func newTestScheduler(t *testing.T, st incident.Store, pols map[incident.Severity]Policy, r *recorder, c *clock) *Scheduler {
	t.Helper()
	s, err := NewScheduler(st, pols, r.deliver, WithClock(c.now), WithInterval(time.Hour))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return s
}

// TestRestartAfterDowntimeFiresOnceNotOncePerMissedInterval is the restart
// burst. The daemon was down for an hour with a five-minute repeat, so twelve
// re-alerts "should" have happened. Exactly one may fire -- a burst during a
// power event, when restarts are most likely, is how an operator learns to
// mute the product.
func TestRestartAfterDowntimeFiresOnceNotOncePerMissedInterval(t *testing.T) {
	ctx := context.Background()
	lastAlert := sched0.Add(-time.Hour)
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0.Add(-2*time.Hour))
	if err := inc.RecordAlert(lastAlert, 0); err != nil {
		t.Fatalf("RecordAlert: %v", err)
	}

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	// The reconciling pass.
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Fatalf("after reconcile: %d deliveries, want exactly 1", got)
	}

	// Ticking again at the same instant -- and the scheduler ticks often --
	// must not replay the backlog.
	for i := 0; i < 5; i++ {
		if err := s.Tick(ctx); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}
	if got := r.count(); got != 1 {
		t.Fatalf("repeated ticks replayed the missed intervals: %d deliveries, want 1", got)
	}

	// And the next one is a full interval away from the alert that just went
	// out, not from the twelve that did not.
	c.advance(5*time.Minute - time.Nanosecond)
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 1 {
		t.Fatalf("alerted early: %d deliveries, want 1", got)
	}
	c.advance(time.Nanosecond)
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 2 {
		t.Fatalf("did not re-alert at the interval: %d deliveries, want 2", got)
	}

	stored := st.must(t, "inc-1")
	if stored.AlertCount != 3 { // one before the restart, two since
		t.Errorf("AlertCount = %d, want 3", stored.AlertCount)
	}
}

// TestFailedDeliveryDoesNotAdvanceLastAlertAt. If every channel failed, the
// incident has not been alerted: the next attempt must come sooner, not later.
func TestFailedDeliveryDoesNotAdvanceLastAlertAt(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0)

	st := newFakeStore(inc)
	r := &recorder{err: errors.New("smtp: 451 greylisted")}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	if err := s.Tick(ctx); err == nil {
		t.Fatal("Tick: a total delivery failure must be reported, got nil")
	}

	stored := st.must(t, "inc-1")
	if stored.LastAlertAt != nil {
		t.Errorf("LastAlertAt = %v after a failed delivery, want nil -- a failure is not an alert", *stored.LastAlertAt)
	}
	if stored.FirstAlertAt != nil {
		t.Errorf("FirstAlertAt = %v after a failed delivery, want nil", *stored.FirstAlertAt)
	}
	if stored.AlertCount != 0 {
		t.Errorf("AlertCount = %d after a failed delivery, want 0", stored.AlertCount)
	}
	if stored.LastDeliveryError == "" {
		t.Error("LastDeliveryError is empty: the operator cannot see why nothing is arriving")
	}
	if stored.State() != incident.StateOpen {
		t.Errorf("state = %s, want %s: a failed delivery must not make it look alerted", stored.State(), incident.StateOpen)
	}

	// Still due on the very next tick, with no clock movement at all.
	if err := s.Tick(ctx); err == nil {
		t.Fatal("Tick: want the failure reported again")
	}
	if got := r.count(); got != 2 {
		t.Errorf("%d delivery attempts, want 2 -- a failed incident must stay due", got)
	}

	// And once a channel finally accepts it, the ladder advances.
	r.mu.Lock()
	r.err = nil
	r.mu.Unlock()
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick after recovery: %v", err)
	}
	stored = st.must(t, "inc-1")
	if stored.LastAlertAt == nil || !stored.LastAlertAt.Equal(sched0) {
		t.Fatalf("LastAlertAt = %v after a successful delivery, want %v", stored.LastAlertAt, sched0)
	}
	if stored.LastDeliveryError != "" {
		t.Errorf("LastDeliveryError = %q after success, want cleared", stored.LastDeliveryError)
	}
}

// TestSuccessfulDeliveryWalksTheStageLadder checks that the scheduler hands the
// delivery callback the stage's own channel list, in full, at each rung.
func TestSuccessfulDeliveryWalksTheStageLadder(t *testing.T) {
	ctx := context.Background()
	pols := map[incident.Severity]Policy{
		incident.SeverityCritical: {
			Name: "test-critical",
			Stages: []Stage{
				{After: 0, Channels: []string{"ntfy", "email"}},
				{After: 2 * time.Minute, Channels: []string{"ntfy", "email", "pushover"}},
				{After: 10 * time.Minute, Channels: []string{"ntfy", "email", "pushover", "voice"}},
			},
			RepeatEvery: 5 * time.Minute,
		},
	}
	inc := incident.Open("inc-1", "access/door-3/forced-open", incident.SeverityCritical, "access", "Door forced", "", sched0)

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, pols, r, c)

	steps := []struct {
		advance   time.Duration
		wantCount int
		wantStage int
	}{
		{0, 1, 0},
		{time.Minute, 1, 0},     // not due yet
		{time.Minute, 2, 1},     // sched0+2m
		{5 * time.Minute, 2, 1}, // sched0+7m: stage 2 is at +10m, repeat is from last alert
		{3 * time.Minute, 3, 2}, // sched0+10m
		{5 * time.Minute, 4, 2}, // sched0+15m: past the ladder, repeating
		{5 * time.Minute, 5, 2}, // sched0+20m
	}
	for i, step := range steps {
		c.advance(step.advance)
		if err := s.Tick(ctx); err != nil {
			t.Fatalf("step %d: Tick: %v", i, err)
		}
		if got := r.count(); got != step.wantCount {
			t.Fatalf("step %d (at %v): %d deliveries, want %d", i, c.now().Sub(sched0), got, step.wantCount)
		}
		last := r.all()[r.count()-1]
		if last.stage != step.wantStage {
			t.Fatalf("step %d: stage %d, want %d", i, last.stage, step.wantStage)
		}
		want := pols[incident.SeverityCritical].Stages[step.wantStage].Channels
		if len(last.channels) != len(want) {
			t.Fatalf("step %d: channels %v, want %v", i, last.channels, want)
		}
	}

	stored := st.must(t, "inc-1")
	if stored.Stage != 2 {
		t.Errorf("stored stage = %d, want 2", stored.Stage)
	}
	if stored.AlertCount != 5 {
		t.Errorf("stored AlertCount = %d, want 5", stored.AlertCount)
	}
}

func TestAcknowledgedAndResolvedIncidentsStopAlerting(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		apply func(*incident.Incident)
	}{
		{"acknowledged", func(i *incident.Incident) { _ = i.Acknowledge(sched0, "ntfy") }},
		{"resolved", func(i *incident.Incident) { _ = i.Resolve(sched0) }},
		{"closed", func(i *incident.Incident) { i.Close(sched0, "operator dismissed") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0.Add(-time.Hour))
			tc.apply(inc)

			st := newFakeStore(inc)
			r := &recorder{}
			c := &clock{t: sched0}
			s := newTestScheduler(t, st, repeatingPolicy(), r, c)

			for i := 0; i < 3; i++ {
				c.advance(10 * time.Minute)
				if err := s.Tick(ctx); err != nil {
					t.Fatalf("Tick: %v", err)
				}
			}
			if got := r.count(); got != 0 {
				t.Errorf("%d deliveries for a %s incident, want 0", got, tc.name)
			}
		})
	}
}

// TestGiveUpClosesTheIncidentWithoutOneLastAlert. An incident past its horizon
// must not get a farewell page on the way out.
func TestGiveUpClosesTheIncidentWithoutOneLastAlert(t *testing.T) {
	ctx := context.Background()
	pols := map[incident.Severity]Policy{
		incident.SeverityHigh: {
			Name:        "test-high",
			Stages:      []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RepeatEvery: 5 * time.Minute,
			GiveUpAfter: time.Hour,
		},
	}
	// Opened two hours ago, never delivered, so it is also due.
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0.Add(-2*time.Hour))

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, pols, r, c)

	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if got := r.count(); got != 0 {
		t.Errorf("%d deliveries while giving up, want 0", got)
	}

	stored := st.must(t, "inc-1")
	if stored.ClosedAt == nil {
		t.Fatal("incident was not closed")
	}
	if !stored.ClosedAt.Equal(sched0) {
		t.Errorf("ClosedAt = %v, want %v", *stored.ClosedAt, sched0)
	}
	if stored.CloseReason == "" {
		t.Error("closed with no reason: the history view cannot explain why it stopped")
	}
	if stored.State() != incident.StateClosed {
		t.Errorf("state = %s, want %s", stored.State(), incident.StateClosed)
	}
	if s.Stats().GaveUp != 1 {
		t.Errorf("Stats().GaveUp = %d, want 1", s.Stats().GaveUp)
	}

	active, _ := st.Active(ctx)
	if len(active) != 0 {
		t.Errorf("%d incidents still active after giving up, want 0", len(active))
	}
}

// TestSchedulerNeverGivesUpOnACriticalIncident. A product whose top severity eventually gives up
// has a silent failure mode precisely when nobody is around.
func TestSchedulerNeverGivesUpOnACriticalIncident(t *testing.T) {
	ctx := context.Background()
	pols := map[incident.Severity]Policy{
		incident.SeverityCritical: {
			Name:        "test-critical",
			Stages:      []Stage{{After: 0, Channels: []string{"ntfy"}}},
			RepeatEvery: 5 * time.Minute,
			GiveUpAfter: 0, // never; Policy.Validate refuses anything else here
		},
	}
	inc := incident.Open("inc-1", "access/door-3/forced-open", incident.SeverityCritical, "access", "Door forced", "", sched0.Add(-30*24*time.Hour))

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, pols, r, c)

	for i := 0; i < 4; i++ {
		if err := s.Tick(ctx); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
		c.advance(5 * time.Minute)
	}
	stored := st.must(t, "inc-1")
	if stored.ClosedAt != nil {
		t.Fatal("a critical incident was closed by the scheduler after a month unacknowledged")
	}
	if r.count() != 4 {
		t.Errorf("%d deliveries, want 4 -- it must keep nagging", r.count())
	}
}

// TestAckArrivingDuringDeliveryIsNotOverwritten. Delivery takes real time: an
// SMTP handshake, a voice call being placed. If the scheduler wrote back the
// copy it scanned before delivering, an ack that landed in that window would
// be erased and the product would keep paging a human who already responded.
func TestAckArrivingDuringDeliveryIsNotOverwritten(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0)

	st := newFakeStore(inc)
	ackAt := sched0.Add(2 * time.Second)
	r := &recorder{
		hook: func(_ *incident.Incident) {
			// The operator taps the ntfy action button while the alert for the
			// previous stage is still in flight.
			cur, err := st.Get(ctx, "inc-1")
			if err != nil {
				t.Errorf("mid-delivery Get: %v", err)
				return
			}
			if err := cur.Acknowledge(ackAt, "ntfy"); err != nil {
				t.Errorf("mid-delivery Acknowledge: %v", err)
				return
			}
			if err := st.Put(ctx, cur); err != nil {
				t.Errorf("mid-delivery Put: %v", err)
			}
		},
	}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	stored := st.must(t, "inc-1")
	if stored.AckedAt == nil {
		t.Fatal("the acknowledgement was overwritten by the scheduler's stale copy")
	}
	if !stored.AckedAt.Equal(ackAt) || stored.AckVia != "ntfy" {
		t.Errorf("ack = %v via %q, want %v via ntfy", stored.AckedAt, stored.AckVia, ackAt)
	}
	// The alert really did go out, so it is recorded -- but the incident is
	// acknowledged and must never be paged again.
	if stored.AlertCount != 1 {
		t.Errorf("AlertCount = %d, want 1", stored.AlertCount)
	}
	c.advance(time.Hour)
	if err := s.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if r.count() != 1 {
		t.Errorf("%d deliveries, want 1 -- an acknowledged incident must stop paging", r.count())
	}
}

// TestUnknownSeverityIsSurfacedNotSilentlySkipped. An incident with no policy
// can never alert; swallowing it is the silent failure §9 exists to prevent.
// It is also not promoted to critical, which would turn one config typo into a
// 3am phone call for every info event.
func TestUnknownSeverityIsSurfacedNotSilentlySkipped(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.Severity("urgent-ish"), "protect", "Camera offline", "", sched0)

	st := newFakeStore(inc)
	r := &recorder{}
	c := &clock{t: sched0}

	var reported []error
	s, err := NewScheduler(st, repeatingPolicy(), r.deliver,
		WithClock(c.now), WithInterval(time.Hour),
		WithErrorHandler(func(e error) { reported = append(reported, e) }))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	if err := s.Tick(ctx); err == nil {
		t.Fatal("Tick returned nil for an unschedulable incident")
	}
	if len(reported) != 1 {
		t.Fatalf("error handler called %d times, want 1", len(reported))
	}
	if r.count() != 0 {
		t.Errorf("%d deliveries, want 0 -- an unknown severity must not be promoted", r.count())
	}
	if s.Stats().Errors != 1 {
		t.Errorf("Stats().Errors = %d, want 1", s.Stats().Errors)
	}
}

// TestOneUnschedulableIncidentDoesNotStopThePass. A bad row must not take out
// every incident after it in scan order -- those would go silent.
func TestOneUnschedulableIncidentDoesNotStopThePass(t *testing.T) {
	ctx := context.Background()
	bad := incident.Open("inc-1-bad", "protect/cam-1/offline", incident.Severity("nonsense"), "protect", "t", "", sched0)
	good := incident.Open("inc-2-good", "protect/cam-2/offline", incident.SeverityHigh, "protect", "t", "", sched0)

	st := newFakeStore(bad, good)
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	if err := s.Tick(ctx); err == nil {
		t.Fatal("Tick: want the bad incident reported")
	}
	got := r.all()
	if len(got) != 1 || got[0].incidentID != "inc-2-good" {
		t.Fatalf("deliveries = %+v, want exactly one for inc-2-good", got)
	}
}

// TestTickSurfacesAStoreThatCannotBeListed. If Active fails, nothing is
// scheduled at all, and that must be loud.
func TestTickSurfacesAStoreThatCannotBeListed(t *testing.T) {
	st := newFakeStore()
	st.activeErr = errors.New("database is locked")
	r := &recorder{}
	c := &clock{t: sched0}

	var reported []error
	s, err := NewScheduler(st, repeatingPolicy(), r.deliver,
		WithClock(c.now), WithErrorHandler(func(e error) { reported = append(reported, e) }))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if err := s.Tick(context.Background()); err == nil {
		t.Fatal("Tick returned nil when the store could not be listed")
	}
	if len(reported) != 1 {
		t.Errorf("error handler called %d times, want 1", len(reported))
	}
}

// TestRunReconcilesBeforeTheFirstTickAndStopsOnCancel. The reconciling pass is
// the first tick, not a separate code path, and shutdown is clean.
func TestRunReconcilesBeforeTheFirstTickAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0.Add(-time.Hour))
	if err := inc.RecordAlert(sched0.Add(-30*time.Minute), 0); err != nil {
		t.Fatalf("RecordAlert: %v", err)
	}
	st := newFakeStore(inc)

	// Cancelling from inside the delivery makes the shutdown deterministic
	// without sleeping: Run's first pass is complete, then the loop sees a
	// cancelled context before the (one hour) ticker can fire.
	r := &recorder{hook: func(*incident.Incident) { cancel() }}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	if err := s.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil -- shutdown is not a failure", err)
	}
	if r.count() != 1 {
		t.Errorf("%d deliveries during the reconciling pass, want 1", r.count())
	}
	if got := s.Stats().Delivered; got != 1 {
		t.Errorf("Stats().Delivered = %d, want 1", got)
	}
}

func TestNewSchedulerRefusesAConfigurationThatCouldGoSilent(t *testing.T) {
	st := newFakeStore()
	r := &recorder{}

	cases := []struct {
		name     string
		store    incident.Store
		policies map[incident.Severity]Policy
		deliver  DeliverFunc
	}{
		{"no store", nil, repeatingPolicy(), r.deliver},
		{"no delivery function", st, repeatingPolicy(), nil},
		{"no policies", st, map[incident.Severity]Policy{}, r.deliver},
		{
			// Validate refuses this, and the scheduler must refuse to start
			// rather than discover it at 3am.
			name:  "critical that gives up",
			store: st,
			policies: map[incident.Severity]Policy{
				incident.SeverityCritical: {
					Name:        "bad",
					Stages:      []Stage{{After: 0, Channels: []string{"ntfy"}}},
					GiveUpAfter: time.Hour,
				},
			},
			deliver: r.deliver,
		},
		{
			name:  "stage with no channels",
			store: st,
			policies: map[incident.Severity]Policy{
				incident.SeverityHigh: {Name: "bad", Stages: []Stage{{After: 0}}},
			},
			deliver: r.deliver,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewScheduler(tc.store, tc.policies, tc.deliver); err == nil {
				t.Fatal("NewScheduler accepted it, want an error")
			}
		})
	}
}

// TestDefaultPoliciesAreSchedulable catches a shipped default that the
// scheduler would refuse to start with.
func TestDefaultPoliciesAreSchedulable(t *testing.T) {
	r := &recorder{}
	if _, err := NewScheduler(newFakeStore(), DefaultPolicies(), r.deliver); err != nil {
		t.Fatalf("the shipped default policies do not start: %v", err)
	}
}

// TestPersistFailureLeavesTheIncidentDue: if the store refuses the write after
// a successful delivery, the incident stays due and is alerted again. A
// duplicate alert is the right direction to fail in; silence is not.
func TestPersistFailureLeavesTheIncidentDue(t *testing.T) {
	ctx := context.Background()
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityHigh, "protect", "Camera offline", "", sched0)

	st := newFakeStore(inc)
	st.putErr = errors.New("disk full")
	r := &recorder{}
	c := &clock{t: sched0}
	s := newTestScheduler(t, st, repeatingPolicy(), r, c)

	for i := 0; i < 2; i++ {
		if err := s.Tick(ctx); err == nil {
			t.Fatalf("tick %d: want the persist failure reported", i)
		}
	}
	if r.count() != 2 {
		t.Errorf("%d deliveries, want 2 -- an unrecorded alert must be retried", r.count())
	}
	if got := st.must(t, "inc-1").LastAlertAt; got != nil {
		t.Errorf("LastAlertAt = %v, want nil (the write failed)", *got)
	}
}

// An acknowledgement that lands DURING delivery must survive the write that
// follows it.
//
// This is the race PutIfUnchanged exists for. The scheduler reads the
// incident, spends real time delivering it, then writes back the fact that it
// alerted -- and the ack arrives precisely in that window, because the alert
// that prompted it has just gone out. With a last-write-wins Put the ack is
// erased and the operator watches the alert keep arriving after they tapped
// the button.
func TestAckLandingDuringDeliveryIsNotOverwritten(t *testing.T) {
	st := newFakeStore()
	inc := incident.Open("i1", "access/front-door/forced-open",
		incident.SeverityCritical, "access", "Door forced open", "", t0)
	if err := st.Put(t.Context(), inc); err != nil {
		t.Fatal(err)
	}

	clk := t0
	ackAt := t0.Add(3 * time.Second)

	// Fire the ack in the narrow window the CAS exists for: AFTER the
	// scheduler re-read and mutated its copy, BEFORE it writes. The re-read
	// cannot see this ack, so only the compare-and-swap can save it.
	var once sync.Once
	st.beforePut = func(id string) {
		once.Do(func() {
			st.mu.Lock()
			cur := st.byID[id]
			acked := ackAt
			cur.AckedAt = &acked
			cur.AckVia = "ntfy"
			cur.UpdatedAt = ackAt
			st.byID[id] = cur
			st.mu.Unlock()
		})
	}

	s, err := NewScheduler(st, DefaultPolicies(),
		func(context.Context, *incident.Incident, int, []string) error { return nil },
		WithClock(func() time.Time { return clk }))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Tick(t.Context()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	got := st.must(t, "i1")
	if !got.Acknowledged() {
		t.Fatal("the acknowledgement was overwritten by the alert write -- " +
			"the operator tapped the button and the product kept paging them")
	}
	if got.AckVia != "ntfy" {
		t.Errorf("AckVia = %q, want %q", got.AckVia, "ntfy")
	}
	// The alert genuinely was delivered before the ack arrived, so recording
	// it is accurate history and is NOT suppressed. What must be true is that
	// the incident stops nagging.
	if due, _, _ := DefaultPolicies()[incident.SeverityCritical].DueNow(got, clk.Add(time.Hour)); due {
		t.Error("still scheduled to alert an hour after being acknowledged")
	}
	// UpdatedAt must not have gone backwards over the ack: the alert write
	// carries the tick's `now`, which is EARLIER than the ack that landed
	// during delivery, and the store's compare-and-swap is built on this
	// value.
	if got.UpdatedAt.Before(ackAt) {
		t.Errorf("UpdatedAt = %v, moved backwards over an ack at %v",
			got.UpdatedAt, ackAt)
	}
}

// A stale expect must be refused rather than silently applied.
func TestCommitRefusesToWriteOverANewerRow(t *testing.T) {
	st := newFakeStore()
	inc := incident.Open("i1", "k", incident.SeverityHigh, "network", "WAN down", "", t0)
	if err := st.Put(t.Context(), inc); err != nil {
		t.Fatal(err)
	}
	stale := clone(inc)
	stale.Title = "written from a stale read"

	// Somebody else writes first.
	cur := st.must(t, "i1")
	cur.UpdatedAt = t0.Add(time.Minute)
	if err := st.Put(t.Context(), cur); err != nil {
		t.Fatal(err)
	}

	err := st.PutIfUnchanged(t.Context(), stale, t0)
	if !errors.Is(err, incident.ErrConflict) {
		t.Fatalf("PutIfUnchanged with a stale expect = %v, want ErrConflict", err)
	}
	if st.must(t, "i1").Title == "written from a stale read" {
		t.Error("the stale write was applied anyway")
	}
}
