package channel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultQueueDepth bounds a channel's backlog.
//
// Bounded rather than unbounded because an unbounded alert queue turns a
// delivery outage into a memory leak: the mail server is down for six hours,
// the queue grows for six hours, and the process dies holding every alert it
// was supposed to send.
const DefaultQueueDepth = 200

// DefaultSendTimeout bounds one delivery, INCLUDING any retry ladder the
// channel runs internally.
//
// 60s rather than 30s because of a specific arithmetic collision. The ntfy
// channel's bounded 429 retry sleeps 2s + 8s + 20s = 30s across four attempts,
// so a 30s budget could never fund the fourth attempt — the channel documented
// a ladder it was structurally incapable of climbing, and rate-limited alerts
// were abandoned one rung early.
//
// The cost of the larger budget is bounded by the queue being per channel: a
// worker stalled for a minute on ntfy delays nothing but ntfy. And 60s still
// sits well inside the shortest escalation interval (2 minutes for critical),
// so a slow delivery cannot collide with the next scheduled one.
//
// If a channel ever needs a longer internal ladder than this, it must say so
// rather than silently truncating: the ladder and this budget are one number
// in two places, and they have already disagreed once.
const DefaultSendTimeout = 60 * time.Second

// ErrQueueFull means the backlog is full and this alert was dropped.
var ErrQueueFull = errors.New("channel queue is full")

// Result reports the outcome of one queued delivery.
type Result struct {
	Channel    string
	IncidentID string
	Err        error
	At         time.Time
}

// Queue runs one channel's deliveries on its own worker.
//
// ONE QUEUE PER CHANNEL, deliberately. A single shared queue lets a stalled
// SMTP connection delay every push notification behind it -- and the push is
// the one that was going to wake somebody up. Per-channel queues mean a dead
// mail server costs you email and nothing else.
//
// This exists at all because delivery must never block ingest. A greylisting
// mail server will otherwise drag the whole ingest cycle progressively later,
// which is a failure that has been observed in production rather than a
// hypothetical.
type Queue struct {
	ch      Channel
	in      chan job
	timeout time.Duration

	onResult func(Result)

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	dropped  int
	inflight bool

	// consecutiveFails and notBefore are the failure backoff.
	//
	// Without one, a channel that is failing is retried at whatever cadence
	// the escalation ladder repeats at -- and a ladder doing its job repeats
	// often. Observed: a broken ntfy configuration republished every twenty
	// seconds for hours and got the installation BANNED by the service, which
	// turned a misconfigured channel into no channel at all, including for the
	// alarms that would otherwise have gone through once it was fixed.
	//
	// So repeated failure widens the gap between attempts. It is not a circuit
	// breaker that gives up: every attempt still happens eventually, and the
	// incident stays due the whole time, because an alarm nobody has been told
	// about must not be marked as delivered.
	consecutiveFails int
	notBefore        time.Time
	lastBackoff      time.Duration
}

// failureBackoff is the ladder applied to consecutive failures.
//
// Deliberately short at the start and hard-capped: a channel that failed once
// is usually about to succeed, and a channel that has failed twenty times is
// not going to be fixed by being asked again in thirty seconds. Five minutes
// is the ceiling because that is roughly the longest an operator will accept
// between fixing a channel and seeing it recover.
var failureBackoff = []time.Duration{
	0, // the first failure costs nothing: try again immediately
	15 * time.Second,
	30 * time.Second,
	time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

// backoffFor is the wait after n consecutive failures.
// n is the count of consecutive failures, so the FIRST failure is n=1 and
// reads the first rung. Indexing by n rather than n-1 skipped that rung and
// charged a fifteen-second delay for a single blip.
func backoffFor(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	if n > len(failureBackoff) {
		return failureBackoff[len(failureBackoff)-1]
	}
	return failureBackoff[n-1]
}

// ErrBackingOff is returned instead of attempting a send that is being held
// back after repeated failures.
//
// An error rather than a silent skip, and it carries when the next attempt is:
// the caller is the escalation scheduler, which must keep the incident DUE. A
// skip reported as success would mark an alarm delivered that nobody received,
// which is the one lie this product cannot tell.
type ErrBackingOff struct {
	Channel string
	Until   time.Time
	Fails   int
}

func (e *ErrBackingOff) Error() string {
	return fmt.Sprintf("%s has failed %d times in a row, so delivery is being "+
		"held back until %s to avoid being rate-limited or blocked by the service; "+
		"the incident stays open and will be retried",
		e.Channel, e.Fails, e.Until.Format(time.RFC3339))
}

type job struct {
	alert Alert
	now   time.Time

	// result, when non-nil, receives the outcome. Buffered by the sender so
	// the worker never blocks on a caller that gave up waiting.
	result chan<- error
}

// NewQueue starts a worker for ch. Call Close to stop it.
func NewQueue(ch Channel, depth int, onResult func(Result)) *Queue {
	if depth <= 0 {
		depth = DefaultQueueDepth
	}
	q := &Queue{
		ch:       ch,
		in:       make(chan job, depth),
		timeout:  DefaultSendTimeout,
		onResult: onResult,
		closed:   make(chan struct{}),
	}
	q.wg.Add(1)
	go q.run()
	return q
}

// Enqueue hands an alert to the worker. It never blocks.
//
// Returning ErrQueueFull rather than blocking is the whole contract: the
// caller is the escalation scheduler, and a scheduler blocked on a dead
// channel stops scheduling every other incident.
func (q *Queue) Enqueue(a Alert, now time.Time) error {
	select {
	case <-q.closed:
		return errors.New("channel queue is closed")
	default:
	}
	select {
	case q.in <- job{alert: a, now: now}:
		return nil
	default:
		q.mu.Lock()
		q.dropped++
		n := q.dropped
		q.mu.Unlock()
		return fmt.Errorf("%w (%d dropped on %s)", ErrQueueFull, n, q.ch.Name())
	}
}

func (q *Queue) run() {
	defer q.wg.Done()
	for {
		select {
		case <-q.closed:
			return
		case j := <-q.in:
			q.deliver(j)
		}
	}
}

func (q *Queue) deliver(j job) {
	q.mu.Lock()
	q.inflight = true
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		q.inflight = false
		q.mu.Unlock()
	}()

	// Held back? Then this attempt does not happen, and the reason is reported
	// rather than swallowed.
	q.mu.Lock()
	holding := !q.notBefore.IsZero() && j.now.Before(q.notBefore)
	held := &ErrBackingOff{Channel: q.ch.Name(), Until: q.notBefore, Fails: q.consecutiveFails}
	q.mu.Unlock()

	var err error
	if holding {
		err = held
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
		err = q.ch.Send(ctx, j.alert)
		cancel()
		q.recordOutcome(err, j.now)
	}
	if j.result != nil {
		// Buffered by the sender, so this never blocks even if the caller has
		// already timed out and walked away.
		j.result <- err
	}
	if q.onResult != nil {
		q.onResult(Result{
			Channel:    q.ch.Name(),
			IncidentID: j.alert.IncidentID,
			Err:        err,
			At:         j.now,
		})
	}
}

// SendAndWait queues an alert and waits for the outcome.
//
// The escalation scheduler needs to know whether the alert actually landed:
// only a SUCCESSFUL delivery may advance LastAlertAt, because if every channel
// failed then nobody has been told and the incident must stay due. So it
// waits, where ingest does not.
//
// That distinction is the whole design. DESIGN-RULES §5 says delivery must
// never block INGEST -- a greylisting mail server must not drag the poll cycle
// -- and the sources are what that protects. The scheduler is a separate
// goroutine and is allowed to wait for an answer.
//
// Queuing is still what serialises a channel: one send in flight per channel,
// bounded backlog, and a stalled SMTP connection cannot delay an ntfy push
// because they are different queues.
func (q *Queue) SendAndWait(ctx context.Context, a Alert, now time.Time) error {
	res := make(chan error, 1)

	select {
	case <-q.closed:
		return errors.New("channel queue is closed")
	default:
	}
	select {
	case q.in <- job{alert: a, now: now, result: res}:
	default:
		q.mu.Lock()
		q.dropped++
		n := q.dropped
		q.mu.Unlock()
		return fmt.Errorf("%w (%d dropped on %s)", ErrQueueFull, n, q.ch.Name())
	}

	select {
	case err := <-res:
		return err
	case <-ctx.Done():
		// The send is still running and will still be attempted; we simply
		// stop waiting. Reported as a failure so the incident stays due --
		// erring toward a duplicate alert, never toward silence.
		return fmt.Errorf("%s: gave up waiting for delivery: %w", q.ch.Name(), ctx.Err())
	case <-q.closed:
		return errors.New("channel queue closed while the alert was in flight")
	}
}

// Stats describes the queue for diagnostics.
type Stats struct {
	Channel  string
	Depth    int
	Pending  int
	Dropped  int
	InFlight bool

	// ConsecutiveFails and BackingOffUntil make the backoff visible.
	//
	// A channel quietly not being attempted is indistinguishable from one that
	// is fine, and this product's whole argument is against states like that.
	ConsecutiveFails int
	BackingOffUntil  time.Time
}

// recordOutcome advances or clears the failure backoff.
func (q *Queue) recordOutcome(err error, now time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err == nil {
		// One success clears the whole ladder. A channel that just worked is
		// working, and making it climb back down would keep punishing it for
		// an outage that is over.
		q.consecutiveFails = 0
		q.notBefore = time.Time{}
		q.lastBackoff = 0
		return
	}
	q.consecutiveFails++
	q.lastBackoff = backoffFor(q.consecutiveFails)
	if q.lastBackoff > 0 {
		q.notBefore = now.Add(q.lastBackoff)
	} else {
		q.notBefore = time.Time{}
	}
}

func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return Stats{
		Channel:  q.ch.Name(),
		Depth:    cap(q.in),
		Pending:  len(q.in),
		Dropped:  q.dropped,
		InFlight: q.inflight,

		ConsecutiveFails: q.consecutiveFails,
		BackingOffUntil:  q.notBefore,
	}
}

// Close stops the worker. In-flight deliveries are allowed to finish; queued
// ones are abandoned, because on shutdown a stale alert is worse than none.
func (q *Queue) Close() {
	q.once.Do(func() { close(q.closed) })
	q.wg.Wait()
}

// TestSummary reports what this channel's Test actually did, or "" when the
// generic "a message was delivered" answer is true for it.
//
// Forwarded from the channel rather than exposing the channel itself, so the
// queue stays the only thing that touches it.
func (q *Queue) TestSummary() string {
	if td, ok := q.ch.(TestDescriber); ok {
		return td.TestSummary()
	}
	return ""
}

// Test sends the channel's own proof-of-configuration message.
//
// Deliberately NOT queued. A test is a person standing in front of the screen
// waiting for an answer, so it must report what actually happened to THIS
// attempt -- and a queued test would report "accepted" and then fail silently
// behind whatever else is in the queue, which is the exact confusion the
// button exists to remove.
//
// It therefore also bypasses the depth limit, which is correct: one deliberate
// message from an operator is not the burst the limit is protecting against.
func (q *Queue) Test(ctx context.Context) error {
	select {
	case <-q.closed:
		return errors.New("channel queue is closed")
	default:
	}
	ctx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()
	err := q.ch.Test(ctx)

	// A test that WORKS clears the failure backoff.
	//
	// The backoff exists because a channel that keeps failing should be asked
	// less often, and the operator's way out of it is to fix the channel. But
	// the test button bypassed the hold without clearing it, so the sequence
	// that actually happens -- fix the topic, press Test, see it pass -- left
	// real alerts held for up to another five minutes with a green tick on
	// screen saying everything was fine. The button exists to remove exactly
	// that kind of confusion.
	//
	// Only on success. A failed test is more evidence of the thing the backoff
	// is already reacting to, and is deliberately NOT counted as another
	// failure either: an operator pressing a diagnostic button should not push
	// their own channel further down the ladder.
	if err == nil {
		q.recordOutcome(nil, time.Time{})
	}
	return err
}
