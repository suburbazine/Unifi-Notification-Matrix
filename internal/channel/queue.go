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

	ctx, cancel := context.WithTimeout(context.Background(), q.timeout)
	defer cancel()

	err := q.ch.Send(ctx, j.alert)
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
	}
}

// Close stops the worker. In-flight deliveries are allowed to finish; queued
// ones are abandoned, because on shutdown a stale alert is worse than none.
func (q *Queue) Close() {
	q.once.Do(func() { close(q.closed) })
	q.wg.Wait()
}
