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

// DefaultSendTimeout bounds one delivery attempt.
const DefaultSendTimeout = 30 * time.Second

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
	if q.onResult != nil {
		q.onResult(Result{
			Channel:    q.ch.Name(),
			IncidentID: j.alert.IncidentID,
			Err:        err,
			At:         j.now,
		})
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
