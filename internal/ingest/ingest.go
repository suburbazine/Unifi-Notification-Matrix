// Package ingest runs the sources and watches them for having stopped.
//
// It exists because a source that is merely CONSTRUCTED does nothing. Until
// this package was written the Protect source was complete and tested and
// never instantiated by the daemon, so `notifymatrix run` started, served the
// interface, ran the escalation scheduler and ingested nothing at all -- a
// product that looked entirely healthy while being blind.
//
// The second job is the one that is easy to skip. A source that dies quietly
// is indistinguishable from a quiet site, and on an alarm product those are
// opposite situations: one means nothing is happening, the other means nothing
// would be reported if it did. So every source declares how long its silence
// may last, and silence past that becomes an incident that escalates like any
// other.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/event"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

// Deps are what the supervisor needs from the rest of the product.
type Deps struct {
	// Handle receives every event. Errors are reported, never returned into
	// the source: a source blocked on the store stops reading its socket, and
	// on a socket with no resume cursor that is events lost for good.
	Handle func(ctx context.Context, ev event.Event) error

	// Raise and Resolve are the deadman's voice. They bypass the rule set --
	// an operator ignore aimed at a noisy camera must not be able to silence
	// the product reporting that it has stopped working.
	Raise   func(ctx context.Context, ent event.Entity, condition string, sev incident.Severity, title, detail string) error
	Resolve func(ctx context.Context, ent event.Entity, condition string) error

	Logf func(format string, args ...any)
	Now  func() time.Time

	// RestartDelay overrides how long a source that RETURNED is left before
	// being started again. Zero takes the default.
	//
	// Injectable so a test can assert the thing that matters here -- that a
	// source which cannot run is NOT restarted -- without waiting out the real
	// delay. A test that waits fifty milliseconds against a thirty-second
	// delay proves nothing, which is exactly what it was doing.
	RestartDelay time.Duration
}

// CheckEvery is how often the deadman looks.
//
// Far finer than any liveness window, because the check is nearly free and the
// alternative is discovering a dead source up to a whole window late.
const CheckEvery = 30 * time.Second

// restartDelay is how long a source that RETURNED is left before being
// started again.
//
// Sources reconnect internally, so Run returning at all is unexpected and
// means something structural. Restarting immediately would spin; leaving it
// stopped would be a source that silently never comes back.
const restartDelay = 30 * time.Second

// Supervisor runs sources and reports on them.
type Supervisor struct {
	deps    Deps
	sources []event.Source

	// entities is what has actually been seen, for the Rules editor.
	entities map[entityKey]*EntitySeen

	mu    sync.Mutex
	state map[string]*sourceState
}

type sourceState struct {
	name string

	// lastEventAt is the last time this source emitted ANYTHING. Started at
	// launch rather than at zero, so a source is given its full liveness
	// window before the deadman can fire -- otherwise every start would raise
	// a fault for every source with a window shorter than the start took.
	lastEventAt time.Time
	events      int64

	silent     bool
	fatal      string
	restarts   int64
	runningFor time.Time
}

// New builds a supervisor over the given sources.
func New(sources []event.Source, deps Deps) (*Supervisor, error) {
	if deps.Handle == nil {
		return nil, errors.New("ingest: no handler")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logf == nil {
		deps.Logf = func(string, ...any) {}
	}
	if deps.RestartDelay <= 0 {
		deps.RestartDelay = restartDelay
	}
	s := &Supervisor{deps: deps, sources: sources, state: map[string]*sourceState{}}
	now := deps.Now()
	for _, src := range sources {
		s.state[src.Name()] = &sourceState{name: src.Name(), lastEventAt: now, runningFor: now}
	}
	return s, nil
}

// Run starts every source and blocks until ctx is done.
//
// It returns nil even when individual sources failed. One misconfigured source
// must not stop the others: a site whose Access key is wrong still wants its
// Protect cameras watched, and refusing to start anything would take away
// working coverage to punish a typo.
func (s *Supervisor) Run(ctx context.Context) error {
	if len(s.sources) == 0 {
		// Not an error, but it IS the thing an operator most needs told. A
		// daemon with no sources is a daemon that will never raise anything.
		s.deps.Logf("ingest: no sources are configured, so nothing will be ingested")
		<-ctx.Done()
		return nil
	}

	var wg sync.WaitGroup
	for _, src := range s.sources {
		wg.Add(1)
		go func(src event.Source) {
			defer wg.Done()
			s.runSource(ctx, src)
		}(src)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runDeadman(ctx)
	}()

	wg.Wait()
	return nil
}

func (s *Supervisor) runSource(ctx context.Context, src event.Source) {
	name := src.Name()
	sink := event.SinkFunc(func(ev event.Event) {
		s.note(name)
		s.noteEntity(name, ev.Entity)
		if err := s.deps.Handle(ctx, ev); err != nil && ctx.Err() == nil {
			// Reported, never returned. See Deps.Handle.
			s.deps.Logf("ingest: %s: handling %s: %v", name, ev.Condition, err)
		}
	})

	for ctx.Err() == nil {
		err := src.Run(ctx, sink)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// A source returns non-nil only for something reconnecting cannot
			// fix -- a bad key, a certificate pin mismatch. It is recorded and
			// raised, and the source is NOT restarted in a loop against a
			// configuration that cannot work.
			s.fail(ctx, name, err)
			return
		}
		// Returned nil without cancellation: unexpected, because sources
		// reconnect internally. Restarted, with a delay, and counted so the
		// UI can show a source that keeps coming back.
		s.deps.Logf("ingest: %s stopped on its own; restarting in %s", name, s.deps.RestartDelay)
		s.mu.Lock()
		if st := s.state[name]; st != nil {
			st.restarts++
			st.runningFor = s.deps.Now()
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.deps.RestartDelay):
		}
	}
}

func (s *Supervisor) fail(ctx context.Context, name string, err error) {
	s.mu.Lock()
	if st := s.state[name]; st != nil {
		st.fatal = err.Error()
	}
	s.mu.Unlock()

	s.deps.Logf("ingest: %s cannot run: %v", name, err)
	if s.deps.Raise == nil {
		return
	}
	ent := sourceEntity(name)
	_ = s.deps.Raise(ctx, ent, event.ConditionSourceSilent, incident.SeverityHigh,
		"The "+name+" source cannot run",
		fmt.Sprintf("%v. Nothing from %s will be reported until this is fixed and "+
			"the service is restarted.", err, name))
}

func (s *Supervisor) note(name string) {
	now := s.deps.Now()
	s.mu.Lock()
	st := s.state[name]
	if st == nil {
		st = &sourceState{name: name, runningFor: now}
		s.state[name] = st
	}
	st.lastEventAt = now
	st.events++
	s.mu.Unlock()
}

// runDeadman raises an incident for a source that has gone quiet.
func (s *Supervisor) runDeadman(ctx context.Context) {
	t := time.NewTicker(CheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkLiveness(ctx)
		}
	}
}

func (s *Supervisor) checkLiveness(ctx context.Context) {
	now := s.deps.Now()
	for _, src := range s.sources {
		window := src.Liveness()
		if window <= 0 {
			// The source has declared that silence means nothing for it. An
			// explicit opt-out, not a default -- a zero here is a decision
			// somebody made in that source's code.
			continue
		}
		name := src.Name()

		s.mu.Lock()
		st := s.state[name]
		if st == nil || st.fatal != "" {
			// Already reported as unable to run. A second incident saying it
			// is also quiet adds nothing and splits the operator's attention.
			s.mu.Unlock()
			continue
		}
		last := st.lastEventAt
		s.mu.Unlock()

		// CONTACT, not events, wherever the source can tell us.
		//
		// Measuring emitted events made a quiet site indistinguishable from a
		// dead one -- the exact confusion this product exists to remove, only
		// pointed the other way. A Protect source over a still evening emits
		// nothing at all while its sockets stay perfectly healthy, and after
		// thirty minutes it was declared silent and paged about every half
		// hour until somebody closed it by hand. Observed on a real
		// installation, repeatedly, for a whole day.
		//
		// A source that knows the difference reports the last frame, poll or
		// sweep that actually reached the console. Nothing arriving THERE is a
		// fault worth waking somebody for; nothing worth emitting is a quiet
		// night, and saying so would be crying wolf.
		if c, ok := src.(event.Contactable); ok {
			if at := c.LastContact(); at.After(last) {
				last = at
			}
		}

		quiet := now.Sub(last)

		s.mu.Lock()
		wasSilent := st.silent
		nowSilent := quiet > window
		st.silent = nowSilent
		s.mu.Unlock()

		switch {
		case nowSilent && !wasSilent && s.deps.Raise != nil:
			_ = s.deps.Raise(ctx, sourceEntity(name), event.ConditionSourceSilent,
				incident.SeverityHigh,
				"The "+name+" source has gone silent",
				fmt.Sprintf("Nothing has arrived from %s since %s (%s ago), and it "+
					"reports that it should never be quiet for longer than %s. "+
					"Either the console is unreachable or this source has stopped "+
					"working -- and while it is quiet, nothing it watches is being "+
					"reported.", name, last.Format(time.RFC3339), quiet.Round(time.Second), window),
			)
		case !nowSilent && wasSilent && s.deps.Resolve != nil:
			_ = s.deps.Resolve(ctx, sourceEntity(name), event.ConditionSourceSilent)
		}
	}
}

// maxKnownEntities bounds what the Rules editor is offered.
//
// Bounded because it is fed by arriving events and nothing else prunes it. A
// site with a lot of transient clients would otherwise grow this without
// limit, which is a memory leak dressed up as a convenience.
const maxKnownEntities = 500

// entityKey identifies one observed thing. A struct rather than a joined
// string: a separator is a bug waiting for a device name that contains it.
type entityKey struct{ source, id, name string }

// EntitySeen is one thing this daemon has actually observed.
//
// BOTH the id and the name, because a rule matches either (see Rule.Matches),
// and they are different in kind: the id is stable and unreadable, the name is
// readable and changes when somebody renames a camera. An operator wants to
// pick the name; a rule that has to survive a rename wants the id.
type EntitySeen struct {
	Source string    `json:"source"`
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Kind   string    `json:"kind"`
	LastAt time.Time `json:"last_at"`
}

// noteEntity remembers something an event was about.
//
// The entity field of a rule is the one no fixed list can supply -- camera and
// door names belong to the site, not to this build -- so the only honest
// source of suggestions is what has actually come through. Everything else
// would be a guess presented as a fact.
func (s *Supervisor) noteEntity(source string, ent event.Entity) {
	if ent.ID == "" && ent.Name == "" {
		return
	}
	key := entityKey{source: source, id: ent.ID, name: ent.Name}
	now := s.deps.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entities == nil {
		s.entities = map[entityKey]*EntitySeen{}
	}
	if e, ok := s.entities[key]; ok {
		e.LastAt = now
		if ent.Name != "" {
			e.Name = ent.Name
		}
		return
	}
	if len(s.entities) >= maxKnownEntities {
		// Full. Drop the least recently seen, which is the one an operator is
		// least likely to be writing a rule about.
		var oldestKey entityKey
		var oldest time.Time
		var haveOldest bool
		for k, e := range s.entities {
			if !haveOldest || e.LastAt.Before(oldest) {
				oldestKey, oldest, haveOldest = k, e.LastAt, true
			}
		}
		delete(s.entities, oldestKey)
	}
	s.entities[key] = &EntitySeen{
		Source: source, ID: ent.ID, Name: ent.Name, Kind: ent.Kind, LastAt: now,
	}
}

// KnownEntities reports what this daemon has seen events about, most recent
// first. Empty on a fresh start, which is honest: nothing has happened yet.
func (s *Supervisor) KnownEntities() []EntitySeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]EntitySeen, 0, len(s.entities))
	for _, e := range s.entities {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastAt.Equal(out[j].LastAt) {
			return out[i].LastAt.After(out[j].LastAt)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// sourceEntity identifies one source for an internal incident. Per source, so
// two dead sources are two incidents -- see rule.RaiseInternalFor.
func sourceEntity(name string) event.Entity {
	return event.Entity{ID: "source/" + name, Name: name + " source", Kind: "service"}
}

// Status is what the supervisor knows about one source.
type Status struct {
	Name        string
	Events      int64
	LastEventAt time.Time
	Silent      bool
	Fatal       string
	Restarts    int64
	Since       time.Time

	// Expected is the source's own declared liveness window, so the interface
	// can say "quiet for 4 minutes, which is fine" rather than making the
	// reader guess whether quiet is bad.
	Expected time.Duration

	// LastContactAt is the last time the source reached its console at all,
	// where the source can tell the difference. Zero when it cannot.
	//
	// Reported separately from LastEventAt because an operator looking at a
	// healthy source over a quiet night needs to see BOTH: nothing has
	// happened, and we are still watching. Showing only the last event made a
	// working installation read as three hours dead.
	LastContactAt time.Time
}

// Statuses reports every source, for the operator interface.
func (s *Supervisor) Statuses() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Status, 0, len(s.sources))
	for _, src := range s.sources {
		st := s.state[src.Name()]
		if st == nil {
			continue
		}
		status := Status{
			Name: st.name, Events: st.events, LastEventAt: st.lastEventAt,
			Silent: st.silent, Fatal: st.fatal, Restarts: st.restarts,
			Since: st.runningFor, Expected: src.Liveness(),
		}
		if c, ok := src.(event.Contactable); ok {
			status.LastContactAt = c.LastContact()
		}
		out = append(out, status)
	}
	return out
}
