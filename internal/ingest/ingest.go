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
//
// The third job is Replace: the set of sources changes while the daemon runs,
// because every other answer to "I changed the API key" is "restart the
// service", and a restart is the one thing an operator should never have to
// do to a product whose job is to be running.
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

	// NoteEntity persists something this product has seen an event about, and
	// KnownFrom reads back what was recorded before this process started.
	//
	// Injected rather than taking a store, so this package still depends on
	// nothing concrete. Both nil in a build that keeps no record -- the
	// in-memory map remains and behaves as it always did, which is what the
	// tests in this package run against.
	NoteEntity func(ctx context.Context, e EntitySeen)
	KnownFrom  func(ctx context.Context) []EntitySeen

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

// ErrStopped is returned by Replace once Run has returned. Nothing can be
// started under a context that is already done, and pretending otherwise
// would report a source as running that never will.
var ErrStopped = errors.New("ingest: the supervisor has stopped")

// Supervisor runs sources and reports on them.
type Supervisor struct {
	deps Deps

	// entities is what has actually been seen, for the Rules editor. It
	// belongs to the SITE, not to any source: a Replace that swapped every
	// source would still leave it exactly as it was.
	entities map[entityKey]*EntitySeen

	// replaceMu serialises Replace against itself. It is a separate lock from
	// mu because a Replace waits for the sources it stopped to actually exit,
	// and a source on its way out takes mu to record its last event; waiting
	// under mu would deadlock the daemon on its own reconfiguration.
	replaceMu sync.Mutex

	mu sync.Mutex
	// running is the current set, in the order the caller gave it. The
	// deadman checks exactly this list and Statuses reports exactly this
	// list, so the two can never disagree with what is actually running.
	running []*runner
	// live is every source goroutine that has not yet exited, whether or not
	// it is still in running. Shutdown waits on it so a source removed
	// moments before the daemon stopped is not left mid-teardown.
	live map[*runner]struct{}
	// ctx is Run's, nil until Run is called. stopped is set once it is done.
	ctx     context.Context
	stopped bool
}

// runner is one source and everything the supervisor knows about it.
//
// The state travels WITH the source rather than living in a map keyed by
// Name, because Name is the application -- "protect" -- and two things can
// carry it at once: a second console, or the same console after somebody
// corrected its key. The record of what the first one reported must not be
// inherited by the second, or the board says a source that has never
// connected has been heard from.
type runner struct {
	src event.Source

	// Guarded by Supervisor.mu.
	state sourceState

	// cancel stops this source alone; done is closed when its goroutine has
	// actually returned. Both nil until the source is started.
	cancel context.CancelFunc
	done   chan struct{}
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
	s := &Supervisor{deps: deps, live: map[*runner]struct{}{}}
	for _, src := range sources {
		if src == nil {
			return nil, errors.New("ingest: nil source")
		}
		s.running = append(s.running, s.newRunner(src))
	}
	return s, nil
}

// newRunner makes the record for a source that is about to be started, with
// its liveness clock at now.
func (s *Supervisor) newRunner(src event.Source) *runner {
	now := s.deps.Now()
	return &runner{src: src, state: sourceState{name: src.Name(), lastEventAt: now, runningFor: now}}
}

// Run starts every source and blocks until ctx is done.
//
// It returns nil even when individual sources failed. One misconfigured source
// must not stop the others: a site whose Access key is wrong still wants its
// Protect cameras watched, and refusing to start anything would take away
// working coverage to punish a typo.
func (s *Supervisor) Run(ctx context.Context) error {
	// BEFORE the sources start, and before the no-sources case below: an
	// installation whose console has been unplugged still has a record of what
	// it used to watch, and that is exactly when somebody wants to read it.
	s.loadKnownEntities(ctx)

	s.mu.Lock()
	if s.ctx != nil {
		s.mu.Unlock()
		return errors.New("ingest: Run called twice")
	}
	s.ctx = ctx
	if len(s.running) == 0 {
		// Not an error, but it IS the thing an operator most needs told. A
		// daemon with no sources is a daemon that will never raise anything.
		s.deps.Logf("ingest: no sources are configured, so nothing will be ingested")
	}
	for _, r := range s.running {
		s.start(r)
	}
	s.mu.Unlock()

	// The deadman runs here, on the caller's goroutine, until ctx is done. It
	// runs even with no sources, because Replace can add some.
	s.runDeadman(ctx)

	// ctx is done. Nothing may be started from here on, and everything that
	// was started is waited for -- including sources a Replace had removed
	// and was still waiting on, because those are in live too.
	s.mu.Lock()
	s.stopped = true
	live := make([]*runner, 0, len(s.live))
	for r := range s.live {
		live = append(live, r)
	}
	s.mu.Unlock()
	for _, r := range live {
		<-r.done
	}
	return nil
}

// start launches the goroutine for r. Called with mu held and s.ctx set.
func (s *Supervisor) start(r *runner) {
	parent := s.ctx
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.done = make(chan struct{})
	s.live[r] = struct{}{}
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.live, r)
			s.mu.Unlock()
			close(r.done)
		}()
		s.runSource(ctx, parent, r)
	}()
}

// Replace makes next the set of running sources.
//
// A source in next that is ALREADY running -- the same value, not merely the
// same name -- is left exactly as it is: its connection, its backoff state and
// its record of what it has reported all survive. A running source that is
// not in next is stopped, and Replace does not return until its goroutine has
// actually exited. Anything else in next is started fresh, with its full
// liveness window ahead of it and no memory of whatever ran under that name
// before.
//
// Identity is the value because the name is not enough. Name is the
// application, "protect", and a Protect source built from a corrected API key
// has the same name as the broken one it replaces; keeping the old one
// because the name matched would leave the daemon watching nothing and
// looking healthy. The caller built both, so the caller is the one that knows
// whether they are the same thing -- it says so by passing the same value.
//
// Safe to call while events are arriving and from any goroutine; calls are
// serialised. Before Run it simply sets what Run will start. After Run has
// returned it refuses with ErrStopped.
func (s *Supervisor) Replace(next []event.Source) (Change, error) {
	s.replaceMu.Lock()
	defer s.replaceMu.Unlock()

	var change Change

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return change, ErrStopped
	}
	current := map[event.Source]*runner{}
	for _, r := range s.running {
		current[r.src] = r
	}
	var (
		running = make([]*runner, 0, len(next))
		kept    = map[*runner]bool{}
		started []*runner
		seen    = map[event.Source]bool{}
	)
	for _, src := range next {
		if src == nil {
			s.mu.Unlock()
			return change, errors.New("ingest: nil source")
		}
		if seen[src] {
			s.mu.Unlock()
			return change, fmt.Errorf("ingest: the %s source is listed twice", src.Name())
		}
		seen[src] = true
		if r := current[src]; r != nil {
			running = append(running, r)
			kept[r] = true
			change.Kept = append(change.Kept, r.state.name)
			continue
		}
		r := s.newRunner(src)
		running = append(running, r)
		started = append(started, r)
		change.Started = append(change.Started, r.state.name)
	}
	var removed []*runner
	for _, r := range s.running {
		if kept[r] {
			continue
		}
		removed = append(removed, r)
		change.Stopped = append(change.Stopped, r.state.name)
		if r.cancel != nil {
			r.cancel()
		}
	}
	s.running = running
	if len(running) == 0 && s.ctx != nil {
		s.deps.Logf("ingest: no sources are configured, so nothing will be ingested")
	}
	s.mu.Unlock()

	// Wait for the removed sources to be GONE, not merely told to go. A
	// caller that reads Statuses the instant this returns must not see a
	// source it just removed still counting events.
	for _, r := range removed {
		if r.done != nil {
			<-r.done
		}
	}

	// A removed source's open incident is about a configuration that no
	// longer exists. Left alone it would escalate for ever, because the only
	// thing that could resolve it is the deadman seeing that source speak
	// again, and that source will never run again. Resolved BEFORE the
	// replacements start, so a replacement that fails at once and raises on
	// the same name is not resolved by mistake a moment later.
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for _, r := range removed {
		s.mu.Lock()
		open := r.state.silent || r.state.fatal != ""
		s.mu.Unlock()
		s.deps.Logf("ingest: %s stopped: no longer configured", r.state.name)
		if open && s.deps.Resolve != nil && !s.watchedAndFaulted(r.state.name) {
			_ = s.deps.Resolve(ctx, sourceEntity(r.state.name), event.ConditionSourceSilent)
		}
	}

	s.mu.Lock()
	if s.ctx != nil && !s.stopped {
		for _, r := range started {
			s.start(r)
		}
	}
	s.mu.Unlock()
	return change, nil
}

// watchedAndFaulted reports whether a source still running under name has an
// open deadman incident of its own. Two consoles both running Protect share
// one incident entity (see sourceEntity), so removing one must not resolve
// what the other is still reporting.
func (s *Supervisor) watchedAndFaulted(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.running {
		if r.state.name == name && (r.state.silent || r.state.fatal != "") {
			return true
		}
	}
	return false
}

// Change is what a Replace did, by source name, for the log and the audit
// record. Names repeat when two consoles run the same application.
type Change struct {
	Kept    []string
	Started []string
	Stopped []string
}

// Sources is the current set, in order. What Replace would keep if handed
// the same values back.
func (s *Supervisor) Sources() []event.Source {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]event.Source, 0, len(s.running))
	for _, r := range s.running {
		out = append(out, r.src)
	}
	return out
}

// runSource runs one source until ctx -- this source's own -- is done.
//
// parent is the supervisor's context, and it is what events and incidents
// are handled under: an event that arrived as its source was being removed
// still happened, and dropping it because the source's context had just been
// cancelled would lose the last thing a camera said before its console was
// reconfigured.
func (s *Supervisor) runSource(ctx, parent context.Context, r *runner) {
	name := r.state.name
	sink := event.SinkFunc(func(ev event.Event) {
		s.note(r)
		s.noteEntity(name, ev.Entity)
		if err := s.deps.Handle(parent, ev); err != nil && parent.Err() == nil {
			// Reported, never returned. See Deps.Handle.
			s.deps.Logf("ingest: %s: handling %s: %v", name, ev.Condition, err)
		}
	})

	for ctx.Err() == nil {
		err := r.src.Run(ctx, sink)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// A source returns non-nil only for something reconnecting cannot
			// fix -- a bad key, a certificate pin mismatch. It is recorded and
			// raised, and the source is NOT restarted in a loop against a
			// configuration that cannot work.
			s.fail(parent, r, err)
			return
		}
		// Returned nil without cancellation: unexpected, because sources
		// reconnect internally. Restarted, with a delay, and counted so the
		// UI can show a source that keeps coming back.
		s.deps.Logf("ingest: %s stopped on its own; restarting in %s", name, s.deps.RestartDelay)
		s.mu.Lock()
		r.state.restarts++
		r.state.runningFor = s.deps.Now()
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.deps.RestartDelay):
		}
	}
}

func (s *Supervisor) fail(ctx context.Context, r *runner, err error) {
	name := r.state.name
	s.mu.Lock()
	r.state.fatal = err.Error()
	s.mu.Unlock()

	s.deps.Logf("ingest: %s cannot run: %v", name, err)
	if s.deps.Raise == nil {
		return
	}
	ent := sourceEntity(name)
	_ = s.deps.Raise(ctx, ent, event.ConditionSourceSilent, incident.SeverityHigh,
		"The "+name+" source cannot run",
		fmt.Sprintf("%v. Nothing from %s will be reported until this is fixed.", err, name))
}

func (s *Supervisor) note(r *runner) {
	now := s.deps.Now()
	s.mu.Lock()
	r.state.lastEventAt = now
	r.state.events++
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
	s.mu.Lock()
	running := append([]*runner(nil), s.running...)
	s.mu.Unlock()

	for _, r := range running {
		src := r.src
		window := src.Liveness()
		if window <= 0 {
			// The source has declared that silence means nothing for it. An
			// explicit opt-out, not a default -- a zero here is a decision
			// somebody made in that source's code.
			continue
		}
		name := r.state.name

		s.mu.Lock()
		if r.state.fatal != "" {
			// Already reported as unable to run. A second incident saying it
			// is also quiet adds nothing and splits the operator's attention.
			s.mu.Unlock()
			continue
		}
		last := r.state.lastEventAt
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
		wasSilent := r.state.silent
		nowSilent := quiet > window
		r.state.silent = nowSilent
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
	Source string `json:"source"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`

	// MAC is carried because it is the only identifier that survives BOTH a
	// rename and a re-adoption. The name survives re-adoption and breaks on a
	// rename; the id survives a rename and breaks on re-adoption, because a
	// UniFi device id is generated at adoption time. Nothing matches on it
	// yet; it is recorded so that the thing which will can be built.
	MAC string `json:"mac,omitempty"`

	// FirstAt is when this was first seen, where the durable record knows.
	// Zero for an entity this process observed with nothing written down.
	FirstAt time.Time `json:"first_at,omitempty"`
	LastAt  time.Time `json:"last_at"`
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
	if len(s.entities) >= maxKnownEntities && s.deps.NoteEntity == nil {
		// Full, and nothing is writing this down. Drop the least recently
		// seen.
		//
		// ONLY when there is no durable record. With one, evicting by recency
		// discards the camera that stopped reporting first, which after a
		// power cut or a lightning strike is precisely the row somebody needs
		// -- the cache would forget the losses and keep the survivors. The
		// bound stays for a build with no store because an unbounded map fed
		// by arriving events is a memory leak dressed up as a convenience.
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
		Source: source, ID: ent.ID, Name: ent.Name, Kind: ent.Kind,
		MAC: ent.MAC, LastAt: now,
	}
	s.persist(EntitySeen{
		Source: source, ID: ent.ID, Name: ent.Name, Kind: ent.Kind,
		MAC: ent.MAC, LastAt: now,
	})
}

// persist writes an entity to the durable record, if there is one.
//
// Called with the lock held and doing its own work outside it would be worse:
// the write is a single upsert on an indexed primary key, and releasing the
// lock to do it would let two events about one device race to create the row.
// The store serialises writers anyway.
func (s *Supervisor) persist(e EntitySeen) {
	if s.deps.NoteEntity == nil {
		return
	}
	s.deps.NoteEntity(context.Background(), e)
}

// loadKnownEntities seeds the in-memory map from the durable record.
//
// Without this the rules editor is empty for as long as it takes each device
// to say something -- which for a camera that has been quiet since before the
// restart is indefinitely, and for a device destroyed in the event that caused
// the restart is for ever. The record is the answer to "what did this site
// have", and it is useless if the product only consults it for things that
// have already spoken again.
func (s *Supervisor) loadKnownEntities(ctx context.Context) {
	if s.deps.KnownFrom == nil {
		return
	}
	prior := s.deps.KnownFrom(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entities == nil {
		s.entities = map[entityKey]*EntitySeen{}
	}
	for _, e := range prior {
		key := entityKey{source: e.Source, id: e.ID, name: e.Name}
		if _, ok := s.entities[key]; ok {
			continue
		}
		seen := e
		s.entities[key] = &seen
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

	// LastError is why the source's last read failed, "" when it did not.
	//
	// Reported beside LastContactAt because the pair is the whole diagnosis: a
	// source with no contact and no error has not tried yet; one with no
	// contact and an error is broken, and the error says how.
	LastError string

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
	out := make([]Status, 0, len(s.running))
	for _, r := range s.running {
		st := r.state
		status := Status{
			Name: st.name, Events: st.events, LastEventAt: st.lastEventAt,
			Silent: st.silent, Fatal: st.fatal, Restarts: st.restarts,
			Since: st.runningFor, Expected: r.src.Liveness(),
		}
		if c, ok := r.src.(event.Contactable); ok {
			status.LastContactAt = c.LastContact()
		}
		if d, ok := r.src.(event.Diagnosable); ok {
			status.LastError = d.LastError()
		}
		out = append(out, status)
	}
	return out
}
