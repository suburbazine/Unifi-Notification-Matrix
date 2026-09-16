package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/incident"
)

func newStore(t *testing.T) *SQLite {
	t.Helper()
	// TempDir registers its own cleanup first, so the Close registered below
	// runs before the directory is removed -- on Windows an open file cannot
	// be deleted and the cleanup would fail the test for the wrong reason.
	path := filepath.Join(t.TempDir(), "incidents.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("bad test timestamp %q: %v", s, err)
	}
	return v.UTC()
}

func ptr(t time.Time) *time.Time { return &t }

func mustPut(t *testing.T, s *SQLite, inc *incident.Incident) {
	t.Helper()
	if err := s.Put(context.Background(), inc); err != nil {
		t.Fatalf("Put(%s): %v", inc.ID, err)
	}
}

// TestRoundTripPreservesNilVersusSetTimestamps is the test this package exists
// for as much as any other. A nil AckedAt that comes back as a zero time makes
// incident.State() report EVERY incident acknowledged, and the product goes
// silent while claiming a human responded.
func TestRoundTripPreservesNilVersusSetTimestamps(t *testing.T) {
	base := ts(t, "2026-09-15T03:14:15.123456789Z")

	cases := []struct {
		name       string
		firstAlert *time.Time
		lastAlert  *time.Time
		acked      *time.Time
		resolved   *time.Time
		closed     *time.Time
	}{
		{name: "all nil"},
		{name: "alerted only", firstAlert: ptr(base), lastAlert: ptr(base.Add(time.Minute))},
		{name: "acked not resolved", firstAlert: ptr(base), lastAlert: ptr(base), acked: ptr(base.Add(time.Hour))},
		{name: "resolved not acked", resolved: ptr(base.Add(2 * time.Hour))},
		{name: "acked and resolved", acked: ptr(base), resolved: ptr(base.Add(time.Second))},
		{name: "closed explicitly", closed: ptr(base.Add(3 * time.Hour))},
		{
			name:       "every field set",
			firstAlert: ptr(base), lastAlert: ptr(base.Add(5 * time.Minute)),
			acked: ptr(base.Add(6 * time.Minute)), resolved: ptr(base.Add(7 * time.Minute)),
			closed: ptr(base.Add(8 * time.Minute)),
		},
		// Whole-second times are the trap: a format that collapses "not set"
		// and "the zero value" would pass every case above and fail here only
		// if it also normalised sub-second precision away.
		{name: "whole second precision", acked: ptr(ts(t, "2026-09-15T03:14:15Z"))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			inc := incident.Open("inc-"+tc.name, "protect/cam-1/"+tc.name,
				incident.SeverityCritical, "protect", "Camera offline", "PoE port flapping", base)
			inc.FirstAlertAt = tc.firstAlert
			inc.LastAlertAt = tc.lastAlert
			inc.AckedAt = tc.acked
			inc.ResolvedAt = tc.resolved
			inc.ClosedAt = tc.closed
			inc.AlertCount = 3
			inc.Stage = 2
			inc.AckVia = "ntfy"
			inc.CloseReason = "operator dismissed"
			inc.PredecessorID = "inc-previous"
			inc.LastDeliveryError = "smtp: 451 greylisted"
			inc.UpdatedAt = base.Add(9 * time.Minute)

			mustPut(t, s, inc)
			got, err := s.Get(context.Background(), inc.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			for _, f := range []struct {
				name string
				want *time.Time
				got  *time.Time
			}{
				{"FirstAlertAt", tc.firstAlert, got.FirstAlertAt},
				{"LastAlertAt", tc.lastAlert, got.LastAlertAt},
				{"AckedAt", tc.acked, got.AckedAt},
				{"ResolvedAt", tc.resolved, got.ResolvedAt},
				{"ClosedAt", tc.closed, got.ClosedAt},
			} {
				switch {
				case f.want == nil && f.got != nil:
					t.Errorf("%s: stored nil, read back %v -- a nil timestamp must never become a value", f.name, *f.got)
				case f.want != nil && f.got == nil:
					t.Errorf("%s: stored %v, read back nil", f.name, *f.want)
				case f.want != nil && !f.want.Equal(*f.got):
					t.Errorf("%s: stored %v, read back %v", f.name, *f.want, *f.got)
				}
			}

			if got.State() != inc.State() {
				t.Errorf("derived state changed across round trip: %s -> %s", inc.State(), got.State())
			}
			if !got.OpenedAt.Equal(inc.OpenedAt) {
				t.Errorf("OpenedAt: want %v, got %v", inc.OpenedAt, got.OpenedAt)
			}
			if !got.UpdatedAt.Equal(inc.UpdatedAt) {
				t.Errorf("UpdatedAt: want %v, got %v", inc.UpdatedAt, got.UpdatedAt)
			}
			if got.Severity != inc.Severity || got.AckVia != inc.AckVia ||
				got.CloseReason != inc.CloseReason || got.PredecessorID != inc.PredecessorID ||
				got.LastDeliveryError != inc.LastDeliveryError ||
				got.AlertCount != inc.AlertCount || got.Stage != inc.Stage {
				t.Errorf("scalar fields did not round trip:\n want %+v\n got  %+v", inc, got)
			}
		})
	}
}

// TestTimestampsAreStoredInUTC guards the other half of the round trip: a
// local-zone timestamp must come back as the same instant, because the
// escalation ladder is arithmetic on these values.
func TestTimestampsAreStoredInUTC(t *testing.T) {
	s := newStore(t)
	zone := time.FixedZone("UTC+13", 13*3600)
	opened := time.Date(2026, 9, 15, 3, 14, 15, 500000000, zone)

	inc := incident.Open("inc-tz", "protect/cam-tz/offline",
		incident.SeverityHigh, "protect", "t", "d", opened)
	inc.AckedAt = ptr(opened.Add(time.Minute))
	mustPut(t, s, inc)

	got, err := s.Get(context.Background(), "inc-tz")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.OpenedAt.Equal(opened) {
		t.Errorf("OpenedAt: want instant %v, got %v", opened, got.OpenedAt)
	}
	if got.OpenedAt.Location() != time.UTC {
		t.Errorf("OpenedAt location: want UTC, got %v", got.OpenedAt.Location())
	}
	if !got.AckedAt.Equal(opened.Add(time.Minute)) {
		t.Errorf("AckedAt: want %v, got %v", opened.Add(time.Minute), *got.AckedAt)
	}
}

// TestConcurrentIngestOfSameDedupKeyYieldsOneActiveIncident is the race the
// partial unique index exists for: a camera flapping on a bad PoE port emits
// fifty events a minute, several ingest goroutines look up the dedup key at
// once, all of them find nothing, and all of them try to create an incident.
// Exactly one may win.
func TestConcurrentIngestOfSameDedupKeyYieldsOneActiveIncident(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const key = "protect/cam-flapping/offline"
	const writers = 16

	// Two barriers, so the race is staged rather than hoped for: every writer
	// completes its lookup before any writer inserts. That is the real shape of
	// the bug -- all of them find nothing, all of them believe they are the
	// first -- and it makes the index the only thing standing between this
	// product and sixteen incidents for one flapping camera.
	looked := make(chan struct{}, writers)
	write := make(chan struct{})

	var wg sync.WaitGroup
	results := make([]error, writers)

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.OpenByDedupKey(ctx, key)
			if !errors.Is(err, incident.ErrNotFound) {
				results[i] = fmt.Errorf("lookup phase: want ErrNotFound, got %v", err)
				looked <- struct{}{}
				<-write
				return
			}
			looked <- struct{}{}
			<-write

			inc := incident.Open(fmt.Sprintf("inc-%02d", i), key,
				incident.SeverityCritical, "protect", "Camera offline", "flap", time.Now())
			results[i] = s.Put(ctx, inc)
		}(i)
	}
	for i := 0; i < writers; i++ {
		<-looked
	}
	close(write)
	wg.Wait()

	var won, lost int
	for i, err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrActiveExists):
			lost++
		default:
			t.Errorf("writer %d: unexpected error: %v", i, err)
		}
	}
	if won != 1 {
		t.Errorf("want exactly 1 successful create, got %d (lost %d)", won, lost)
	}

	active, err := s.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("want 1 active incident for the flapping camera, got %d", len(active))
	}
	if active[0].DedupKey != key {
		t.Errorf("active incident has dedup key %q, want %q", active[0].DedupKey, key)
	}
}

// TestClosingAnIncidentFreesItsDedupKeyForARecurrence: a condition that clears
// and comes back is a NEW incident (incident.Recur), so the key has to become
// available again the moment the old one goes terminal.
func TestClosingAnIncidentFreesItsDedupKeyForARecurrence(t *testing.T) {
	ctx := context.Background()
	key := "access/door-3/forced-open"
	base := ts(t, "2026-09-15T01:00:00Z")

	terminalWays := []struct {
		name string
		make func(*incident.Incident)
	}{
		{"closed explicitly", func(i *incident.Incident) { i.Close(base.Add(time.Minute), "operator dismissed") }},
		{"acked and resolved", func(i *incident.Incident) {
			_ = i.Acknowledge(base.Add(time.Minute), "ntfy")
			_ = i.Resolve(base.Add(2 * time.Minute))
		}},
	}

	for _, tw := range terminalWays {
		t.Run(tw.name, func(t *testing.T) {
			s := newStore(t)
			first := incident.Open("inc-1", key, incident.SeverityCritical, "access", "Door forced", "", base)
			mustPut(t, s, first)

			// While it is active the key is taken.
			second := incident.Open("inc-2", key, incident.SeverityCritical, "access", "Door forced", "", base)
			if err := s.Put(ctx, second); !errors.Is(err, ErrActiveExists) {
				t.Fatalf("second active incident on the same key: want ErrActiveExists, got %v", err)
			}

			tw.make(first)
			mustPut(t, s, first)

			if _, err := s.OpenByDedupKey(ctx, key); !errors.Is(err, incident.ErrNotFound) {
				t.Errorf("OpenByDedupKey after terminal: want ErrNotFound, got %v", err)
			}
			recurrence := first.Recur("inc-2", base.Add(time.Hour))
			if err := s.Put(ctx, recurrence); err != nil {
				t.Fatalf("recurrence rejected after predecessor went terminal: %v", err)
			}
			got, err := s.OpenByDedupKey(ctx, key)
			if err != nil {
				t.Fatalf("OpenByDedupKey: %v", err)
			}
			if got.ID != "inc-2" || got.PredecessorID != "inc-1" {
				t.Errorf("want the recurrence linked to its predecessor, got id=%s predecessor=%s", got.ID, got.PredecessorID)
			}
		})
	}
}

// TestDerivedTerminalMatchesIncidentPackage walks every combination of the
// three timestamps that decide terminality and checks that SQL and Go agree.
//
// The predicate is spelled twice -- once in the frozen migration that builds
// the partial index, once in the nonTerminal constant the queries use -- and a
// third time as incident.Incident.Terminal(). If any of the three drifts, an
// incident either stops being schedulable or blocks its own recurrence.
func TestDerivedTerminalMatchesIncidentPackage(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := ts(t, "2026-09-15T00:00:00Z")

	set := []*time.Time{nil, ptr(base.Add(time.Minute))}
	names := []string{"nil", "set"}

	wantActive := 0
	for c := range set {
		for a := range set {
			for r := range set {
				id := fmt.Sprintf("inc-c%s-a%s-r%s", names[c], names[a], names[r])
				inc := incident.Open(id, "src/"+id+"/cond", incident.SeverityHigh, "protect", "t", "d", base)
				inc.ClosedAt = set[c]
				inc.AckedAt = set[a]
				inc.ResolvedAt = set[r]
				inc.UpdatedAt = base
				mustPut(t, s, inc)

				_, err := s.OpenByDedupKey(ctx, inc.DedupKey)
				foundBySQL := err == nil
				if err != nil && !errors.Is(err, incident.ErrNotFound) {
					t.Fatalf("%s: OpenByDedupKey: %v", id, err)
				}
				if goSaysActive := !inc.Terminal(); foundBySQL != goSaysActive {
					t.Errorf("%s (state %s): SQL says active=%v, incident.Terminal() says active=%v",
						id, inc.State(), foundBySQL, goSaysActive)
				}
				if !inc.Terminal() {
					wantActive++
				}
			}
		}
	}

	active, err := s.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != wantActive {
		t.Errorf("Active returned %d incidents, want %d", len(active), wantActive)
	}
}

// TestRecentOrdersByUpdatedAtAcrossSubSecondPrecision pins the storage layout.
// RFC3339Nano drops trailing zeros, which makes "…:05Z" sort AFTER "…:05.5Z"
// as text -- so history would silently interleave.
func TestRecentOrdersByUpdatedAtAcrossSubSecondPrecision(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := ts(t, "2026-09-15T12:00:00Z")

	// Deliberately mixes whole seconds with fractional ones.
	offsets := []time.Duration{
		0,
		500 * time.Millisecond,
		time.Second,
		time.Second + 1,
		2 * time.Second,
		2*time.Second + 999999999,
	}
	for i, off := range offsets {
		inc := incident.Open(fmt.Sprintf("inc-%d", i), fmt.Sprintf("s/e%d/c", i),
			incident.SeverityLow, "network", "t", "d", base)
		inc.UpdatedAt = base.Add(off)
		// Terminal so they do not fight over the dedup index; Recent includes
		// terminal incidents by contract.
		inc.Close(base.Add(off), "test")
		inc.ClosedAt = ptr(base.Add(off))
		inc.UpdatedAt = base.Add(off)
		mustPut(t, s, inc)
	}

	got, err := s.Recent(ctx, 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != len(offsets) {
		t.Fatalf("Recent returned %d, want %d", len(got), len(offsets))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].UpdatedAt.Before(got[i].UpdatedAt) {
			t.Fatalf("Recent is not newest-first: %v came before %v",
				got[i-1].UpdatedAt, got[i].UpdatedAt)
		}
	}
	if !got[0].UpdatedAt.Equal(base.Add(offsets[len(offsets)-1])) {
		t.Errorf("newest first: got %v, want %v", got[0].UpdatedAt, base.Add(offsets[len(offsets)-1]))
	}

	limited, err := s.Recent(ctx, 2)
	if err != nil {
		t.Fatalf("Recent(2): %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("Recent(2) returned %d rows", len(limited))
	}
}

// TestPutOnSameIDUpdatesRatherThanDeletingTheDedupNeighbour: INSERT OR REPLACE
// would resolve a dedup-key conflict by DELETING the conflicting row, which
// would discard a live alarm without an error. Rewriting the same id must
// update it; a colliding id must fail.
func TestPutOnSameIDUpdatesRatherThanDeletingTheDedupNeighbour(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := ts(t, "2026-09-15T00:00:00Z")

	live := incident.Open("inc-live", "protect/cam-1/offline", incident.SeverityCritical, "protect", "Camera offline", "", base)
	mustPut(t, s, live)

	// Rewriting the same incident is an update, not a conflict.
	_ = live.RecordAlert(base.Add(time.Second), 0)
	mustPut(t, s, live)
	got, err := s.Get(ctx, "inc-live")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AlertCount != 1 || got.LastAlertAt == nil {
		t.Errorf("same-id Put did not update: %+v", got)
	}

	// A different incident claiming the same key must be refused, and the live
	// one must still be there afterwards.
	intruder := incident.Open("inc-intruder", "protect/cam-1/offline", incident.SeverityCritical, "protect", "Camera offline", "", base)
	if err := s.Put(ctx, intruder); !errors.Is(err, ErrActiveExists) {
		t.Fatalf("want ErrActiveExists, got %v", err)
	}
	if _, err := s.Get(ctx, "inc-live"); err != nil {
		t.Fatalf("the live incident was destroyed by a rejected insert: %v", err)
	}
}

func TestPutRejectsIncidentsThatWouldPoisonTheSchedule(t *testing.T) {
	s := newStore(t)
	base := ts(t, "2026-09-15T00:00:00Z")

	cases := []struct {
		name string
		inc  *incident.Incident
	}{
		{"no id", &incident.Incident{DedupKey: "a/b/c", OpenedAt: base, UpdatedAt: base}},
		// An empty dedup key is one shared key, not "no key": the partial
		// unique index would then allow exactly one active incident in the
		// whole product.
		{"no dedup key", &incident.Incident{ID: "x", OpenedAt: base, UpdatedAt: base}},
		// A zero OpenedAt puts every escalation stage in the year 1, so the
		// incident pages forever at the tick rate.
		{"zero opened_at", &incident.Incident{ID: "x", DedupKey: "a/b/c", UpdatedAt: base}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Put(context.Background(), tc.inc); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
	if err := s.Put(context.Background(), nil); err == nil {
		t.Error("Put(nil): want an error, got nil")
	}
}

// TestStateSurvivesReopen is the durability claim reduced to what a test can
// actually assert: close the process, open the same file, find the alarm still
// alarming with its timestamps intact.
func TestStateSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "incidents.db")
	base := ts(t, "2026-09-15T02:00:00.250000000Z")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	inc := incident.Open("inc-1", "protect/cam-1/offline", incident.SeverityCritical, "protect", "Camera offline", "PoE", base)
	if err := inc.RecordAlert(base.Add(30*time.Second), 1); err != nil {
		t.Fatalf("RecordAlert: %v", err)
	}
	mustPut(t, s, inc)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	active, err := reopened.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("after restart: want 1 active incident, got %d", len(active))
	}
	got := active[0]
	if got.State() != incident.StateAlerting {
		t.Errorf("after restart: state %s, want %s", got.State(), incident.StateAlerting)
	}
	if got.LastAlertAt == nil || !got.LastAlertAt.Equal(base.Add(30*time.Second)) {
		t.Errorf("after restart: LastAlertAt %v, want %v", got.LastAlertAt, base.Add(30*time.Second))
	}
	if got.Stage != 1 || got.AlertCount != 1 {
		t.Errorf("after restart: stage=%d alerts=%d, want 1/1", got.Stage, got.AlertCount)
	}
}

func TestMigrationRunsOnceAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.db")
	for i := 0; i < 3; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
	v := readUserVersion(t, path)
	if v != latestVersion() {
		t.Errorf("user_version = %d, want %d", v, latestVersion())
	}
}

// TestOpenRefusesADatabaseFromANewerBuild: a downgrade that "mostly works"
// writes rows the newer build then misreads, and the rows are live alarms.
// Refusing to start is loud; corrupting incident state is not.
func TestOpenRefusesADatabaseFromANewerBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Close()

	setUserVersion(t, path, latestVersion()+7)

	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a database written by a newer build")
	}
}

// TestConcurrentReadersAndWriters is a smoke test for the "safe for concurrent
// use" clause of the Store contract: ingest, the scheduler and the UI all
// touch it at once.
func TestConcurrentReadersAndWriters(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := ts(t, "2026-09-15T00:00:00Z")

	const n = 20
	var wg sync.WaitGroup
	errCh := make(chan error, 4*n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			inc := incident.Open(fmt.Sprintf("inc-%02d", i), fmt.Sprintf("protect/cam-%02d/offline", i),
				incident.SeverityHigh, "protect", "Camera offline", "", base.Add(time.Duration(i)*time.Second))
			if err := s.Put(ctx, inc); err != nil {
				errCh <- err
				return
			}
			if err := inc.RecordAlert(base.Add(time.Minute), 0); err != nil {
				errCh <- err
				return
			}
			if err := s.Put(ctx, inc); err != nil {
				errCh <- err
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Active(ctx); err != nil {
				errCh <- err
			}
			if _, err := s.Recent(ctx, 10); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent access: %v", err)
	}

	active, err := s.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != n {
		t.Errorf("want %d active incidents, got %d", n, len(active))
	}
}

func TestGetAndOpenByDedupKeyReportNotFound(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, incident.ErrNotFound) {
		t.Errorf("Get: want incident.ErrNotFound, got %v", err)
	}
	if _, err := s.OpenByDedupKey(ctx, "nope/nope/nope"); !errors.Is(err, incident.ErrNotFound) {
		t.Errorf("OpenByDedupKey: want incident.ErrNotFound, got %v", err)
	}
}

// TestDurabilityPragmasAreSetOnEveryPooledConnection. The PRAGMAs live in the
// DSN precisely because synchronous and busy_timeout are per connection;
// running them once against the pool would configure exactly one.
//
// The assertions that carry the weight here are busy_timeout and foreign_keys,
// not synchronous. This driver already defaults synchronous to 2 (FULL), so
// checking only that value passes whether or not synchronous=FULL is in the
// DSN at all -- a test that certifies a setting it cannot see. busy_timeout
// defaults to 0 and foreign_keys to OFF, so both differ from what we ask for
// AND are per-connection: if the DSN pragmas were ever "simplified" into one
// db.Exec after Open, exactly one connection would carry them and the
// remaining three would fail here. The synchronous check stays because it
// still catches somebody explicitly choosing NORMAL.
func TestDurabilityPragmasAreSetOnEveryPooledConnection(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Hold several connections open at once so the checks below cannot all
	// land on the same one.
	var conns []*sql.Conn
	for i := 0; i < 4; i++ {
		c, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatalf("Conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i, c := range conns {
		var journal string
		if err := c.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
			t.Fatalf("conn %d journal_mode: %v", i, err)
		}
		if journal != "wal" {
			t.Errorf("conn %d: journal_mode = %q, want wal", i, journal)
		}
		var sync int
		if err := c.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&sync); err != nil {
			t.Fatalf("conn %d synchronous: %v", i, err)
		}
		// 2 == FULL. NORMAL (1) survives a process crash but not power loss,
		// and the commits it loses are the most recent ones -- the incident
		// that opened seconds before the power went out.
		if sync != 2 {
			t.Errorf("conn %d: synchronous = %d, want 2 (FULL)", i, sync)
		}
		// Default 0. Without it, a write that meets another process's lock
		// fails instead of waiting, and the incident is simply not recorded.
		var busy int
		if err := c.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
			t.Fatalf("conn %d busy_timeout: %v", i, err)
		}
		if busy != 10000 {
			t.Errorf("conn %d: busy_timeout = %d, want 10000 -- this connection was never configured", i, busy)
		}
		// Default OFF, and per connection like the two above.
		var fk int
		if err := c.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("conn %d foreign_keys: %v", i, err)
		}
		if fk != 1 {
			t.Errorf("conn %d: foreign_keys = %d, want 1", i, fk)
		}
	}
}

// TestConcurrentOpenOfTheSameDatabaseAllSucceed. Two processes can hold this
// file at once and the daemon has to cope: a service restart overlaps its
// predecessor, an operator leaves a sqlite3 session open, an upgrade runs two
// daemons for a moment.
//
// Two distinct failures live here, and both were real. Reading user_version
// outside the migration transaction lets both openers decide to apply
// migration 1, and the loser dies on "table incidents already exists". And the
// first connection to a brand-new file converts it to WAL, which answers
// SQLITE_BUSY immediately rather than waiting out busy_timeout. Either one
// means a daemon that does not start, which is indistinguishable from a daemon
// that has nothing to say.
func TestConcurrentOpenOfTheSameDatabaseAllSucceed(t *testing.T) {
	const openers = 4
	// Repeated because the window is the first write transaction on a fresh
	// file: it is narrow, and a single attempt can miss it.
	for run := 0; run < 5; run++ {
		path := filepath.Join(t.TempDir(), "incidents.db")

		var wg sync.WaitGroup
		stores := make([]*SQLite, openers)
		errs := make([]error, openers)
		for i := 0; i < openers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				stores[i], errs[i] = Open(path)
			}(i)
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Errorf("run %d opener %d: %v", run, i, err)
			}
		}
		for _, s := range stores {
			if s != nil {
				if err := s.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}
		}
		if t.Failed() {
			return
		}
		if v := readUserVersion(t, path); v != latestVersion() {
			t.Fatalf("run %d: user_version = %d, want %d", run, v, latestVersion())
		}
	}
}

func readUserVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	return v
}

func setUserVersion(t *testing.T, path string, v int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
}

// PutIfUnchanged against the real database, not the scheduler's fake. The two
// could otherwise drift, and the fake is the one every scheduler test trusts.
func TestPutIfUnchangedComparesAndSwaps(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	opened := ts(t, "2026-09-15T03:00:00Z")

	inc := incident.Open("i1", "access/front-door/forced-open",
		incident.SeverityCritical, "access", "Door forced open", "", opened)
	mustPut(t, s, inc)

	t.Run("writes when unchanged", func(t *testing.T) {
		cur, err := s.Get(ctx, "i1")
		if err != nil {
			t.Fatal(err)
		}
		expect := cur.UpdatedAt
		cur.Title = "updated"
		cur.UpdatedAt = opened.Add(time.Minute)
		if err := s.PutIfUnchanged(ctx, cur, expect); err != nil {
			t.Fatalf("PutIfUnchanged: %v", err)
		}
		got, _ := s.Get(ctx, "i1")
		if got.Title != "updated" {
			t.Errorf("Title = %q, want %q", got.Title, "updated")
		}
	})

	t.Run("refuses a stale expect and changes nothing", func(t *testing.T) {
		cur, err := s.Get(ctx, "i1")
		if err != nil {
			t.Fatal(err)
		}
		stale := *cur
		stale.Title = "written from a stale read"
		stale.UpdatedAt = opened.Add(2 * time.Minute)

		err = s.PutIfUnchanged(ctx, &stale, opened) // the ORIGINAL updated_at
		if !errors.Is(err, incident.ErrConflict) {
			t.Fatalf("PutIfUnchanged with a stale expect = %v, want ErrConflict", err)
		}
		got, _ := s.Get(ctx, "i1")
		if got.Title == "written from a stale read" {
			t.Fatal("the refused write was applied anyway")
		}
	})

	t.Run("a deleted row is ErrNotFound, never a resurrection", func(t *testing.T) {
		// It cannot INSERT: resurrecting a deleted incident would also
		// resurrect whatever acknowledgement was on the caller's copy.
		gone := incident.Open("does-not-exist", "k", incident.SeverityHigh,
			"network", "x", "", opened)
		err := s.PutIfUnchanged(ctx, gone, opened)
		if !errors.Is(err, incident.ErrNotFound) {
			t.Fatalf("PutIfUnchanged on a missing row = %v, want ErrNotFound", err)
		}
		if _, err := s.Get(ctx, "does-not-exist"); !errors.Is(err, incident.ErrNotFound) {
			t.Fatal("PutIfUnchanged created a row it should have refused")
		}
	})

	t.Run("exactly one of two racing writers wins", func(t *testing.T) {
		cur, err := s.Get(ctx, "i1")
		if err != nil {
			t.Fatal(err)
		}
		expect := cur.UpdatedAt

		var wg sync.WaitGroup
		results := make([]error, 8)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c := *cur
				c.Title = fmt.Sprintf("writer-%d", i)
				c.UpdatedAt = expect.Add(time.Duration(i+1) * time.Second)
				results[i] = s.PutIfUnchanged(ctx, &c, expect)
			}(i)
		}
		wg.Wait()

		var won, conflicted int
		for _, err := range results {
			switch {
			case err == nil:
				won++
			case errors.Is(err, incident.ErrConflict):
				conflicted++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if won != 1 {
			t.Errorf("%d writers won, want exactly 1 -- the compare-and-swap "+
				"is what stops an acknowledgement being overwritten", won)
		}
		if conflicted != len(results)-1 {
			t.Errorf("%d conflicts, want %d", conflicted, len(results)-1)
		}
	})
}
