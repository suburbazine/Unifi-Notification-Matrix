package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)

func open(t *testing.T, opts ...Option) (*File, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := Open(dir, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, dir
}

func TestAppendAndReadBack(t *testing.T) {
	a, dir := open(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := a.Append(ctx, Entry{
			At: t0.Add(time.Duration(i) * time.Minute), Kind: KindAcknowledged,
			Actor: "ntfy", IncidentID: fmt.Sprintf("i%d", i),
			Summary: fmt.Sprintf("acknowledged %d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Newest first: an operator opening this wants the most recent thing.
	got, err := a.Recent(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if got[0].IncidentID != "i2" {
		t.Errorf("first entry is %s, want the newest (i2)", got[0].IncidentID)
	}

	// One JSON object per line, greppable with no tooling -- which is the
	// point of the format.
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("file has %d lines, want 3", len(lines))
	}
	for i, l := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

// THE ONE THAT MATTERS. This file is plain text, is meant to be grepped, and
// gets pasted into support tickets.
func TestSecretsNeverReachTheFile(t *testing.T) {
	a, dir := open(t)
	const canary = "SUPER-SECRET-CONSOLE-KEY"

	err := a.Append(context.Background(), Entry{
		Kind:    KindConfigChanged,
		Actor:   "web",
		Summary: "settings saved",
		Fields: map[string]string{
			"api_key":        canary,
			"ntfy_token":     canary,
			"smtp_password":  canary,
			"session_cookie": canary,
			"Authorization":  canary,
			"console":        "10.0.0.1", // not a credential: must survive
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("a credential reached the audit file:\n%s", raw)
	}
	// Over-redacting is free; under-redacting is a key in a text file forever.
	// But ordinary fields must still be useful.
	if !strings.Contains(string(raw), "10.0.0.1") {
		t.Errorf("a non-credential field was redacted too:\n%s", raw)
	}
}

func TestLongValuesAreCapped(t *testing.T) {
	a, dir := open(t)
	huge := strings.Repeat("x", 100_000)
	if err := a.Append(context.Background(), Entry{
		Kind: KindEvent, Summary: huge,
		Fields: map[string]string{"detail": huge},
	}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 20_000 {
		t.Errorf("one entry wrote %d bytes; an unbounded field can fill a disk", st.Size())
	}
}

func TestRotationKeepsHistoryReadable(t *testing.T) {
	a, dir := open(t, WithMaxBytes(2048), WithKeep(3))
	ctx := context.Background()

	for i := 0; i < 120; i++ {
		if err := a.Append(ctx, Entry{
			At: t0.Add(time.Duration(i) * time.Second), Kind: KindAlertSent,
			IncidentID: fmt.Sprintf("i%03d", i),
			Summary:    strings.Repeat("padding ", 5),
		}); err != nil {
			t.Fatal(err)
		}
	}

	rotated, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if len(rotated) == 0 {
		t.Fatal("nothing rotated")
	}
	if len(rotated) > 3 {
		t.Errorf("%d rotated files kept, want at most 3", len(rotated))
	}

	// A listing must not go empty just because a rotation happened -- Recent
	// walks back into rotated files.
	got, err := a.Recent(ctx, 40)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 40 {
		t.Errorf("Recent returned %d entries after rotation, want 40 -- the "+
			"history view would look empty right after a rotation", len(got))
	}
	if got[0].IncidentID != "i119" {
		t.Errorf("newest entry is %s, want i119", got[0].IncidentID)
	}
}

// A torn write from a crash must not hide every entry after it.
func TestACorruptLineDoesNotHideTheRest(t *testing.T) {
	a, dir := open(t)
	ctx := context.Background()

	if err := a.Append(ctx, Entry{At: t0, Kind: KindEvent, IncidentID: "before"}); err != nil {
		t.Fatal(err)
	}
	// A power cut mid-append leaves a line with no newline. Simulated the way
	// it really happens: the process dies, the file is left torn, and a new
	// process opens it.
	a.Close()
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"at":"2026-09-16T03:0`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	a2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	if err := a2.Append(ctx, Entry{At: t0.Add(time.Minute), Kind: KindEvent, IncidentID: "after"}); err != nil {
		t.Fatal(err)
	}
	got, err := a2.Recent(ctx, 10)
	if err != nil {
		t.Fatalf("a corrupt line failed the whole read: %v", err)
	}
	var ids []string
	for _, e := range got {
		ids = append(ids, e.IncidentID)
	}
	joined := strings.Join(ids, ",")
	if !strings.Contains(joined, "before") || !strings.Contains(joined, "after") {
		t.Errorf("entries either side of a torn line were lost: %v", ids)
	}
}

// Appends come from ingest, the scheduler and the web UI at once.
func TestConcurrentAppendsProduceWholeLines(t *testing.T) {
	a, dir := open(t)
	ctx := context.Background()

	const n = 60
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = a.Append(ctx, Entry{
				Kind: KindAlertSent, IncidentID: fmt.Sprintf("i%02d", i),
				Summary: "concurrent",
			})
		}(i)
	}
	wg.Wait()

	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d", len(lines), n)
	}
	for i, l := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("line %d is interleaved or truncated: %v\n%s", i, err, l)
		}
	}
}

// A write failure must be reported, never returned into the path of the thing
// being recorded: an alert that was delivered but could not be written down is
// still an alert that was delivered.
func TestWriteFailuresAreReportedOutOfBand(t *testing.T) {
	var got []error
	a, _ := open(t, WithErrorHandler(func(err error) { got = append(got, err) }))

	// Close the underlying file out from under it.
	a.mu.Lock()
	a.f.Close()
	a.mu.Unlock()

	_ = a.Append(context.Background(), Entry{Kind: KindEvent, Summary: "x"})
	if len(got) == 0 {
		t.Error("a write failure was not reported to the error handler")
	}
}

func TestAppendFillsInTheTimestamp(t *testing.T) {
	a, _ := open(t)
	before := time.Now().Add(-time.Second)
	if err := a.Append(context.Background(), Entry{Kind: KindEvent, Summary: "x"}); err != nil {
		t.Fatal(err)
	}
	got, err := a.Recent(context.Background(), 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("Recent = %v, %v", got, err)
	}
	if got[0].At.Before(before) {
		t.Errorf("At = %v, want a filled-in current time", got[0].At)
	}
	if got[0].At.Location() != time.UTC {
		t.Errorf("At is in %v, want UTC -- an audit record read in another "+
			"timezone must not be ambiguous", got[0].At.Location())
	}
}

func TestNopDiscards(t *testing.T) {
	var l Log = Nop{}
	if err := l.Append(context.Background(), Entry{Kind: KindEvent}); err != nil {
		t.Fatal(err)
	}
	got, err := l.Recent(context.Background(), 10)
	if err != nil || len(got) != 0 {
		t.Errorf("Nop.Recent = %v, %v", got, err)
	}
}

// Two rotations in quick succession must produce two files.
//
// The first implementation stamped rotated names to the SECOND, so two
// rotations inside one second produced the same name and os.Rename silently
// clobbered the older file -- destroying a whole audit file with no error
// anywhere. An alarm storm is exactly the condition that rotates quickly.
//
// Asserted directly rather than inferred from a count of readable entries: the
// indirect version passed or failed on timing, which is how a test comes to
// certify a bug.
func TestRapidRotationsDoNotOverwriteEachOther(t *testing.T) {
	// Big enough for one entry, small enough that the next one rotates.
	a, dir := open(t, WithMaxBytes(300), WithKeep(50))
	ctx := context.Background()

	const rotations = 6
	for i := 0; i < rotations+1; i++ {
		if err := a.Append(ctx, Entry{
			Kind: KindAlertSent, IncidentID: fmt.Sprintf("i%02d", i),
			Summary: strings.Repeat("p", 200),
		}); err != nil {
			t.Fatal(err)
		}
	}

	rotated, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != rotations {
		t.Fatalf("%d rotated files for %d rotations -- names collided and an "+
			"audit file was overwritten:\n%v", len(rotated), rotations, rotated)
	}

	// And every entry must still be findable across the set.
	seen := map[string]bool{}
	all, err := a.Recent(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		seen[e.IncidentID] = true
	}
	for i := 0; i < rotations+1; i++ {
		if id := fmt.Sprintf("i%02d", i); !seen[id] {
			t.Errorf("entry %s was lost across rotation", id)
		}
	}
}
