package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileName is the current audit file inside the data directory.
const FileName = "audit.jsonl"

// DefaultMaxBytes is when the current file is rotated.
const DefaultMaxBytes = 8 << 20 // 8 MiB

// DefaultKeep is how many rotated files are retained.
//
// Deliberately generous. This is the record somebody consults months after an
// incident, and the cost of keeping it is a few megabytes of text.
const DefaultKeep = 10

// File is an append-only JSONL audit log.
//
// JSONL rather than a table in the incident database, for three reasons that
// all point the same way:
//
//   - APPEND-ONLY IS STRUCTURAL. Editing a past entry means rewriting the
//     file; there is no UPDATE. That is not tamper-proofing -- anyone with
//     write access can rewrite anything -- but it means casual, accidental or
//     well-meaning rewriting does not happen, which covers most of what
//     actually goes wrong with records.
//   - An operator can read it with `tail` and `grep` at 3am, with no tooling,
//     over SSH, while the product is broken. A database needs the product to
//     be working to answer questions about why the product is not working.
//   - It survives the incident store being deleted, which is a thing people do
//     when trying to fix something.
type File struct {
	dir      string
	maxBytes int64
	keep     int

	mu   sync.Mutex
	f    *os.File
	size int64

	// onError reports a write failure. Appending must never fail the
	// operation being recorded -- an alert that was delivered but could not be
	// written down is still delivered -- so failures surface here instead of
	// being returned into the caller's path.
	onError func(error)
}

// Option configures a File.
type Option func(*File)

// WithMaxBytes sets the rotation threshold.
func WithMaxBytes(n int64) Option { return func(f *File) { f.maxBytes = n } }

// WithKeep sets how many rotated files are retained.
func WithKeep(n int) Option { return func(f *File) { f.keep = n } }

// WithErrorHandler reports write failures out of band.
func WithErrorHandler(fn func(error)) Option { return func(f *File) { f.onError = fn } }

// Open opens or creates the audit log in dir.
func Open(dir string, opts ...Option) (*File, error) {
	if dir == "" {
		return nil, errors.New("audit: no directory given")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: creating %s: %w", dir, err)
	}
	a := &File{dir: dir, maxBytes: DefaultMaxBytes, keep: DefaultKeep}
	for _, o := range opts {
		o(a)
	}
	if err := a.reopen(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *File) path() string { return filepath.Join(a.dir, FileName) }

func (a *File) reopen() error {
	// O_APPEND: every write goes to the end regardless of what else has the
	// file open, and the kernel makes writes under the pipe buffer size atomic
	// -- so a second process (the CLI reading while the daemon writes) cannot
	// interleave half a line into the middle of another.
	f, err := os.OpenFile(a.path(), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: opening %s: %w", a.path(), err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: %s: %w", a.path(), err)
	}
	a.f, a.size = f, st.Size()

	// Heal a torn tail.
	//
	// A crash mid-append leaves a line with no newline. Without this the NEXT
	// entry is concatenated onto it, so one lost record becomes two: the torn
	// one AND the first good one after the restart -- which is the entry most
	// likely to explain the crash. Terminating it turns the damage into
	// exactly one skipped line.
	if a.size > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, a.size-1); err == nil && last[0] != byte('\n') {
			if n, err := f.Write([]byte{'\n'}); err == nil {
				a.size += int64(n)
			}
		}
	}
	return nil
}

// Append writes one entry.
func (a *File) Append(_ context.Context, e Entry) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = e.At.UTC()
	if e.Kind == "" {
		e.Kind = "unknown"
	}
	e.scrub()

	b, err := json.Marshal(e)
	if err != nil {
		a.report(fmt.Errorf("audit: encoding %s: %w", e.Kind, err))
		return err
	}
	b = append(b, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return errors.New("audit: log is closed")
	}
	if a.size+int64(len(b)) > a.maxBytes {
		if err := a.rotateLocked(); err != nil {
			// Rotation failed: keep writing to the current file rather than
			// dropping the record. An oversized audit file is a nuisance; a
			// missing entry is the thing this package exists to prevent.
			a.report(err)
		}
	}
	n, err := a.f.Write(b)
	a.size += int64(n)
	if err != nil {
		a.report(fmt.Errorf("audit: writing: %w", err))
		return err
	}
	// Flushed on every entry. The entries that matter most are the ones
	// written immediately before a crash -- an acknowledgement, a config
	// change, the alert that went out just before the power failed -- so
	// buffering them is buffering exactly the wrong records. Volume here is
	// incidents and deliveries, not raw packets, so the cost is small.
	if err := a.f.Sync(); err != nil {
		a.report(fmt.Errorf("audit: flushing: %w", err))
	}
	return nil
}

func (a *File) report(err error) {
	if a.onError != nil {
		a.onError(err)
	}
}

// rotateLocked renames the current file and starts a new one.
func (a *File) rotateLocked() error {
	if err := a.f.Close(); err != nil {
		return fmt.Errorf("audit: closing before rotation: %w", err)
	}
	a.f = nil

	// Timestamped rather than numbered: numbered rotation renames every file
	// on every rotation, which on a crash mid-rotation can lose one. A name
	// that is written once is never renamed again.
	//
	// The suffix exists because the first version used one-second granularity,
	// and two rotations inside the same second produced the same name --
	// os.Rename then SILENTLY CLOBBERED the older file, destroying a whole
	// audit file. Found by a test that rotated quickly, which is exactly what
	// an alarm storm does.
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	rotated := filepath.Join(a.dir, fmt.Sprintf("audit-%s.jsonl", stamp))
	for i := 1; ; i++ {
		if _, err := os.Stat(rotated); errors.Is(err, os.ErrNotExist) {
			break
		}
		rotated = filepath.Join(a.dir, fmt.Sprintf("audit-%s-%d.jsonl", stamp, i))
	}
	if err := os.Rename(a.path(), rotated); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = a.reopen()
		return fmt.Errorf("audit: rotating: %w", err)
	}
	if err := a.reopen(); err != nil {
		return err
	}
	a.pruneLocked()
	return nil
}

func (a *File) pruneLocked() {
	entries, err := filepath.Glob(filepath.Join(a.dir, "audit-*.jsonl"))
	if err != nil || len(entries) <= a.keep {
		return
	}
	sort.Strings(entries) // timestamped names sort chronologically
	for _, p := range entries[:len(entries)-a.keep] {
		_ = os.Remove(p)
	}
}

// Recent returns the newest entries, newest first.
//
// Reads the current file and walks backwards through rotated ones until it has
// enough, so a listing does not go empty immediately after a rotation.
func (a *File) Recent(_ context.Context, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}
	files := []string{a.path()}
	if rotated, err := filepath.Glob(filepath.Join(a.dir, "audit-*.jsonl")); err == nil {
		sort.Sort(sort.Reverse(sort.StringSlice(rotated)))
		files = append(files, rotated...)
	}

	var out []Entry
	for _, p := range files {
		got, err := readTail(p, limit-len(out))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return out, err
		}
		// readTail returns oldest-first; prepend keeps the overall order
		// newest-first as we walk back through older files.
		out = append(out, reverse(got)...)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// readTail returns up to n entries from the end of a file, oldest first.
//
// Reads forward with a bounded ring rather than seeking backwards: audit files
// are capped at a few megabytes, a ring of n entries is small, and the simple
// version has no partial-line edge case to get wrong at the seek boundary.
func readTail(path string, n int) ([]Entry, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ring := make([]Entry, 0, n)
	sc := bufio.NewScanner(f)
	// A single entry can carry a long summary; the default 64KiB token limit
	// would silently stop the scan at the first oversized line, which reads as
	// "the audit record ends here".
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// A corrupt line -- a torn write from a crash -- must not hide
			// every entry after it. Skipped, and counted by being visibly
			// absent rather than by failing the whole read.
			continue
		}
		if len(ring) == n {
			copy(ring, ring[1:])
			ring = ring[:n-1]
		}
		ring = append(ring, e)
	}
	if err := sc.Err(); err != nil {
		return ring, fmt.Errorf("audit: reading %s: %w", path, err)
	}
	return ring, nil
}

func reverse(in []Entry) []Entry {
	out := make([]Entry, len(in))
	for i, e := range in {
		out[len(in)-1-i] = e
	}
	return out
}

// Close flushes and closes the current file.
func (a *File) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	f := a.f
	a.f = nil
	return f.Close()
}

// Path is the current audit file, for diagnostics and for telling an operator
// where to look.
func (a *File) Path() string { return a.path() }
