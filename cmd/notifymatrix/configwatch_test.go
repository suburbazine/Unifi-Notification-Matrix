package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// A fake file, so these tests are about the decision rather than about how
// fast a filesystem updates a timestamp.
type fakeFile struct {
	now  time.Time
	st   stamp
	load func() (*config.Config, error)

	applied  int
	applyErr error
	logs     []string
}

func newWatchFixture(t *testing.T) (*configWatcher, *fakeFile) {
	t.Helper()
	f := &fakeFile{now: time.Unix(1_700_000_000, 0)}
	f.st = stamp{mod: f.now, size: 100, ok: true}
	f.load = func() (*config.Config, error) { c := config.Default(); return &c, nil }

	w := &configWatcher{
		stat: func() stamp { return f.st },
		load: func() (*config.Config, error) { return f.load() },
		apply: func(*config.Config) error {
			f.applied++
			return f.applyErr
		},
		logf: func(format string, args ...any) {
			f.logs = append(f.logs, format)
		},
		now: func() time.Time { return f.now },
	}
	w.applied = w.stat()
	return w, f
}

func (f *fakeFile) edit(size int64) {
	f.now = f.now.Add(time.Second)
	f.st = stamp{mod: f.now, size: size, ok: true}
}

func (f *fakeFile) wait(d time.Duration) { f.now = f.now.Add(d) }

// AN EDIT TO THE FILE IS AN EDIT TO THE RUNNING DAEMON.
//
// The interface's Save applies what it saves. A config.yaml edited by hand did
// not, and that is the documented path -- the setup guide tells an operator to
// edit this file. So the instructions produced a daemon that showed the new
// setting on its own page, because the page reads the file, and went on
// watching by the old one.
func TestAnEditedFileIsAppliedOnceItHasStoppedChanging(t *testing.T) {
	w, f := newWatchFixture(t)

	f.edit(120)
	w.check()
	if f.applied != 0 {
		t.Fatal("applied a file that was still being written")
	}

	f.wait(configSettle)
	w.check()
	if f.applied != 1 {
		t.Fatalf("applied %d times after the file settled, want 1 -- an edit to "+
			"config.yaml still needs a restart", f.applied)
	}

	// And not again while nothing changes.
	f.wait(time.Minute)
	w.check()
	w.check()
	if f.applied != 1 {
		t.Errorf("applied %d times; an unchanged file is being re-applied every tick", f.applied)
	}
}

// AN EDITOR IS NOT AN ATOMIC WRITER.
//
// config.Save renames into place, so its writes are never half-visible. A
// person with a text editor has no such guarantee: several truncate and then
// write, and a read inside that window returns a prefix that may well parse.
// Applying it would replace a working configuration with part of one.
func TestAFileStillBeingWrittenIsNotRead(t *testing.T) {
	w, f := newWatchFixture(t)

	for i := 0; i < 5; i++ {
		f.edit(int64(100 + i*40)) // each tick finds it a different size
		w.check()
	}
	if f.applied != 0 {
		t.Fatalf("read a file that changed on every look (%d times)", f.applied)
	}

	// It has stopped moving, but not for long enough yet. The window between
	// an editor's truncate and its write looks exactly like this: two looks in
	// a row agreeing, at a file that is not finished.
	w.check()
	if f.applied != 0 {
		t.Errorf("read the file after it had held still for less than the settle "+
			"time (%d times); two looks agreeing is not the same as finished", f.applied)
	}

	f.wait(configSettle)
	w.check()
	if f.applied != 1 {
		t.Errorf("applied %d times once the writing stopped, want 1", f.applied)
	}
}

// A file that cannot be read is reported ONCE per edit.
//
// The alternative is a line every two seconds for as long as the mistake
// stands, which buries the one line that says what is wrong -- and a log
// nobody can read is the same as no log.
func TestAnUnreadableFileIsReportedOncePerEdit(t *testing.T) {
	w, f := newWatchFixture(t)
	f.load = func() (*config.Config, error) { return nil, errors.New("line 12: what is a 'severty'") }

	f.edit(120)
	w.check() // notices
	f.wait(configSettle)
	w.check() // reads, and refuses
	for i := 0; i < 10; i++ {
		f.wait(configPollEvery)
		w.check()
	}
	if got := countLogs(f.logs, "refused"); got != 1 {
		t.Errorf("the refusal was logged %d times, want 1", got)
	}
	if f.applied != 0 {
		t.Error("a configuration that would not load was applied anyway")
	}

	// The next edit gets its own attempt, and its own line.
	f.edit(140)
	w.check()
	f.wait(configSettle)
	w.check()
	if got := countLogs(f.logs, "refused"); got != 2 {
		t.Errorf("after a second bad edit the refusal was logged %d times in all, "+
			"want 2 -- an operator who fixes one mistake and makes another is told "+
			"nothing", got)
	}
}

// THE DAEMON MUST NOT READ BACK ITS OWN SAVE.
//
// Every save from the interface rewrites this file. Without this the watcher
// finds it changed two seconds later, applies a configuration that is already
// in force, and announces it as an edit somebody made on disk -- which is a
// log line that says a thing that did not happen.
func TestTheDaemonsOwnSaveIsNotReadBackAsSomebodyElsesEdit(t *testing.T) {
	w, f := newWatchFixture(t)

	f.edit(180) // the interface's Save rewrote the file...
	w.written() // ...and said so.

	// Looked at repeatedly, with time to spare: if the save had not been
	// declared, this is exactly the sequence that would notice it, wait for it
	// to settle, and apply it.
	w.check()
	f.wait(configSettle * 2)
	w.check()
	w.check()
	if f.applied != 0 {
		t.Errorf("the daemon re-applied its own save %d time(s)", f.applied)
	}
	if len(f.logs) != 0 {
		t.Errorf("the daemon announced its own save as an edit on disk: %v", f.logs)
	}
}

// A configuration that loads but will not go into force leaves a line saying
// which part did not, because the daemon is now running a mixture.
func TestAConfigurationThatCannotBeAppliedSaysSo(t *testing.T) {
	w, f := newWatchFixture(t)
	f.applyErr = errors.New("the channels could not be rebuilt")

	f.edit(120)
	w.check()
	f.wait(configSettle)
	w.check()
	if got := countLogs(f.logs, "could not be applied"); got != 1 {
		t.Errorf("logs = %v; an operator whose edit went in halfway is told nothing", f.logs)
	}
}

func countLogs(logs []string, substr string) int {
	n := 0
	for _, l := range logs {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}
