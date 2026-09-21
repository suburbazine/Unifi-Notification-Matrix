package main

import (
	"context"
	"os"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// The configuration file, watched.
//
// Settings saved through the interface take effect at once. A config.yaml
// edited on disk did not, and the two being different is worse than either
// being slow: the setup guide tells an operator to edit this file by hand, so
// the documented path was the one that silently did nothing. Somebody adds a
// console, sees the interface list it -- the page reads the file -- and
// concludes it is being watched.
//
// POLLED RATHER THAN NOTIFIED. A filesystem watcher is a dependency, and it is
// the wrong one here: this file lives on a UniFi gateway's /data, on a Windows
// program directory, and inside containers with overlay filesystems, and inotify
// semantics differ across all of them. Two seconds of latency on a change a
// human just made by hand is not worth a per-platform failure mode -- and a
// poll that finds nothing costs one stat.

const (
	// configPollEvery is how often the file is looked at.
	configPollEvery = 2 * time.Second

	// configSettle is how long it must hold still before it is read.
	//
	// AN EDITOR IS NOT AN ATOMIC WRITER. config.Save writes and renames, so its
	// own writes are never half-visible, but a person editing the file has no
	// such guarantee: several editors truncate and then write, and reading in
	// that window yields a valid-looking prefix. Waiting for the size and the
	// timestamp to stop moving costs two seconds and removes the whole class.
	configSettle = 2 * time.Second
)

// stamp is what "the file changed" means here.
//
// Modification time AND size, because a timestamp alone has one-second
// granularity on some filesystems and an edit that replaces one character
// inside the same second is exactly the kind a person makes.
type stamp struct {
	mod  time.Time
	size int64
	ok   bool
}

func (a stamp) same(b stamp) bool {
	return a.ok == b.ok && a.size == b.size && a.mod.Equal(b.mod)
}

// configWatcher applies changes made to the file rather than to the page.
type configWatcher struct {
	stat  func() stamp
	load  func() (*config.Config, error)
	apply func(*config.Config) error
	logf  func(format string, args ...any)
	now   func() time.Time

	// applied is the last stamp this watcher has dealt with -- by applying it,
	// by refusing it, or by being told the daemon wrote it.
	applied stamp

	pending      stamp
	pendingSince time.Time
}

func newConfigWatcher(dataDir string, apply func(*config.Config) error,
	logf func(string, ...any)) *configWatcher {
	path := config.Path(dataDir)
	w := &configWatcher{
		stat: func() stamp {
			fi, err := os.Stat(path)
			if err != nil {
				return stamp{}
			}
			return stamp{mod: fi.ModTime(), size: fi.Size(), ok: true}
		},
		load:  func() (*config.Config, error) { return config.Load(dataDir) },
		apply: apply,
		logf:  logf,
		now:   time.Now,
	}
	w.applied = w.stat()
	return w
}

// written tells the watcher that this daemon produced the file's current
// contents, so it does not read back its own save and announce it as somebody
// else's edit.
func (w *configWatcher) written() {
	if w == nil {
		return
	}
	w.applied = w.stat()
	w.pending = stamp{}
}

// check is one pass. Separated from run so a test can drive it a tick at a
// time rather than sleeping.
func (w *configWatcher) check() {
	cur := w.stat()
	if cur.same(w.applied) {
		w.pending = stamp{}
		return
	}
	if !cur.same(w.pending) {
		// It is still moving. Note where it is and look again next time.
		w.pending = cur
		w.pendingSince = w.now()
		return
	}
	if w.now().Sub(w.pendingSince) < configSettle {
		return
	}

	// Whatever happens below, this version has been dealt with. A file that
	// cannot be read must not be retried every two seconds until somebody
	// fixes it -- the next edit is what gets the next attempt.
	w.applied = cur
	w.pending = stamp{}

	next, err := w.load()
	if err != nil {
		// Once per edit, which the line above is what guarantees: a file that
		// cannot be read is not re-read every two seconds until somebody fixes
		// it, and the next edit gets its own attempt and its own line. An
		// operator who corrects one mistake and makes another must be told
		// again -- even when the complaint is word for word the same one.
		w.logf("the configuration file changed on disk and was refused, so this "+
			"daemon is still running the previous one: %v", err)
		return
	}
	if err := w.apply(next); err != nil {
		w.logf("the configuration file changed on disk and could not be applied "+
			"in full: %v", err)
		return
	}
	w.logf("the configuration file changed on disk; applied without a restart")
}

func (w *configWatcher) run(ctx context.Context) {
	if w == nil {
		return
	}
	t := time.NewTicker(configPollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check()
		}
	}
}
