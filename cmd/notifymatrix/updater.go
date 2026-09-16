package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/update"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// updater holds what the last check found, so the interface can show it
// without going to the network every time somebody opens a tab.
type updater struct {
	mu        sync.Mutex
	client    update.Client
	current   string
	latest    *update.Release
	checkedAt time.Time
	lastErr   string
}

func newUpdater(current string) *updater { return &updater{current: current} }

// exePath is the binary an update would replace.
func exePath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Resolve symlinks, or an update replaces the link and leaves the real
	// binary untouched -- which looks like it worked and changes nothing.
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return p, nil
}

// applicable reports whether this installation could install an update, and
// why not when it could not.
//
// Answered before anything is downloaded. Finding out that the binary is not
// writable AFTER fetching and verifying it wastes the operator's time and
// leaves a file on disk for no reason.
func applicable() (bool, string) {
	if !update.CanVerifyPublisher() {
		return false, "this build cannot check who signed a replacement, so it will " +
			"not install one. Verify the download with cosign (docs/RELEASING.md) " +
			"and replace the binary yourself."
	}
	exe, err := exePath()
	if err != nil {
		return false, "the running binary could not be located: " + err.Error()
	}
	// Writability of the DIRECTORY, because the install is two renames rather
	// than a write to the file itself.
	f, err := os.CreateTemp(filepath.Dir(exe), ".notifymatrix-writetest-*")
	if err != nil {
		return false, fmt.Sprintf("%s cannot be written to by the account this "+
			"service runs as, so the binary there cannot be replaced: %v",
			filepath.Dir(exe), err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true, ""
}

func (u *updater) state() web.UpdateState {
	u.mu.Lock()
	defer u.mu.Unlock()

	can, why := applicable()
	st := web.UpdateState{
		Current:  u.current,
		Checked:  u.checkedAt,
		Error:    u.lastErr,
		CanApply: can,
		Why:      why,
	}
	if u.latest != nil {
		st.Available = u.latest.Version
		st.ReleaseURL = u.latest.URL
		st.PublishedAt = u.latest.PublishedAt
	}
	return st
}

func (u *updater) check(ctx context.Context) (web.UpdateState, error) {
	rel, err := u.client.Check(ctx, u.current)

	u.mu.Lock()
	u.checkedAt = time.Now()
	if err != nil {
		// Kept and shown. A check that failed quietly is indistinguishable
		// from being up to date, and that is how a machine sits on a build
		// with a known problem believing it is current.
		u.lastErr = err.Error()
		u.latest = nil
	} else {
		u.lastErr = ""
		u.latest = rel
	}
	u.mu.Unlock()

	if err != nil {
		return u.state(), err
	}
	return u.state(), nil
}

// apply downloads, verifies and installs, then restarts the service.
//
// The version the operator saw is passed back in and checked against what the
// feed now offers. Without it, a release published between the check and the
// click gets installed instead -- silently, and not the one they agreed to.
func (u *updater) apply(ctx context.Context, wantVersion, dataDir string) error {
	if can, why := applicable(); !can {
		return fmt.Errorf("update: %s", why)
	}

	u.mu.Lock()
	rel := u.latest
	u.mu.Unlock()

	if rel == nil {
		return fmt.Errorf("update: nothing has been found to install -- check first")
	}
	if wantVersion != "" && wantVersion != rel.Version {
		return fmt.Errorf("update: you asked to install %s but the newest release is "+
			"now %s. Check again and look at what changed before installing it",
			wantVersion, rel.Version)
	}

	exe, err := exePath()
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// Download performs BOTH gates: the checksum against the release's own
	// manifest, and the Authenticode publisher check against the binary
	// running now. It returns an error rather than a file if either fails.
	verified, err := u.client.Download(ctx, rel, exe)
	if err != nil {
		return err
	}
	if err := update.Apply(verified, exe); err != nil {
		return err
	}

	// Restarting is what makes the new binary the running one. A successful
	// update that is still running the old code is the same as no update, and
	// worse because the version on the page now disagrees with the process.
	if err := restartSelf(service.New(), dataDir); err != nil {
		return fmt.Errorf("update: %s was installed, but the service could not be "+
			"restarted (%w). It will come up on the new version the next time it "+
			"starts", rel.Version, err)
	}
	return nil
}
