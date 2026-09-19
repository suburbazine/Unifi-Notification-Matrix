//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DefaultUser is the unprivileged account the service runs as.
//
// Least privilege, decided in ARCHITECTURE.md §9a. The consequence carried
// forward: this account can READ a systemd-creds host-key credential (systemd
// decrypts it as root before dropping privileges) but can never WRITE one, so
// UI-entered secrets use the TPM tier where a TPM exists and the key-file tier
// otherwise.
const DefaultUser = "notifymatrix"

func defaultDataDir() string { return "/var/lib/" + Name }

// New returns the systemd manager.
func New() Manager { return systemdManager{} }

type systemdManager struct{}

const systemctlTimeout = 30 * time.Second

func systemctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("systemctl %s timed out after %s", strings.Join(args, " "), systemctlTimeout)
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return strings.TrimSpace(stdout.String()), fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (systemdManager) UnitText(o InstallOptions) (string, error) {
	o = withLinuxDefaults(o)
	return RenderUnit(o)
}

func withLinuxDefaults(o InstallOptions) InstallOptions {
	if o.ExePath == "" {
		o.ExePath, _ = os.Executable()
	}

	// A UNIFI GATEWAY IS A DIFFERENT PLATFORM, not a Linux box with different
	// defaults, and the differences are corrections rather than preferences --
	// so they are detected rather than asked for. An operator who had to know
	// to pass a flag would otherwise get a unit that does not start.
	o.Appliance = o.Appliance || OnUniFiOS()

	if o.DataDir == "" {
		if o.Appliance {
			o.DataDir = UniFiOSDataDir
		} else {
			o.DataDir = defaultDataDir()
		}
	}
	if o.User == "" {
		if o.Appliance {
			// ROOT ON THE APPLIANCE, and this is a real departure from
			// ARCHITECTURE.md 9a's least-privilege rule, so it is stated
			// rather than slipped in.
			//
			// A UniFi gateway has no useradd on every image, administers
			// itself as root, and keeps /etc on an overlay shared with the
			// firmware. Creating a system account there is a change to
			// somebody else's base image that has to survive their upgrades,
			// for a boundary that buys little on a box where the operator's
			// own shell is root already.
			//
			// --user still works for anybody who has made an account and
			// knows their image keeps it.
			o.User = "root"
		} else {
			o.User = DefaultUser
		}
	}
	return o
}

func (m systemdManager) Install(o InstallOptions) error {
	if os.Geteuid() != 0 {
		return ErrNeedsPrivilege
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("%w: systemctl is not on PATH", ErrUnsupported)
	}
	o = withLinuxDefaults(o)

	// HEADROOM BEFORE ANYTHING IS WRITTEN. On a gateway the thing being
	// protected is not this product: it is the routing and inspection sharing
	// the hardware. Checked first so a refusal leaves nothing behind.
	if o.Appliance {
		if _, _, err := CheckHeadroom(); err != nil {
			return err
		}
	}

	unit, err := RenderUnit(o)
	if err != nil {
		return err
	}
	if err := ensureUser(o.User); err != nil {
		return err
	}
	// The appliance unit has no StateDirectory to create it, so the daemon's
	// own directory is made here, at the same mode StateDirectoryMode would
	// have given it.
	if o.Appliance {
		if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
			return fmt.Errorf("service: creating %s: %w", o.DataDir, err)
		}
	}
	// 0644: systemd must read it, and it contains no secret -- the credential
	// it references is encrypted and lives elsewhere.
	if err := os.WriteFile(UnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("service: writing %s: %w", UnitPath, err)
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err := systemctl("enable", Name); err != nil {
		return err
	}
	if _, err := systemctl("start", Name); err != nil {
		return err
	}
	return nil
}

// ensureUser creates the service account if it is missing.
//
// A system account with no login shell and no home: it exists to own a state
// directory and hold a TPM group membership, and nothing should ever log in as
// it.
func ensureUser(user string) error {
	if user == "" || user == "root" {
		return nil
	}
	if _, err := exec.Command("id", "-u", user).Output(); err == nil {
		return nil // already exists
	}
	useradd, err := exec.LookPath("useradd")
	if err != nil {
		return fmt.Errorf("service: user %q does not exist and useradd is not "+
			"available to create it; create it by hand, or pass --user root", user)
	}
	out, err := exec.Command(useradd,
		"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", user).CombinedOutput()
	if err != nil {
		return fmt.Errorf("service: creating user %q: %s", user, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemdManager) Uninstall() error {
	if os.Geteuid() != 0 {
		return ErrNeedsPrivilege
	}
	if _, err := os.Stat(UnitPath); errors.Is(err, os.ErrNotExist) {
		return ErrNotInstalled
	}
	// Best effort through stop and disable: a unit that will not stop must
	// still be removable.
	_, _ = systemctl("stop", Name)
	_, _ = systemctl("disable", Name)
	if err := os.Remove(UnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service: removing %s: %w", UnitPath, err)
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	// The state directory is deliberately LEFT BEHIND. It holds the incident
	// history, and an uninstall that silently deletes the record of every
	// alarm the site has ever had is not a thing to do without being asked.
	return nil
}

func (systemdManager) Start() error {
	if os.Geteuid() != 0 {
		return ErrNeedsPrivilege
	}
	_, err := systemctl("start", Name)
	return err
}

func (systemdManager) Stop() error {
	if os.Geteuid() != 0 {
		return ErrNeedsPrivilege
	}
	_, err := systemctl("stop", Name)
	return err
}

func (systemdManager) Status() (Status, error) {
	if _, err := os.Stat(UnitPath); errors.Is(err, os.ErrNotExist) {
		return Status{State: StateNotInstalled}, nil
	}
	out := Status{State: StateUnknown}

	// `show` rather than `status`: a stable key=value contract instead of
	// human prose that changes between systemd releases.
	props, err := systemctl("show", Name,
		"--property=ActiveState,MainPID,UnitFileState,Restart,StartLimitIntervalUSec")
	if err != nil {
		return out, err
	}
	kv := map[string]string{}
	for _, line := range strings.Split(props, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[k] = v
		}
	}

	switch kv["ActiveState"] {
	case "active", "activating":
		out.State = StateRunning
	case "inactive", "failed", "deactivating":
		out.State = StateStopped
		if kv["ActiveState"] == "failed" {
			out.Detail = "the unit is in a failed state"
		}
	}
	if pid, err := strconv.Atoi(kv["MainPID"]); err == nil && pid > 0 {
		out.PID = pid
	}
	out.StartType = kv["UnitFileState"] // "enabled" means it comes back after a reboot

	// Restart=always plus a DISABLED start limiter is what "never gives up"
	// means here. Restart=always with systemd's default limiter still stops
	// after 5 starts in 10 seconds, which is the wrong polarity for an alarm
	// watchdog -- so both are checked before claiming crash recovery.
	noLimit := kv["StartLimitIntervalUSec"] == "0" ||
		strings.EqualFold(kv["StartLimitIntervalUSec"], "infinity")
	out.RecoversFromCrash = kv["Restart"] == "always" && noLimit
	if kv["Restart"] == "always" && !noLimit {
		out.Detail = strings.TrimSpace(out.Detail +
			" restarts on failure, but the start limiter can still stop it giving up")
	}
	return out, nil
}

// RunAsService is a no-op on Linux: systemd runs the process directly with no
// handshake, so `run` is the whole integration. Always returns false, meaning
// "carry on running normally".
func RunAsService(func(context.Context) error) (bool, error) { return false, nil }

// Elevate is not available on Linux; there is no UAC equivalent to prompt
// with, and re-execing under sudo from a daemon would be a worse idea than
// telling the operator to use it themselves.
// EscapeArg is a no-op off Windows: nothing here builds a command line as
// a single string.
func EscapeArg(s string) string { return s }

func Elevate(string) error {
	return fmt.Errorf("%w: re-run with sudo", ErrNeedsPrivilege)
}
