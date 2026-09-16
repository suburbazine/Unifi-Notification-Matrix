// Package service makes the daemon survive a logout, a crash and a reboot with
// nobody involved, and controllable without a terminal.
//
// A watchdog that stops when somebody logs out is not a watchdog. See
// ARCHITECTURE.md §9a for the reasoning; this package is that section made
// executable.
package service

import (
	"errors"
	"fmt"
	"time"
)

// Identity of the installed service. These strings reach the Windows service
// control manager and the systemd unit name, so changing one after a release
// orphans every existing installation.
const (
	Name        = "notifymatrix"
	DisplayName = "UniFi Notification Matrix"
	Description = "Escalates UniFi Protect, Access and Network alarms until a human acknowledges them."
)

// State is what the service manager reports.
type State string

const (
	StateRunning      State = "running"
	StateStopped      State = "stopped"
	StateNotInstalled State = "not installed"
	StateUnknown      State = "unknown"
)

// Status is a snapshot for the CLI and the diagnostics page.
type Status struct {
	State State
	PID   int

	// StartType says whether it comes back after a reboot. An installed
	// service that is not set to start automatically is the failure nobody
	// notices until the power cycles.
	StartType string

	// RecoversFromCrash reports whether the service manager will restart it
	// after an abnormal exit. Reported separately from StartType because they
	// are different mechanisms and only one of them is on by default --
	// installing a service with automatic start covers reboot and logout but
	// NOT a crash.
	RecoversFromCrash bool

	Detail string
}

// InstallOptions configures an installation.
type InstallOptions struct {
	// ExePath defaults to the running executable.
	ExePath string

	// DataDir is where the config, the incident store and the single-instance
	// lock live.
	DataDir string

	// User is the account the service runs as. Linux only; on Windows the
	// service runs as LocalSystem so it shares one machine-scope DPAPI config
	// with the operator's browser session (ARCHITECTURE.md §6).
	User string
}

// Manager installs and controls the platform's service.
type Manager interface {
	Install(InstallOptions) error
	Uninstall() error
	Start() error
	Stop() error
	Status() (Status, error)

	// UnitText renders what Install would write, without writing it. Lets the
	// operator read the unit before it is installed, and lets the CLI show it
	// when the install needs privileges they do not have.
	UnitText(InstallOptions) (string, error)
}

var (
	// ErrNotInstalled is returned by control verbs when the service is absent.
	ErrNotInstalled = errors.New("service is not installed")

	// ErrNeedsPrivilege means the operation requires administrator or root.
	ErrNeedsPrivilege = errors.New("this needs administrator privileges")

	// ErrUnsupported is returned on platforms with no service integration.
	ErrUnsupported = errors.New("service installation is not supported on this platform")
)

// Restart delays applied after an abnormal exit.
//
// These exist because installing a service with automatic start covers reboot
// and logout but does NOT restart it after a crash -- the Windows SCM leaves a
// crashed service stopped unless failure actions are set explicitly, and prior
// in-house work never set them. So a crash at 2am was silent until somebody
// noticed.
var RestartDelays = []time.Duration{
	5 * time.Second,
	30 * time.Second,
	60 * time.Second, // and every subsequent failure
}

// FailureResetPeriod is how long a service must run before its failure count
// resets.
//
// Deliberately long. A short reset period means a daemon that crashes once an
// hour looks healthy to the service manager forever, because each failure is
// counted as if it were the first. A day means a genuine crash loop is still
// recognisable as one.
const FailureResetPeriod = 24 * time.Hour

// String renders a status for the CLI.
func (s Status) String() string {
	out := string(s.State)
	if s.PID > 0 {
		out += fmt.Sprintf(" (pid %d)", s.PID)
	}
	if s.State != StateNotInstalled {
		out += fmt.Sprintf("; start=%s", s.StartType)
		if s.RecoversFromCrash {
			out += "; restarts after a crash"
		} else {
			out += "; WILL NOT restart after a crash"
		}
	}
	if s.Detail != "" {
		out += " -- " + s.Detail
	}
	return out
}
