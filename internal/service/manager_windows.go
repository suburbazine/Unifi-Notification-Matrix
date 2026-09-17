//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func defaultDataDir() string {
	// ProgramData, not a user profile: the service runs as LocalSystem and the
	// operator configures it from a browser session running as themselves.
	// They must reach the same directory, for the same reason the DPAPI scope
	// is machine-wide (ARCHITECTURE.md §6).
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "NotifyMatrix")
	}
	return `C:\ProgramData\NotifyMatrix`
}

// New returns the Windows service manager.
func New() Manager { return winManager{} }

type winManager struct{}

func (winManager) UnitText(o InstallOptions) (string, error) {
	// Windows has no unit file; describe what would be configured, so the CLI
	// can show it and `install` holds no surprises.
	exe := o.ExePath
	if exe == "" {
		exe, _ = os.Executable()
	}
	s := fmt.Sprintf(`Windows service configuration

  Name           %s
  Display name   %s
  Binary         %s run --data-dir %s
  Account        LocalSystem
  Start type     Automatic (starts at boot, survives logout)

Recovery actions (these are what restart it after a CRASH; automatic start
alone does NOT cover that):
`, Name, DisplayName, exe, o.DataDir)
	for i, d := range RestartDelays {
		label := fmt.Sprintf("failure %d", i+1)
		if i == len(RestartDelays)-1 {
			label = "subsequent failures"
		}
		s += fmt.Sprintf("  %-20s restart after %s\n", label, d)
	}
	s += fmt.Sprintf("  %-20s %s\n", "reset failure count", FailureResetPeriod)
	s += "  also applies to non-crash failures (a non-zero exit code)\n"
	return s, nil
}

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func withMgr(fn func(*mgr.Mgr) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connecting to the service manager: %w", err)
	}
	defer m.Disconnect()
	return fn(m)
}

func (w winManager) Install(o InstallOptions) error {
	if !elevated() {
		return ErrNeedsPrivilege
	}
	exe := o.ExePath
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return fmt.Errorf("service: locating this executable: %w", err)
		}
	}
	if o.DataDir == "" {
		o.DataDir = defaultDataDir()
	}
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return fmt.Errorf("service: creating %s: %w", o.DataDir, err)
	}

	return withMgr(func(m *mgr.Mgr) error {
		if s, err := m.OpenService(Name); err == nil {
			s.Close()
			return fmt.Errorf("service: %q is already installed", Name)
		}
		s, err := m.CreateService(Name, exe, mgr.Config{
			DisplayName: DisplayName,
			Description: Description,
			StartType:   mgr.StartAutomatic,
			// LocalSystem by default. Deliberate: it shares the machine-scope
			// DPAPI config with the operator's browser session, so a key
			// entered in the UI is readable by the service.
		}, "run", "--data-dir", o.DataDir)
		if err != nil {
			return fmt.Errorf("service: creating %q: %w", Name, err)
		}
		defer s.Close()

		// THE PART THAT IS USUALLY MISSED.
		//
		// StartType: Automatic covers reboot and logout. It does NOT restart a
		// service that crashed -- the SCM leaves it stopped unless failure
		// actions are set explicitly. Prior in-house work installs services
		// correctly and never sets these, so a crash at 2am is silent until
		// somebody notices.
		actions := make([]mgr.RecoveryAction, 0, len(RestartDelays))
		for _, d := range RestartDelays {
			actions = append(actions, mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: d})
		}
		if err := s.SetRecoveryActions(actions, uint32(FailureResetPeriod/time.Second)); err != nil {
			// Roll back rather than leave a service installed that looks fine
			// and will not come back from a crash.
			_ = s.Delete()
			return fmt.Errorf("service: setting recovery actions (the service was "+
				"removed rather than left without them): %w", err)
		}

		// Recovery actions default to firing only on a CRASH. A daemon that
		// exits non-zero because its config is unreadable has failed just as
		// completely, and must also be retried -- the config may be being
		// fixed right now.
		if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
			_ = s.Delete()
			return fmt.Errorf("service: enabling recovery on non-crash failures "+
				"(the service was removed): %w", err)
		}

		return s.Start()
	})
}

func (w winManager) Uninstall() error {
	if !elevated() {
		return ErrNeedsPrivilege
	}
	return withMgr(func(m *mgr.Mgr) error {
		s, err := m.OpenService(Name)
		if err != nil {
			return ErrNotInstalled
		}
		defer s.Close()
		// Best effort: Delete marks it regardless, and a service that will not
		// stop must still be removable.
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if err := s.Delete(); err != nil {
			return err
		}
		removeEventLogSource()
		return nil
	})
}

func (w winManager) Start() error {
	if !elevated() {
		return ErrNeedsPrivilege
	}
	return withMgr(func(m *mgr.Mgr) error {
		s, err := m.OpenService(Name)
		if err != nil {
			return ErrNotInstalled
		}
		defer s.Close()
		return s.Start()
	})
}

func (w winManager) Stop() error {
	if !elevated() {
		return ErrNeedsPrivilege
	}
	return withMgr(func(m *mgr.Mgr) error {
		s, err := m.OpenService(Name)
		if err != nil {
			return ErrNotInstalled
		}
		defer s.Close()
		_, err = s.Control(svc.Stop)
		return err
	})
}

// withReadOnlyMgr opens the service control manager for QUERYING only.
//
// mgr.Connect() asks for SC_MANAGER_ALL_ACCESS, which an unelevated process
// does not get -- so using it for Status made `status` and `selfcheck` fail
// with "Access is denied" for any operator who had not opened an admin prompt.
// That is precisely backwards: diagnostics are what somebody reaches for when
// things are wrong, and demanding elevation to ANSWER "is it running" turns a
// five-second check into a detour.
//
// Querying needs only SC_MANAGER_CONNECT, and reading a service's config and
// state needs only SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS. Install, start
// and stop still require elevation, as they should.
func withReadOnlyMgr(fn func(*mgr.Mgr) error) error {
	h, err := windows.OpenSCManager(nil, nil,
		windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return fmt.Errorf("service: connecting to the service manager: %w", err)
	}
	m := &mgr.Mgr{Handle: h}
	defer windows.CloseServiceHandle(h)
	return fn(m)
}

// openForQuery opens one service with read-only rights.
func openForQuery(m *mgr.Mgr, name string) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, p,
		windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func (w winManager) Status() (Status, error) {
	var out Status
	err := withReadOnlyMgr(func(m *mgr.Mgr) error {
		s, err := openForQuery(m, Name)
		if err != nil {
			out = Status{State: StateNotInstalled}
			return nil
		}
		defer s.Close()

		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("service: querying %q: %w", Name, err)
		}
		out.PID = int(st.ProcessId)
		switch st.State {
		case svc.Running:
			out.State = StateRunning
		case svc.Stopped:
			out.State = StateStopped
			out.PID = 0
		default:
			out.State = StateUnknown
			out.Detail = fmt.Sprintf("service state %d", st.State)
		}

		if cfg, err := s.Config(); err == nil {
			switch cfg.StartType {
			case mgr.StartAutomatic:
				out.StartType = "automatic"
			case mgr.StartManual:
				out.StartType = "manual"
			case mgr.StartDisabled:
				out.StartType = "disabled"
			default:
				out.StartType = fmt.Sprintf("%d", cfg.StartType)
			}
		}

		// Report crash recovery as its own fact. An installed, automatic,
		// running service with no recovery actions looks perfectly healthy and
		// will not come back from a panic.
		if ra, err := s.RecoveryActions(); err == nil {
			for _, a := range ra {
				if a.Type == mgr.ServiceRestart {
					out.RecoversFromCrash = true
					break
				}
			}
		}
		return nil
	})
	return out, err
}

// RunAsService runs fn under the SCM when this process was started by it.
//
// Returns false when running interactively, which is what lets one binary be
// both the service and the CLI.
func RunAsService(fn func(context.Context) error) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, nil
	}
	h := &handler{run: fn}
	if err := svc.Run(Name, h); err != nil {
		return true, fmt.Errorf("service: running under the SCM: %w", err)
	}
	reportStopToEventLog(h.err)
	return true, h.err
}

type handler struct {
	run func(context.Context) error
	err error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.err = h.run(ctx)
	}()

	// AcceptShutdown as well as AcceptStop: without it the daemon is killed
	// outright on a reboot rather than being asked to stop, and every clean
	// shutdown would look like a crash to the run marker.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(25 * time.Second):
					// Report stopped anyway. The SCM will terminate us
					// shortly; saying so is better than being killed while
					// still claiming to be running.
				}
				return false, 0
			}
		case <-done:
			// The daemon exited on its own. Reporting a non-zero exit code is
			// what makes the SCM apply the recovery actions set at install.
			status <- svc.Status{State: svc.StopPending}
			if h.err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}

// Elevate re-runs this executable with the same arguments through UAC.
//
// The alternative is an access-denied message the operator has to interpret,
// on a product whose install path must work for somebody who has never opened
// a terminal.
// EscapeArg quotes one command-line argument the way Windows parses them.
//
// The elevation paths built their command line with --data-dir "%s", which is
// correct right up until the path ends in a backslash -- and PowerShell tab
// completion produces exactly that. A path like D:\nm\ became "D:\nm\", where
// the trailing \" is an ESCAPED QUOTE rather than a closing one, so the
// elevated process received an unterminated argument and used the wrong data
// directory. In a separate elevated window, where the operator could not see
// it happen.
func EscapeArg(s string) string { return windows.EscapeArg(s) }

func Elevate(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)
	argPtr, _ := windows.UTF16PtrFromString(args)
	if err := windows.ShellExecute(0, verb, exePtr, argPtr, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("service: elevation was declined or failed: %w", err)
	}
	return nil
}

var _ = errors.Is
