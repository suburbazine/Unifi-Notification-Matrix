//go:build windows

package service

import (
	"golang.org/x/sys/windows/svc/eventlog"
)

// eventLogID is the one event ID this program writes. The EventCreate message
// file registered below accepts IDs 1 to 1000 and renders the text verbatim.
const eventLogID = 1

// reportStopToEventLog writes why the service stopped to the Application log.
//
// Under the service manager, stderr goes nowhere. Before this, a service that
// failed at startup left an operator with "Stopped" in services.msc and no
// account of why anywhere on the machine -- the audit record is only reachable
// through the interface, which runs inside the service that just stopped.
//
// The source is registered here rather than only at install, because the
// installs that most need this already exist. The service runs as LocalSystem,
// which may create it; "already registered" is the normal case and ignored.
// Best effort throughout: failing to report a failure must not change how the
// failure itself is handled.
func reportStopToEventLog(cause error) {
	if cause == nil {
		return
	}
	_ = eventlog.InstallAsEventCreate(Name, eventlog.Error|eventlog.Warning|eventlog.Info)
	l, err := eventlog.Open(Name)
	if err != nil {
		return
	}
	defer l.Close()
	_ = l.Error(eventLogID, "The NotifyMatrix service stopped: "+cause.Error()+
		"\r\n\r\nWhile it is stopped, alarms are not delivered. The service manager "+
		"retries it on the recovery schedule set at install. Once it is running "+
		"again, the same reason is shown in the interface's Activity log.")
}

// removeEventLogSource undoes the registration, best effort, on uninstall.
func removeEventLogSource() {
	_ = eventlog.Remove(Name)
}
