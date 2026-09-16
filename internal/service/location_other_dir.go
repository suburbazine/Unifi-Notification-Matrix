//go:build !windows

package service

// DefaultInstallPath is where the service binary belongs on Linux.
//
// /usr/local/bin is root-owned and not writable by the unprivileged account
// the daemon runs as. That is deliberate and has a visible consequence: the
// in-app updater reports that it cannot replace the binary, which is true and
// is better than a service account able to rewrite its own executable.
func DefaultInstallPath() string { return "/usr/local/bin/notifymatrix" }

func suggestedDir() string { return "/usr/local/bin" }
