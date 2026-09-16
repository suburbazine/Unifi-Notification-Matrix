//go:build !windows

package config

import "os"

// restrictToAdmins narrows the file to its owner.
//
// The daemon runs as its own unprivileged account, so owner-only is exactly
// the right answer here: root can read it, the service can read it, and no
// other account on the machine can.
func restrictToAdmins(path string) error { return os.Chmod(path, 0o600) }
