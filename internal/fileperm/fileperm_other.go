//go:build !windows

package fileperm

import "os"

// Restrict narrows the file to its owner.
//
// The daemon runs as its own unprivileged account, so owner-only is exactly
// the right answer here: root can read it, the service can read it, and no
// other account on the machine can.
func Restrict(path string) error { return os.Chmod(path, 0o600) }

// RestrictDir narrows a directory to its owner. 0700 is what MkdirAll is
// already asked for here; this makes the intent explicit and repairs a
// directory created before that was true.
func RestrictDir(path string) error { return os.Chmod(path, 0o700) }
