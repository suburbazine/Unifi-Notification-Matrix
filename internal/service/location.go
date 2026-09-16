package service

import (
	"os"
	"path/filepath"
	"strings"
)

// LocationWarning reports why installing the service from this path is a bad
// idea, or "" when there is nothing to say.
//
// The service runs as LocalSystem on Windows and as a dedicated account on
// Linux. Its binary therefore needs to live somewhere that ordinary, UNelevated
// processes cannot write -- because anybody who can replace that file chooses
// what runs as the service account the next time it starts.
//
// This matters most precisely where it is least obvious. The natural thing to
// do with a downloaded program is run it from Downloads, and `install`
// registers whatever path it was run from, for ever. Downloads is inside the
// operator's own profile, so a process running as them -- with no
// administrator rights and no prompt -- can overwrite the binary and get
// LocalSystem on the next restart.
//
// Note what that route bypasses: the updater checks the Authenticode publisher
// of anything it installs, and none of that applies to a file somebody simply
// overwrites. A signature check on one path is worth little while another path
// is open.
//
// Deliberately a warning and not a refusal. Running from a temporary directory
// to try the thing out is legitimate, and a security tool that will not let
// somebody evaluate it is a security tool nobody evaluates.
func LocationWarning(exe string) string {
	p := strings.ToLower(filepath.Clean(exe))
	if p == "" {
		return ""
	}

	for _, bad := range userWritableRoots() {
		if bad == "" {
			continue
		}
		b := strings.ToLower(filepath.Clean(bad))
		if b == string(filepath.Separator) || len(b) < 4 {
			continue
		}
		if p == b || strings.HasPrefix(p, b+string(filepath.Separator)) {
			return "the service would run from " + filepath.Dir(exe) + ", which is " +
				"inside a user profile or a temporary directory. Anything running as " +
				"that user can replace this file WITHOUT administrator rights, and " +
				"whatever replaces it runs as the service account the next time the " +
				"service starts. Copy it somewhere only administrators can write -- " +
				suggestedDir() + " -- and install it from there."
		}
	}
	return ""
}

// userWritableRoots are the places a downloaded program actually ends up.
//
// Not an ACL audit: it names the locations that are user-writable by
// construction, rather than claiming to have checked the permissions on this
// particular machine. A path outside all of them may still be writable by
// somebody it should not be, and this says nothing about that -- which is why
// the message describes WHERE the file is rather than asserting who can write
// it.
func userWritableRoots() []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, home)
	}
	out = append(out, os.TempDir())
	for _, env := range []string{"TEMP", "TMP", "TMPDIR"} {
		if v := os.Getenv(env); v != "" {
			out = append(out, v)
		}
	}
	return out
}
