package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/escalate"
)

// AN IANA ZONE HAS TO WORK ON A MACHINE WITH NO GO INSTALLED ON IT.
//
// Windows has no system time zone database. time.LoadLocation there falls back
// to zoneinfo.zip inside a Go INSTALLATION, and an operator running a release
// binary does not have one -- so every IANA name was refused, while "UTC" and
// "Local" worked, those two being the only names that resolve without the
// database at all. It was reported as the slash in "America/New_York" breaking
// the field, which is exactly what it looks like from the outside: every name
// with a slash in it is every name that is not one of those two.
//
// Quiet hours are validated at load, so the same missing database refuses the
// START of a daemon whose zone was written into config.yaml by hand. The site
// is then watched by nothing. Reproduced against the shipped v0.4.1 binary:
//
//	error: config: ...config.yaml is not usable:
//	quiet hours: unknown time zone: "America/New_York"
//
// The fix is the blank import of time/tzdata in main.go, and this is what
// stops that unused-looking line being tidied away.
//
// IN A CHILD PROCESS, which is not ceremony. The lookup order is: the
// platform's own directories (none, on Windows), then the copy embedded by
// time/tzdata, then $GOROOT/lib/time/zoneinfo.zip. Only the last of those can
// be taken away, and on go1.26 runtime.GOROOT() no longer re-reads the
// environment -- an os.Setenv inside the test is simply ignored, and the test
// then passes on a dev machine whether or not the import is there. That is the
// first version of this test, and it was worthless. The variable has to be set
// before the process starts, so the test starts one.
//
// WINDOWS ONLY: on Linux and macOS /usr/share/zoneinfo answers every one of
// these lookups with or without the embedded copy, so there the test could
// never go red. CI runs a Windows leg, which is where this bites.
func TestAnIANAZoneLoadsWithNoGoInstallationToFallBackOn(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only reproducible on Windows: a unix system database answers " +
			"these lookups with or without the embedded copy")
	}

	// The operator's machine: no Go, and no ZONEINFO pointing at a zip
	// somebody unpacked by hand.
	env := []string{"NOTIFYMATRIX_TZ_CHILD=1", "ZONEINFO="}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.EqualFold(k, "GOROOT") && !strings.EqualFold(k, "ZONEINFO") {
			env = append(env, kv)
		}
	}
	env = append(env, "GOROOT="+filepath.Join(t.TempDir(), "no-go-installed-here"))

	cmd := exec.Command(os.Args[0], "-test.run=TestZoneLookupsInsideThatChild", "-test.v")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("with no Go installation to fall back on, this binary cannot resolve "+
			"IANA time zones -- so quiet hours cannot be set from the interface and a "+
			"zone written into config.yaml refuses the daemon's start. Restore the "+
			"blank import of time/tzdata in main.go.\n\n%s", out)
	}
}

// TestZoneLookupsInsideThatChild is the body of the test above, run in a
// process started without a usable GOROOT. It is skipped when run directly.
func TestZoneLookupsInsideThatChild(t *testing.T) {
	if os.Getenv("NOTIFYMATRIX_TZ_CHILD") != "1" {
		t.Skip("started by TestAnIANAZoneLoadsWithNoGoInstallationToFallBackOn")
	}
	t.Logf("GOROOT at runtime: %s", runtime.GOROOT())

	for _, zone := range []string{
		"America/New_York", // the one in the field's own example text
		"Europe/London",
		"Australia/Sydney",
		"Asia/Tokyo",
	} {
		if _, err := time.LoadLocation(zone); err != nil {
			t.Errorf("time.LoadLocation(%q): %v", zone, err)
		}
		q := escalate.QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: zone}
		if err := q.Validate(); err != nil {
			t.Errorf("quiet hours in %s: %v", zone, err)
		}
	}

	// And the validator has not simply stopped checking: a name that is not a
	// zone must still be refused, or this would pass on a build where the
	// lookup had been abandoned altogether.
	bogus := escalate.QuietHours{Enabled: true, Start: "22:00", End: "07:00", Zone: "Mars/Olympus_Mons"}
	if err := bogus.Validate(); !errors.Is(err, escalate.ErrBadQuietZone) {
		t.Errorf("a zone that does not exist was accepted (%v); the check that catches "+
			"a typo has gone, and this test now proves nothing", err)
	}
}
