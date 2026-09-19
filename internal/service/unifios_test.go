package service

import (
	"strings"
	"testing"
)

func applianceUnit(t *testing.T) string {
	t.Helper()
	u, err := RenderUnit(InstallOptions{
		ExePath:   "/data/notifymatrix/notifymatrix",
		DataDir:   UniFiOSDataDir,
		User:      "root",
		Appliance: true,
	})
	if err != nil {
		t.Fatalf("rendering the appliance unit: %v", err)
	}
	return u
}

// directives is the unit with its comments removed.
//
// ASSERT ON WHAT SYSTEMD ACTS ON. These units carry more explanation than
// configuration, and a raw substring search reads those comments as settings:
// the first version of the tss check below failed against the line "# No
// SupplementaryGroups=tss here", which is the comment saying the directive is
// deliberately absent.
//
// It guards the opposite mistake too. A directive commented out during a
// change would still satisfy a naive Contains, so a test that cannot tell the
// two apart passes either way and means nothing.
func directives(unit string) string {
	var kept []string
	for _, line := range strings.Split(unit, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		kept = append(kept, t)
	}
	return strings.Join(kept, "\n")
}

// And the helper is itself checked, because a comment-stripper that strips
// everything would make every assertion below vacuously pass.
func TestTheDirectiveFilterKeepsSettingsAndDropsProse(t *testing.T) {
	got := directives("# a comment\n\nRestart=always\n  # indented comment\nUser=root\n")
	if got != "Restart=always\nUser=root" {
		t.Fatalf("directives() = %q", got)
	}
	if directives(applianceUnit(t)) == "" {
		t.Fatal("the filter removed the entire unit, so nothing below is " +
			"actually being asserted on")
	}
}

// THE TWO LINES THAT WOULD STOP IT STARTING.
//
// StateDirectory is always relative to /var/lib, so it cannot express /data --
// and SupplementaryGroups naming a group that does not exist FAILS the unit at
// start, which is what tss would do on a gateway that has no TPM. Both are
// right everywhere else and fatal here, which is the whole reason the
// appliance renders its own unit.
func TestTheApplianceUnitOmitsWhatWouldFailOnAGateway(t *testing.T) {
	u := directives(applianceUnit(t))

	if strings.Contains(u, "SupplementaryGroups=tss") {
		t.Error("the unit asks for the tss group; there is no TPM on these " +
			"devices and systemd fails a unit naming a group that does not exist, " +
			"so the daemon would never start")
	}
	if strings.Contains(u, "StateDirectory=") {
		t.Error("the unit uses StateDirectory, which is relative to /var/lib " +
			"and cannot name /data")
	}
	if !strings.Contains(u, "ReadWritePaths="+UniFiOSDataDir) {
		t.Errorf("nothing grants write access to %s, so ProtectSystem=strict "+
			"leaves the daemon unable to write its own store -- which fails at "+
			"the first incident, not at start:\n%s", UniFiOSDataDir, u)
	}
}

// THE FENCE IS THERE, and it is a fence rather than a ceiling the daemon lives
// against.
func TestTheApplianceUnitFencesMemoryOnABoxThatAlsoRoutes(t *testing.T) {
	u := directives(applianceUnit(t))

	for _, want := range []string{"MemoryHigh=", "MemoryMax="} {
		if !strings.Contains(u, want) {
			t.Errorf("no %s in the unit; a fault in this process would take "+
				"capacity from routing and inspection on the same hardware", want)
		}
	}
	if MemoryMaxMB <= MemoryHighMB {
		t.Errorf("MemoryMax %d is not above MemoryHigh %d; being throttled is "+
			"survivable and being killed stops the alerting, so the hard limit "+
			"has to sit well clear of the soft one", MemoryMaxMB, MemoryHighMB)
	}
	// The install refuses below MinAvailableMB, so a fence tighter than that
	// would be one the daemon runs into on an ordinary day rather than a
	// backstop against a fault.
	if MinAvailableMB < MemoryHighMB {
		t.Errorf("the install allows %d MB of headroom for a %d MB soft limit",
			MinAvailableMB, MemoryHighMB)
	}
}

// AND EVERYTHING THAT MAKES THIS PRODUCT WORK SURVIVES THE VARIANT.
//
// The appliance unit is a correction for one platform, not a reduced build.
// Restart=always with the rate limiter disabled is the pair of lines that
// decides whether a crash at 4am is recovered from, and a variant that quietly
// dropped them would be worse than no appliance support at all.
func TestTheApplianceUnitKeepsWhatDecidesWhetherItRecovers(t *testing.T) {
	u := directives(applianceUnit(t))
	for _, want := range []string{
		"StartLimitIntervalSec=0",
		"Restart=always",
		"ProtectSystem=strict",
		"NoNewPrivileges=true",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("the appliance unit dropped %q", want)
		}
	}
}

// The ordinary Linux unit is untouched by any of this.
func TestTheOrdinaryLinuxUnitIsUnchanged(t *testing.T) {
	u, err := RenderUnit(InstallOptions{
		ExePath: "/usr/local/bin/notifymatrix",
		DataDir: "/var/lib/notifymatrix",
		// A literal rather than DefaultUser: that constant is defined in the
		// linux-only file and this test renders the unit on every platform,
		// which is the point -- the template is built and checked from a
		// developer machine.
		User: "notifymatrix",
	})
	if err != nil {
		t.Fatal(err)
	}
	u = directives(u)
	if !strings.Contains(u, "StateDirectory=notifymatrix") {
		t.Error("the normal unit lost its StateDirectory")
	}
	if !strings.Contains(u, "SupplementaryGroups=tss") {
		t.Error("the normal unit lost TPM access, which silently demotes the " +
			"secret store to the key-file tier on every machine with a TPM")
	}
	if strings.Contains(u, "MemoryHigh=") || strings.Contains(u, "ReadWritePaths=") {
		t.Error("appliance directives leaked into the ordinary unit")
	}
}

// A DATA DIRECTORY THAT IS NOT ABSOLUTE IS STILL REFUSED.
//
// ReadWritePaths lifts the /var/lib requirement; it does not lift the need for
// a real path. This is the one hole in an otherwise read-only filesystem.
func TestTheApplianceUnitStillRefusesANonsenseDataDirectory(t *testing.T) {
	for _, bad := range []string{"", "relative/path", "/data/../etc", ".."} {
		_, err := RenderUnit(InstallOptions{
			ExePath: "/data/notifymatrix/notifymatrix", DataDir: bad, Appliance: true,
		})
		if err == nil {
			t.Errorf("accepted data dir %q", bad)
		}
	}
}

// THE PLATFORM IS DETECTED, NEVER GUESSED.
//
// Every combination, because the dangerous one is not "fails to detect a
// gateway" -- it is detecting one where there is none. An ordinary Linux host
// with a /data directory would get the appliance unit: a memory fence it never
// asked for, and no TPM access it may well have, silently demoting its secret
// store to the key-file tier.
func TestBothSignalsAreRequiredToCallSomethingAGateway(t *testing.T) {
	realTool, realData := hasDeviceInfoTool, hasDataPartition
	t.Cleanup(func() { hasDeviceInfoTool, hasDataPartition = realTool, realData })

	for _, c := range []struct {
		tool, data, want bool
		what             string
	}{
		{true, true, true, "a UniFi gateway"},
		{true, false, false, "the tool but no /data"},
		{false, true, false, "a Linux host that happens to have /data"},
		{false, false, false, "an ordinary machine"},
	} {
		hasDeviceInfoTool = func() bool { return c.tool }
		hasDataPartition = func() bool { return c.data }
		if got := OnUniFiOS(); got != c.want {
			t.Errorf("%s: OnUniFiOS() = %v, want %v", c.what, got, c.want)
		}
	}
}

// And on the machine actually running the tests, neither signal is present.
func TestTheGatewayPlatformIsNotDetectedWhereItIsNot(t *testing.T) {
	if OnUniFiOS() {
		t.Error("this test machine was identified as a UniFi gateway, which " +
			"means the detection is matching something it should not")
	}
}

// A MEMORY READING THAT CANNOT BE TAKEN IS NOT A REFUSAL.
//
// An unknown is not a failure. Refusing an install because /proc/meminfo looks
// different from the expectation would block a gateway with ample room, and
// the check exists to protect the box rather than to be strict.
func TestAnUnreadableMemoryFigureDoesNotRefuseTheInstall(t *testing.T) {
	// On any machine without a Linux /proc this takes the unreadable path,
	// which is the one being asserted on.
	available, warning, err := CheckHeadroom()
	if err != nil && available >= MinAvailableMB {
		t.Errorf("refused with %d MB available, which is above the %d MB floor",
			available, MinAvailableMB)
	}
	if err == nil && available == 0 && warning == "" {
		t.Error("the headroom check neither reported a figure nor said it " +
			"could not take one, so an operator is told nothing either way")
	}
}

// The warning has to name the thing it is about and say what to do, or it is
// a sentence somebody scrolls past.
func TestTheCoLocationWarningSaysWhatToDoAboutIt(t *testing.T) {
	w := CoLocationWarning("UniFi Cloud Gateway Fiber")
	if !strings.Contains(w, "UniFi Cloud Gateway Fiber") {
		t.Error("the warning does not name the device")
	}
	for _, want := range []string{"shares fate", "peer", "heartbeat"} {
		if !strings.Contains(w, want) {
			t.Errorf("the warning does not mention %q, so it states a problem "+
				"without an answer", want)
		}
	}
	// With no model it still has to read as a sentence.
	if bare := CoLocationWarning(""); strings.Contains(bare, "this  ") {
		t.Errorf("an unknown model leaves a gap in the sentence: %q", bare)
	}
}
