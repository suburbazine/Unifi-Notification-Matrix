package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// RUNNING ON THE THING IT WATCHES.
//
// A UniFi gateway -- UCG, UXG, UDM, UDR, EFG -- is a Debian userland with
// systemd running natively, on arm64, with memory to spare. So this product
// runs there, and some operators have no other box to put it on.
//
// # It is the wrong place, and the install says so
//
// This product exists to notice when UniFi equipment stops reporting. Hosted
// on the gateway, it shares fate with the thing it is watching: when that box
// reboots, wedges, or loses power, the daemon whose job is to raise the alarm
// goes with it, and the most important alarm it has -- "the site went quiet"
// -- is the one it structurally cannot send.
//
// That is not a reason to refuse the install. It is a reason to say it every
// single time the daemon starts, rather than once in a document. See
// CoLocationWarning.
//
// The honest fix is a second pair of eyes somewhere else: a peer paired over
// Xtremission Link at another site, or an outbound heartbeat to something
// off-premises that alarms on SILENCE rather than on a message. Either one
// covers the case this deployment cannot.
//
// # Why /data and nothing else
//
// On UniFi OS the root filesystem is an overlay whose writable upper layer IS
// the persistent /data partition. A file written anywhere on the root
// filesystem physically lands on persistent storage, which is why a systemd
// unit in /etc/systemd/system survives a firmware upgrade -- and it is exactly
// how the community's udm-boot service survives one too.
//
// The state directory is still pinned to /data rather than left at
// /var/lib/notifymatrix, and deliberately so. Relying on the overlay to carry
// /var/lib means relying on an implementation detail of somebody else's
// firmware to keep the incident history; /data is the partition Ubiquiti
// documents as persistent and the one every other on-box tool uses. A factory
// reset clears it, like everything else.

// UniFiOSDataDir is where a gateway install keeps its state.
//
// Fixed, and not derived from the default data directory. See the package
// comment: this is the path the platform guarantees.
const UniFiOSDataDir = "/data/" + Name

// deviceInfoTool is the model/firmware helper Ubiquiti ships on every current
// UniFi OS gateway. Its presence is what identifies the platform: it is
// specific to these devices, it is not something a general Debian host has,
// and the community's own on-boot installer depends on it for the same reason.
const deviceInfoTool = "ubnt-device-info"

// MinAvailableMB is the headroom an install requires.
//
// Matched to MemoryHighMB below: refusing to install without at least as much
// free memory as the fence allows means the fence is a backstop against a
// fault rather than something the daemon runs into on an ordinary day.
//
// The steady state is far under this -- a Go binary holding a small SQLite
// store and a few HTTP listeners -- but a gateway is a shared box and the
// routing and IPS paths on it matter more than this product does.
const MinAvailableMB = 256

// MemoryHighMB is the soft limit: past it the kernel throttles and reclaims.
const MemoryHighMB = 256

// MemoryMaxMB is the hard limit, and the daemon is killed at it.
//
// Twice the soft limit, because the failure modes are not symmetric. Being
// throttled is survivable and self-correcting; being OOM-killed stops the
// alerting, and although Restart=always brings it back, a restart loop on the
// box that routes the site is the outcome worth spending headroom to avoid.
const MemoryMaxMB = 512

// The two signals, injected rather than called directly.
//
// Not for neatness: a platform check that nothing can exercise is a platform
// check nobody can be sure about. Both probes fail on a developer machine, so
// without this the only reachable case is "neither" -- and a version requiring
// just ONE of them would pass every test while installing an appliance unit on
// an ordinary Linux host that happened to have a /data directory.
var (
	hasDeviceInfoTool = func() bool {
		_, err := exec.LookPath(deviceInfoTool)
		return err == nil
	}
	hasDataPartition = func() bool {
		info, err := os.Stat("/data")
		return err == nil && info.IsDir()
	}
)

// OnUniFiOS reports whether this is a UniFi OS gateway.
//
// BOTH signals, because acting on one would be a guess in a direction that
// costs something. A general Debian host can have a /data directory for any
// reason, and installing the appliance unit there would give it a memory fence
// it never asked for and no TPM access it may well have. A UniFi device
// without /data is not one this can install to at all.
func OnUniFiOS() bool {
	return hasDeviceInfoTool() && hasDataPartition()
}

// UniFiOSModel returns what the device calls itself, for diagnostics.
//
// Best effort and never load-bearing: the install gates on MEMORY, not on
// model. A gateway released after this build has to work without a code
// change, and a list of known models is a list that goes stale.
func UniFiOSModel() string {
	out, err := exec.Command(deviceInfoTool, "model").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// AvailableMB reports MemAvailable from /proc/meminfo.
//
// MemAvailable rather than MemFree: free memory on a router is mostly page
// cache and reporting it as unavailable would refuse installs on boxes with
// plenty of room.
func AvailableMB() (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("service: reading available memory: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "MemAvailable:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			break
		}
		kb, err := strconv.Atoi(fields[0])
		if err != nil {
			break
		}
		return kb / 1024, nil
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("service: reading available memory: %w", err)
	}
	return 0, fmt.Errorf("service: /proc/meminfo has no MemAvailable line")
}

// CheckHeadroom refuses an install that would leave the gateway short.
//
// Reported as a refusal with a number in it rather than a warning, because the
// thing being protected is not this product: it is the routing and inspection
// running on the same box. An alerting daemon that degrades the network it
// watches has made the site worse.
//
// A memory reading that cannot be taken is NOT a refusal. An unknown is not a
// failure, and refusing on one would block an install on a gateway that has
// ample room because its /proc layout differs from the one expected.
func CheckHeadroom() (available int, warning string, err error) {
	available, err = AvailableMB()
	if err != nil {
		return 0, "could not read available memory, so the headroom check was skipped", nil
	}
	if available < MinAvailableMB {
		return available, "", fmt.Errorf(
			"only %d MB of memory is available and this needs %d MB of headroom "+
				"so it stays clear of routing and inspection on this gateway. "+
				"Free some up -- removing an unused UniFi application is the "+
				"usual way -- or install on a separate machine, which is the "+
				"better answer anyway: see the note about running on the device "+
				"you are watching",
			available, MinAvailableMB)
	}
	return available, "", nil
}

// CoLocationWarning is printed at EVERY start on a gateway install.
//
// Every start, not just at install. Install output scrolls away and is read
// once, by somebody who has already decided; this is the sentence that matters
// at three in the morning, and it belongs where the other startup warnings
// are.
//
// It is also not a scold. The deployment is legitimate and sometimes it is the
// only hardware there is. What it must never be is mistaken for equivalent.
func CoLocationWarning(model string) string {
	where := "this UniFi gateway"
	if model != "" {
		where = "this " + model
	}
	return "this daemon is running ON " + where + ", so it shares fate with " +
		"the equipment it watches: if this device reboots, wedges or loses " +
		"power, the alarm about that will not be sent by anything. Pair a peer " +
		"at another site, or point an off-site heartbeat at this installation, " +
		"so something outside this box notices when it goes quiet"
}
