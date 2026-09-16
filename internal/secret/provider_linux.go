//go:build linux

package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	providers = []Provider{
		sdCredsProvider{},
		tpm2Provider{},
		ageKeyProvider{},
		plainProvider{},
	}
}

// Secret Service (libsecret / gnome-keyring / KWallet) is deliberately absent
// from this chain, and the reason is specific rather than a preference.
//
// go-keyring calls dbus.SessionBus(). For a systemd SYSTEM unit there is no
// $DBUS_SESSION_BUS_ADDRESS and no /run/user/<uid>/bus -- a system unit with
// User= gets no logind session -- so it falls through to exec'ing dbus-launch,
// which dies with "Cannot autolaunch D-Bus without X11 $DISPLAY".
//
// Worse: if a session bus IS manufactured, go-keyring's Unlock waits on an
// unbounded promptSignal with no timeout, so a locked login keyring makes the
// daemon hang forever instead of failing. secret-tool is the same libsecret
// client on the same bus and fails identically.
//
// Secret Service is the right answer for a desktop application with a
// logged-in user. It is the wrong one for a daemon, and the difference is easy
// to miss because the API is identical in both cases -- it simply never
// returns.
//
// That hazard is also why every exec below carries a context timeout.

// credName is the systemd-creds --name binding. Fixed for the application:
// decrypt refuses a blob whose name does not match, which stops a credential
// being replayed into a different consumer on the same host.
const credName = "notifymatrix"

// execTimeout bounds every helper invocation. A hung helper must fail the
// operation, never block the daemon -- see the Secret Service note above.
const execTimeout = 10 * time.Second

// ---------------------------------------------------------------------------
// Tier 1: systemd-creds
// ---------------------------------------------------------------------------

// sdCredsProvider shells out to systemd-creds. No cgo, no Go binding, no D-Bus.
//
// --with-key=auto is a genuine structural analogue of DPAPI machine scope:
// where a TPM exists it silently upgrades to host+tpm2 (stronger than anything
// Windows offers); where it does not, host-key-only matches DPAPI machine
// scope exactly, including its weakness -- both fall to a full disk image.
//
// --tpm2-pcrs defaults to EMPTY, which is what makes this usable unattended:
// credentials survive reboots and firmware or kernel updates with no re-seal,
// no prompt and no PIN.
type sdCredsProvider struct{}

func (sdCredsProvider) Prefix() string     { return PrefixSDCreds }
func (sdCredsProvider) Mechanism() string  { return "systemd-creds (host key, TPM2 where present)" }
func (sdCredsProvider) MachineBound() bool { return true }

// minSystemdVersion is the first release carrying systemd-creds.
//
// This is not a formality. Ubuntu 22.04 LTS ships systemd 249.11, so a large
// installed base lands below this line and falls to a lower tier. The fallback
// chain is the majority path, not decoration.
const minSystemdVersion = 250

// The probe spawns up to three helper processes, so its result is cached for
// the life of the process. Rescan clears it.
var (
	sdMu     sync.Mutex
	sdDone   bool
	sdOK     bool
	sdReason string
)

func (p sdCredsProvider) Available() (bool, string) {
	sdMu.Lock()
	defer sdMu.Unlock()
	if !sdDone {
		sdOK, sdReason = p.probe()
		sdDone = true
	}
	return sdOK, sdReason
}

func (sdCredsProvider) rescan() {
	sdMu.Lock()
	defer sdMu.Unlock()
	sdDone = false
}

func (sdCredsProvider) probe() (bool, string) {
	if _, err := exec.LookPath("systemd-creds"); err != nil {
		return false, "systemd-creds is not on PATH (needs systemd >= 250)"
	}

	// THE CONTAINER TRAP.
	//
	// Inside a container, --with-key=auto does not fail -- it succeeds
	// SILENTLY. The TPM2 path is refused because systemd detects the
	// container, but the host-key path only tests whether /var/lib/systemd is
	// on a temporary filesystem, and an overlay writable layer is not tmpfs.
	// So it happily creates credential.secret in the container's ephemeral
	// layer and emits a valid-looking blob with no error and no warning -- and
	// every secret becomes unreadable after the next container restart.
	//
	// Refusing here, rather than discovering it on the next restart, is the
	// entire reason this probe exists.
	if inContainer() {
		return false, "running in a container: systemd-creds would bind to an " +
			"ephemeral host key and silently lose every secret on restart"
	}

	v, err := systemdVersion()
	if err != nil {
		return false, "could not determine the systemd version: " + err.Error()
	}
	if v < minSystemdVersion {
		return false, fmt.Sprintf("systemd %d is too old for systemd-creds (needs >= %d)",
			v, minSystemdVersion)
	}

	// The host key is root-readable only. If we cannot read it and there is no
	// TPM to fall back on, encryption will fail at write time -- so report it
	// now, while a lower tier can still be chosen.
	if !canReadHostKey() && !hasTPM() {
		return false, "cannot read /var/lib/systemd/credential.secret (needs root) " +
			"and no TPM is present"
	}
	return true, ""
}

func inContainer() bool {
	// systemd's own detection, so this agrees with what systemd-creds itself
	// will conclude. Exit status 0 means "in a container".
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	if err := exec.CommandContext(ctx, "systemd-detect-virt", "--container", "--quiet").Run(); err == nil {
		return true
	}
	// Fall back to the usual markers when systemd-detect-virt is absent.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/run/systemd/container"); err == nil && len(bytes.TrimSpace(b)) > 0 {
		return true
	}
	return false
}

func systemdVersion() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemd-creds", "--version").Output()
	if err != nil {
		return 0, err
	}
	// First line looks like: "systemd 255 (255.4-1ubuntu8.4)"
	fields := strings.Fields(string(out))
	for _, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			return n, nil
		}
	}
	return 0, errors.New("no version number in systemd-creds --version output")
}

func canReadHostKey() bool {
	f, err := os.Open("/var/lib/systemd/credential.secret")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func hasTPM() bool {
	for _, p := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func (sdCredsProvider) Protect(plaintext []byte) ([]byte, error) {
	return runCreds("encrypt", plaintext, "--with-key=auto")
}

func (sdCredsProvider) Unprotect(blob []byte) ([]byte, error) {
	return runCreds("decrypt", blob)
}

func runCreds(verb string, in []byte, extra ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	args := append([]string{verb, "--name=" + credName}, extra...)
	args = append(args, "-", "-") // stdin -> stdout
	cmd := exec.CommandContext(ctx, "systemd-creds", args...)
	cmd.Stdin = bytes.NewReader(in)

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("systemd-creds %s timed out after %s", verb, execTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("systemd-creds %s: %s", verb, msg)
	}
	return stdout.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Tier 2: direct TPM2 sealing -- NOT YET IMPLEMENTED
// ---------------------------------------------------------------------------

// tpm2Provider will seal under the SRK with no PCR policy, via
// github.com/google/go-tpm (verified cgo-free; NOT go-tpm-tools, which is not).
//
// It is declared but unimplemented so that the prefix is reserved and the
// diagnostics report names it as a real tier rather than hiding the gap. Until
// it lands, systems without systemd-creds fall to the key-file tier, which
// works everywhere but is NOT machine-bound -- see ageKeyProvider.
//
// This tier is what rescues Ubuntu 22.04 (systemd 249), Alpine, and
// TPM-passthrough containers, so it is worth building before first release.
type tpm2Provider struct{}

func (tpm2Provider) Prefix() string     { return PrefixTPM2 }
func (tpm2Provider) Mechanism() string  { return "TPM2 sealed (direct)" }
func (tpm2Provider) MachineBound() bool { return true }

func (tpm2Provider) Available() (bool, string) {
	if !hasTPM() {
		return false, "no TPM device present"
	}
	return false, "not yet implemented in this build"
}

var errTPMUnimplemented = errors.New("direct TPM2 sealing is not implemented in this build")

func (tpm2Provider) Protect([]byte) ([]byte, error)   { return nil, errTPMUnimplemented }
func (tpm2Provider) Unprotect([]byte) ([]byte, error) { return nil, errTPMUnimplemented }
