package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// fingerprintKey salts the host hash.
//
// Not a secret and not doing security work. It exists so the value in a config
// file is obviously application-specific and is not the raw machine id — the
// machine id is a stable system identifier and a config file may be pasted
// into a support ticket. The hash answers "same machine?" and nothing else.
var fingerprintKey = []byte("notifymatrix/config/host-fingerprint/v1")

// HostFingerprint identifies this machine, stably across reboots.
//
// Returns "" when no stable identifier can be found, which is treated
// throughout as "cannot tell" rather than as a mismatch. A false "this config
// is from another machine" would send an operator re-entering credentials that
// were fine.
func HostFingerprint() string {
	id := machineID()
	if id == "" {
		return ""
	}
	m := hmac.New(sha256.New, fingerprintKey)
	m.Write([]byte(id))
	// Truncated: this is a comparison token in a human-readable file, not a
	// cryptographic commitment, and a 64-character hex string in a config file
	// invites somebody to think it is a key.
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// machineID reads the platform's stable host identifier.
func machineID() string {
	if id := platformMachineID(); id != "" {
		return id
	}
	// Hostname is a weak fallback: it can be changed, and two fresh VMs from
	// one image can share it. Weak is still better than nothing here, because
	// the consequence of a wrong answer is a diagnostic hint, never a
	// security decision.
	if h, err := os.Hostname(); err == nil {
		return "hostname:" + strings.TrimSpace(h)
	}
	return ""
}

// MatchesThisHost reports whether the config was written on this machine.
//
// A config with no recorded fingerprint, or a machine that cannot identify
// itself, returns true: "cannot tell" must not be reported as "foreign".
func (s SecretsMeta) MatchesThisHost() bool {
	if s.HostFingerprint == "" {
		return true
	}
	here := HostFingerprint()
	if here == "" {
		return true
	}
	return s.HostFingerprint == here
}
