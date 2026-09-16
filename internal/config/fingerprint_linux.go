//go:build linux

package config

import (
	"os"
	"strings"
)

// platformMachineID reads systemd's machine id.
//
// /etc/machine-id is generated once at install and is stable across reboots.
// /var/lib/dbus/machine-id is the older location, still present on some
// systems and symlinked on most.
func platformMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return "machine-id:" + id
			}
		}
	}
	return ""
}
