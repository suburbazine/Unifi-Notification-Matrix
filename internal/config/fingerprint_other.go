//go:build !windows && !linux

package config

// platformMachineID has no implementation on platforms that are not shipping
// targets; machineID falls back to the hostname.
func platformMachineID() string { return "" }
