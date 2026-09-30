//go:build !windows

package firewall

// System is the firewall of the machine this runs on. There is no Windows
// Firewall here, and the page says nothing about one.
func System(program string) Firewall {
	return Firewall{Program: program}
}
