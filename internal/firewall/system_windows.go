package firewall

// System is the firewall of the machine this runs on, for program.
func System(program string) Firewall {
	return Firewall{Supported: true, Program: program, Run: PowerShell}
}
