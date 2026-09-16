//go:build !windows

package main

// Only Windows Explorer hands a console program a terminal and then takes it
// away again. A file manager on Linux either refuses to run a console program
// or opens a terminal the user closes themselves, so there is nothing to wait
// for and waiting would be an unwanted prompt on a machine nobody is sitting
// at.
func ownsTheConsoleAlone() bool { return false }
