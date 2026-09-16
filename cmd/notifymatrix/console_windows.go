//go:build windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NewLazySystemDLL, not NewLazyDLL: it pins the load to System32 rather than
// searching the directory the executable was started from. This binary is
// something people download and run out of Downloads, which is exactly the
// directory an attacker can drop a kernel32.dll into.
var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// ownsTheConsoleAlone reports whether this process is the only one attached to
// its console, which is what a double-click from Explorer looks like.
//
// Explorer creates a console for a console program and destroys it the instant
// the program exits. Everything printed vanishes in a flash, and the binary
// looks broken to somebody who has no reason to know it is a command-line
// tool. Started from a PowerShell or cmd window instead, the console is SHARED
// with that shell -- the process list has at least two entries -- and there is
// nothing to pause for, because the output stays on screen.
func ownsTheConsoleAlone() bool {
	// Ask whether anyone is actually there to press a key before deciding to
	// wait for one. GetConsoleMode fails when stdin is redirected or absent,
	// which covers the service (no console at all) and any scheduled task or
	// script that runs this unattended. Getting this wrong would hang an
	// automated invocation forever, so it is checked first.
	var mode uint32
	if err := windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode); err != nil {
		return false
	}

	// The count, not the pids. Four is room enough to distinguish "just us"
	// from "us and a shell" without caring who the others are; the call
	// returns the required size rather than failing if there are more.
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	return n == 1
}
