//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// detachChild puts the helper in its own process group with no console.
//
// CREATE_NEW_PROCESS_GROUP so a Ctrl-C aimed at the daemon does not also kill
// the thing restarting it, and CREATE_NO_WINDOW so a console does not flash up
// on the desktop of whoever happens to be logged in -- a service restarting
// itself should be invisible, not a window nobody can explain.
func detachChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x08000000, // CREATE_NO_WINDOW
	}
}
