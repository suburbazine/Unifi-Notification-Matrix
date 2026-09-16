//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detachChild starts the helper in its own session, so it is not taken down
// with the process group systemd is stopping.
func detachChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
