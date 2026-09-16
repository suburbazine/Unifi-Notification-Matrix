//go:build windows

package service

import (
	"os"
	"path/filepath"
)

// InstallDirName is the folder a Windows install lives in.
const InstallDirName = "NotifyMatrix"

// DefaultInstallPath is where the service binary belongs on Windows.
//
// Under Program Files, because its ACL is the point: administrators and SYSTEM
// may write, everybody else may only read and execute. That is what makes
// replacing the binary an elevated act, and it is the difference between the
// updater's signature check being the way in and being one way in.
func DefaultInstallPath() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, InstallDirName, "notifymatrix.exe")
}

func suggestedDir() string { return filepath.Dir(DefaultInstallPath()) }
