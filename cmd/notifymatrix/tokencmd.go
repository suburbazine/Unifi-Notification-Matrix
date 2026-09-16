package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
)

// setupTokenCmd prints the one-time setup token.
//
// The token file is readable only by administrators and the account the daemon
// runs as, which is correct -- anybody holding it can claim the settings page
// of a fresh installation -- and which, on its own, was not enough.
//
// Windows filters an administrator's token: until a process elevates, its
// BUILTIN\Administrators membership is DENY-ONLY, so an ACE granting
// Administrators grants that process nothing. The daemon runs as LocalSystem,
// so the file ends up owned by SYSTEM with Administrators alongside, and an
// operator who is an administrator, who did everything right, gets "Access is
// denied" from Notepad with no indication that elevating would fix it.
//
// So this does the elevating. The permissions do not move.
func setupTokenCmd(dataDir string, interactive bool) int {
	path := config.SetupTokenPath(dataDir)

	body, err := os.ReadFile(path)
	switch {
	case err == nil:
		fmt.Print(string(body))
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Println()
		}
		return 0

	case errors.Is(err, fs.ErrNotExist):
		// The common reason by far, and worth saying rather than reporting a
		// missing file: the token is deleted the moment a password exists.
		fmt.Printf(`No setup token is waiting at %s.

That normally means a password is already set -- the token is deleted as soon
as one is, and it would not work any more in any case.

To replace the password:  %s
`, path, typedCommand("set-password"))
		return 1

	case errors.Is(err, fs.ErrPermission):
		return elevateForToken(path, dataDir, interactive)

	default:
		fmt.Fprintln(os.Stderr, "error: could not read", path+":", err)
		return 1
	}
}

// elevateForToken re-runs this command with administrator rights.
func elevateForToken(path, dataDir string, interactive bool) int {
	fmt.Printf(`%s exists, but reading it needs
administrator rights.

That is deliberate: anybody holding the token can claim the settings page of
this installation. Being in the Administrators group is not enough on its own
-- Windows withholds those rights from a process until it elevates, which is
why opening the file directly reports "access denied".

`, path)

	if runtime.GOOS != "windows" {
		fmt.Printf("Read it as root:  sudo cat %s\n", path)
		return 1
	}

	if interactive && !askYesNo(os.Stdout, bufio.NewReader(os.Stdin),
		"Open an elevated window and show it?") {
		fmt.Printf("\nTo do it yourself, from an administrator terminal:\n    %s\n",
			typedCommand("setup-token"))
		return 1
	}

	args := "setup-token"
	if dataDir != "" {
		args += fmt.Sprintf(` --data-dir "%s"`, dataDir)
	}
	if err := service.Elevate(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintf(os.Stderr, "       from an administrator terminal:  %s\n",
			typedCommand("setup-token"))
		return 1
	}
	fmt.Println("\nThe token is in the elevated window -- approve the Windows prompt.")
	return 0
}
