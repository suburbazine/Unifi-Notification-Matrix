package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/service"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// setPassword sets the settings password from the command line.
//
// The web setup token is minted in memory and printed to stdout when the
// daemon starts, on the reasoning that possession of the console is the only
// authority on a fresh install. That reasoning holds right up until the
// daemon is a SERVICE, which is what the product tells everybody to do: a
// Windows service has no stdout at all, so the token is printed into a void
// and the settings page can never be unlocked. The install instructions had
// no way out of that, and neither did anybody who followed them.
//
// So: a second door, openable only by somebody who can already write the
// config file. That is not a weaker authority than the console -- anyone who
// can write the config can point the daemon at their own everything -- and it
// costs nothing at rest, which writing the token to a file would not.
func setPassword(dataDir string, interactive bool) int {
	// LoadOrCreate, not Load: somebody who downloaded this and wants a password
	// set before anything else has no configuration yet, and refusing them with
	// "could not read the configuration" would be a dead end on step one.
	cfg, err := config.LoadOrCreate(dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: could not read the configuration:", err)
		fmt.Fprintf(os.Stderr, "       looked in %s\n", config.Path(dataDir))
		return 1
	}

	if cfg.Web.PasswordHash != "" {
		fmt.Println("A settings password is already set. This replaces it.")
	}

	pw, err := readNewPassword(os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	hash, err := web.HashPassword(pw)
	if err != nil {
		// Stated as the rule rather than as a failure, because the only way to
		// get here is a password that is too short and the useful thing to say
		// is how long it has to be.
		if errors.Is(err, web.ErrWeakPassword) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "error: could not hash the password:", err)
		return 1
	}

	cfg.Web.PasswordHash = hash
	if err := config.Save(dataDir, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error: could not save the configuration:", err)
		return 1
	}
	fmt.Println("\nPassword set.")

	// The daemon reads its config at start, so one that is already running is
	// still holding the old value -- and worse, it would write that stale copy
	// back over this one the next time anything saves. Saying "done" without
	// saying that is a lie that looks like success right up until they try to
	// sign in.
	//
	// The question is "is a daemon using THIS data directory", not "is the
	// service running". They are different questions whenever the service was
	// installed against some other --data-dir, and answering the second one
	// would tell somebody to restart a service that never reads this file.
	// The single-instance lock answers the first exactly.
	if !service.IsHeld(dataDir) {
		fmt.Println("It takes effect the next time the daemon starts.")
		return 0
	}

	fmt.Printf("\nA daemon is running against %s and is still holding the\n", dataDir)
	fmt.Println("old configuration. It has to be restarted before this password works.")

	// Only offer to drive the service when the service is in fact what holds
	// this directory. A foreground `notifymatrix run` also holds the lock, and
	// stopping the service would not touch it.
	st, serr := service.New().Status()
	if serr != nil || st.State != service.StateRunning {
		fmt.Println("\nThat daemon is not this machine's service -- most likely a")
		fmt.Println("`notifymatrix run` in another window. Stop it and start it again.")
		return 0
	}

	if interactive && askYesNo(os.Stdout, bufio.NewReader(os.Stdin), "Restart the service now?") {
		if code := serviceCmd("stop", dataDir, ""); code != 0 {
			return code
		}
		return serviceCmd("start", dataDir, "")
	}
	fmt.Println("\nTo do it yourself:  notifymatrix stop && notifymatrix start")
	return 0
}

// readNewPassword asks twice without echoing, when there is a terminal to
// echo to.
//
// Piped input reads a single line and does not confirm it: a script that
// supplies the same wrong value twice has confirmed nothing, and refusing to
// work without a terminal would make this unusable from the one place an
// unattended install actually happens.
func readNewPassword(in *os.File, out io.Writer) (string, error) {
	if !term.IsTerminal(int(in.Fd())) {
		line, err := bufio.NewReader(in).ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", errors.New("no password was supplied on standard input")
		}
		// An EOF with content read is the normal end of a piped value.
		if err != nil && err != io.EOF {
			return "", err
		}
		return line, nil
	}

	fmt.Fprintf(out, "New settings password (at least %d characters, not shown): ", web.MinPasswordLength)
	first, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	fmt.Fprint(out, "Again: ")
	second, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("the two passwords did not match; nothing was changed")
	}
	return string(first), nil
}
