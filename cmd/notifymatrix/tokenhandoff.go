package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
	"github.com/suburbazine/Unifi-Notification-Matrix/internal/setup"
)

// THE MOMENT AN INSTALL IS MOST LIKELY TO BE LOST.
//
// `install` printed "install: ok" and stopped. The service then started, minted
// a one-time setup token, and wrote it to a file -- and said so on a console
// that does not exist, because a Windows service has no stdout. The operator
// saw two words, opened the interface, and was asked for a token nothing had
// ever shown them.
//
// The sign-in page does explain it, so nobody was permanently stuck. But the
// moment they most needed the answer was the moment the install finished, and
// that was the one place that said nothing.
//
// Worse on the elevated path: `install` without administrator rights relaunches
// itself in a NEW elevated window, which Windows destroys the instant the
// program exits. Everything this prints would flash past unread.

// tokenWaitFor is how long to wait for the service to write its token.
//
// The service is started by the install and mints the token when it starts, so
// this is a race by construction. Generous enough for a cold start on a slow
// machine, short enough that somebody watching does not conclude it has hung.
const tokenWaitFor = 20 * time.Second

// tokenPollEvery is how often to look while waiting.
const tokenPollEvery = 250 * time.Millisecond

// confirmWord is what the operator types to say they have the token.
//
// A word rather than Enter. Enter is what somebody presses to make a prompt go
// away, and "press Enter to continue" would be a pause dressed up as a
// confirmation -- which is the failure this exists to prevent, one step later.
const confirmWord = "copied"

// handOverSetupToken shows the new installation's setup token and does not
// return until the operator says they have it.
//
// out, in and interactive are passed rather than read from the world, for the
// reason holdTheWindowOpen gives: the interesting case is a console this
// process owns alone, which a test process never has.
func handOverSetupToken(out io.Writer, in io.Reader, dataDir string, interactive bool,
	waitFor time.Duration, exe string) {

	// Already set up. Re-installing over a working configuration mints no
	// token, so waiting for one would hang for twenty seconds and then report
	// a problem that is not one.
	if cfg, err := config.Load(dataDir); err == nil && cfg != nil &&
		cfg.Web.PasswordHash != "" {
		fmt.Fprintf(out, "\nA settings password is already set, so there is no "+
			"setup token to collect.\nOpen http://%s/ and sign in.\n",
			listenOrDefault(cfg.Web.Listen))
		return
	}

	token, where, ok := waitForSetupToken(dataDir, waitFor)
	if !ok {
		// Not a failure worth stopping on. The token may simply be slower than
		// this was willing to wait, and it is retrievable by command -- so say
		// that rather than implying something broke.
		fmt.Fprintf(out, `
The service is starting and has not written its setup token yet.

When you are ready to set the first password, run:

    %s

It needs administrator rights and will ask for them.
`, setup.Input{Exe: exe}.Command("setup-token"))
		return
	}

	fmt.Fprintf(out, `
================================================================
 COPY THIS NOW -- it is how you set the first password
================================================================

    %s

It works once. Nothing else can claim the settings page.
`, token)
	if where != "" {
		fmt.Fprintf(out, "\nIt is also in %s\nuntil a password is set.\n", where)
	}
	fmt.Fprintf(out, `
If this window closes before you have it, you are not locked out:

    %s

`, setup.Input{Exe: exe}.Command("setup-token"))

	if !interactive {
		// Nobody is watching: a scripted or unattended install. Blocking here
		// would hang a deployment for ever, which is a far worse failure than
		// an unread prompt.
		return
	}

	// THE POINT OF ALL OF THIS. Hold the window until they say they have it.
	fmt.Fprintf(out, "Type %s and press Enter once you have copied the token: ", confirmWord)
	if !awaitConfirmation(out, in) {
		fmt.Fprintf(out, "\nCarrying on without a confirmation. Run %s if you need it again.\n",
			setup.Input{Exe: exe}.Command("setup-token"))
	}
}

// awaitConfirmation reads until the operator types the word, and reports
// whether they did.
//
// Bounded, and stdin closing ends it. An operator who cannot get past a prompt
// is locked out by the thing meant to help them, and this is running in a
// window that may be the only one they have.
func awaitConfirmation(out io.Writer, in io.Reader) bool {
	const tries = 5
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	attempts := 0

	for attempts < tries {
		n, err := in.Read(one)
		if n > 0 {
			if one[0] != '\n' {
				if one[0] != '\r' {
					buf = append(buf, one[0])
				}
				if len(buf) > 64 {
					buf = buf[:64]
				}
				continue
			}
			line := strings.ToLower(strings.TrimSpace(string(buf)))
			buf = buf[:0]
			if line == confirmWord {
				fmt.Fprintln(out, "\nGood. The token is spent the moment you use it.")
				return true
			}
			attempts++
			if attempts < tries {
				fmt.Fprintf(out, "Type %s to confirm you have the token: ", confirmWord)
			}
			continue
		}
		if err != nil {
			// Closed or redirected stdin. Not somebody refusing to answer.
			return false
		}
	}
	return false
}

// waitForSetupToken polls for the file the service writes, because the service
// writes it a moment after the install returns.
func waitForSetupToken(dataDir string, waitFor time.Duration) (token, path string, ok bool) {
	path = config.SetupTokenPath(dataDir)
	deadline := time.Now().Add(waitFor)
	for {
		if b, err := os.ReadFile(path); err == nil {
			if tok := firstToken(string(b)); tok != "" {
				return tok, path, true
			}
		}
		if time.Now().After(deadline) {
			return "", path, false
		}
		time.Sleep(tokenPollEvery)
	}
}

// firstToken pulls the token out of the file, which wraps it in explanatory
// text for whoever opens it directly.
//
// Matched on the ALPHABET rather than on "a line with no spaces", which was
// the first attempt and was wrong: the file's second line is a rule of equals
// signs under the heading, and that has no spaces either. A token is base64url,
// so "=" is precisely the character that cannot appear in one.
func firstToken(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < minTokenChars || !isBase64URL(line) || !looksRandom(line) {
			continue
		}
		return line
	}
	return ""
}

// minTokenChars is shorter than a real token -- 32 random bytes is 43 url-safe
// characters -- so a future change to the token size does not silently stop
// this finding it, and long enough that no decoration in the file reaches it.
const minTokenChars = 32

// looksRandom rejects decoration that happens to be in the alphabet.
//
// "-" and "_" ARE base64url characters, so a rule of hyphens under a heading
// passes the alphabet check -- found by the test written for the equals-sign
// rule, which is the same mistake one character over. A run of one repeated
// character is not a token; 32 random bytes produce about thirty distinct
// characters, so eight is far below anything real and far above any rule.
func looksRandom(s string) bool {
	seen := map[rune]bool{}
	for _, r := range s {
		seen[r] = true
		if len(seen) >= minDistinctChars {
			return true
		}
	}
	return false
}

const minDistinctChars = 8

func isBase64URL(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func listenOrDefault(listen string) string {
	if l := strings.TrimSpace(listen); l != "" {
		return l
	}
	return "127.0.0.1:8322"
}

// someoneIsWatching reports whether stdin is a terminal a person could type
// into.
//
// A DIFFERENT question from ownsTheConsoleAlone, which asks whether this
// process is the only one on its console -- the double-click case. Here the
// question is simply whether anybody is there, because an install run from a
// PowerShell window is shared with that shell and still has an operator in
// front of it.
//
// Wrong in the safe direction by construction: redirected, piped or absent
// stdin all report false, so a scripted or unattended install never blocks.
// The cost of a false negative is an unread prompt; the cost of a false
// positive is a deployment hanging for ever.
func someoneIsWatching() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
