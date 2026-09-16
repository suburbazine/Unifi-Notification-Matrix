package main

import (
	"bufio"
	"flag"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/config"
)

// The bug this exists for was silent, which is the worst kind. Go's flag
// package stops parsing at the first non-flag argument, so `run --data-dir X`
// discarded the flag entirely: the daemon came up against the DEFAULT data
// directory and said nothing about it.
//
// For this product that is not cosmetic. The data directory holds the incident
// store and the single-instance lock, so silently using the wrong one means a
// second instance that cannot see the first -- and two processes both alerting
// is the exact failure the lock exists to prevent.
func TestFlagsAreParsedWhereverTheVerbAppears(t *testing.T) {
	for _, tc := range []struct {
		name    string
		argv    []string
		cmd     string
		dataDir string
		user    string
	}{
		{"flags after the verb", []string{"run", "--data-dir", "/tmp/x"}, "run", "/tmp/x", ""},
		{"flags before the verb", []string{"--data-dir", "/tmp/x", "run"}, "run", "/tmp/x", ""},
		{"equals form after", []string{"run", "--data-dir=/tmp/x"}, "run", "/tmp/x", ""},
		{"equals form before", []string{"--data-dir=/tmp/x", "run"}, "run", "/tmp/x", ""},
		{"single dash", []string{"run", "-data-dir", "/tmp/x"}, "run", "/tmp/x", ""},
		{"verb only", []string{"status"}, "status", "", ""},
		{"no arguments at all", nil, "", "", ""},
		{"two flags after the verb", []string{"install", "--data-dir", "/tmp/x", "--user", "nm"}, "install", "/tmp/x", "nm"},
		{"flags either side", []string{"--user", "nm", "install", "--data-dir", "/tmp/x"}, "install", "/tmp/x", "nm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, flags := splitCommand(tc.argv)
			if cmd != tc.cmd {
				t.Errorf("command = %q, want %q", cmd, tc.cmd)
			}
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.SetOutput(&strings.Builder{})
			dataDir := fs.String("data-dir", "", "")
			user := fs.String("user", "", "")
			if err := fs.Parse(flags); err != nil {
				t.Fatalf("parsing %v: %v", flags, err)
			}
			if *dataDir != tc.dataDir {
				t.Errorf("--data-dir = %q, want %q", *dataDir, tc.dataDir)
			}
			if *user != tc.user {
				t.Errorf("--user = %q, want %q", *user, tc.user)
			}
		})
	}
}

// A flag VALUE that happens to look like a verb must not be mistaken for one.
func TestAFlagValueIsNotMistakenForTheVerb(t *testing.T) {
	// "status" here is the directory name, not the command.
	cmd, flags := splitCommand([]string{"--data-dir", "status", "run"})
	if cmd != "run" {
		t.Errorf("command = %q, want %q -- the value of --data-dir was taken as the verb", cmd, "run")
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(&strings.Builder{})
	dataDir := fs.String("data-dir", "", "")
	if err := fs.Parse(flags); err != nil {
		t.Fatal(err)
	}
	if *dataDir != "status" {
		t.Errorf("--data-dir = %q, want %q", *dataDir, "status")
	}
}

func TestDoubleDashEndsFlagParsing(t *testing.T) {
	cmd, flags := splitCommand([]string{"run", "--", "--data-dir"})
	if cmd != "run" {
		t.Errorf("command = %q, want run", cmd)
	}
	if len(flags) != 1 || flags[0] != "--data-dir" {
		t.Errorf("flags = %v, want the literal argument preserved", flags)
	}
}

// Double-clicking the .exe in Explorer ran it, printed its status, and closed
// the window in the same instant. The report was "it just opens and closes
// silently" -- and for a downloaded security tool that reads as broken, or
// worse, as something that did not want to be watched. The program was fine.
// Nobody could see it.
func TestADoubleClickedWindowWaitsBeforeItCloses(t *testing.T) {
	var out strings.Builder
	holdTheWindowOpen(&out, strings.NewReader("\n"), true, `C:\Users\x\Downloads\notifymatrix-windows-amd64.exe`)

	got := out.String()
	if got == "" {
		t.Fatal("nothing was printed before the window closed; the flash is the whole bug")
	}
	for _, want := range []string{
		"Press Enter", // the pause itself
		"PowerShell",  // and where the rest of the commands live
		"setup",       // pointed at the command that leads somewhere
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the message does not mention %q:\n%s", want, got)
		}
	}

	// The command it suggests has to be the file the user actually has, not
	// the project's name for it. They downloaded `notifymatrix-windows-amd64.exe`
	// and typing `notifymatrix setup` gets them "not recognized".
	if !strings.Contains(got, `.\notifymatrix-windows-amd64.exe setup`) {
		t.Errorf("suggested a command naming something other than the file on disk:\n%s", got)
	}
	if strings.Contains(got, `C:\Users\x\Downloads`) {
		t.Errorf("printed the full path where a command is meant to go:\n%s", got)
	}
}

// The pause must happen ONLY for a double-click. Run from a shell the output
// stays on screen with nothing to wait for, and a pause there would stall every
// scripted invocation -- including the service, and including CI.
func TestNothingWaitsWhenTheConsoleIsShared(t *testing.T) {
	var out strings.Builder
	// A reader that fails the test if it is ever consulted: blocking on stdin
	// is the failure being guarded against, and it would not look like a
	// failing assertion, it would look like a hung build.
	holdTheWindowOpen(&out, readerThatMustNotBeRead{t}, false, "notifymatrix")
	if out.String() != "" {
		t.Errorf("printed a double-click message into a shell session:\n%s", out.String())
	}
}

type readerThatMustNotBeRead struct{ t *testing.T }

func (r readerThatMustNotBeRead) Read([]byte) (int, error) {
	r.t.Fatal("waited for a keypress in a session that was not a double-click; unattended runs would hang here")
	return 0, nil
}

// ARCHITECTURE says a double-click must get somebody from "downloaded a file"
// to "it is running and will keep running" WITHOUT being told to open a
// terminal. Printing `notifymatrix install` for them to type is exactly being
// told to open a terminal, so the offer has to be a question they can answer
// where they are.
func TestTheOfferDefaultsToYesOnAPlainEnter(t *testing.T) {
	for _, tc := range []struct {
		typed string
		want  bool
	}{
		{"\n", true},       // just pressed Enter -- the whole point
		{"y\n", true},      //
		{"YES\n", true},    //
		{"  \n", true},     // Enter with a stray space
		{"n\n", false},     //
		{"no\n", false},    //
		{"later\n", false}, // anything that is not yes
		{"", false},        // stdin closed: nobody is there to consent
	} {
		var out strings.Builder
		got := askYesNo(&out, bufio.NewReader(strings.NewReader(tc.typed)), "Install it?")
		if got != tc.want {
			t.Errorf("typed %q: got %v, want %v", tc.typed, got, tc.want)
		}
		if !strings.Contains(out.String(), "Install it?") {
			t.Errorf("typed %q: the question was never asked: %q", tc.typed, out.String())
		}
	}
}

// A closed stdin must read as NO, not as a default yes. This is the branch
// that installs a Windows service and triggers a UAC prompt: getting it wrong
// means an unattended run commits to a system change nobody asked for, because
// there was nobody there to decline it.
func TestAClosedStdinDeclinesRatherThanConsenting(t *testing.T) {
	var out strings.Builder
	if askYesNo(&out, bufio.NewReader(strings.NewReader("")), "Install and start it now?") {
		t.Fatal("consented to installing a service on behalf of a session with no human in it")
	}
}

// The path in os.Args[0] is always a Windows path here -- this code only runs
// on Windows -- but the machine deciding what a separator is may not be.
// filepath.Base on Linux leaves `C:\Users\x\nm.exe` whole, and the suggested
// command becomes `.\C:\Users\x\nm.exe setup`, which is not a command.
func TestTheSuggestedCommandNamesTheFileOnEverySeparator(t *testing.T) {
	for _, tc := range []struct{ argv0, want string }{
		{`C:\Users\x\Downloads\notifymatrix-windows-amd64.exe`, "notifymatrix-windows-amd64.exe"},
		{`C:/Users/x/Downloads/notifymatrix.exe`, "notifymatrix.exe"},
		{`\server\share\notifymatrix.exe`, "notifymatrix.exe"},
		{"/usr/local/bin/notifymatrix", "notifymatrix"},
		{"notifymatrix.exe", "notifymatrix.exe"},
		{"", ""},
	} {
		if got := executableName(tc.argv0); got != tc.want {
			t.Errorf("executableName(%q) = %q, want %q", tc.argv0, got, tc.want)
		}
	}
}

// The channel set is built once at start and never rebuilt, so the config on
// disk and the running process drift apart the moment anybody saves. Reported
// as: ntfy enabled in the UI, and the audit log insisting it is "not enabled".
// Both were telling the truth about different things.
//
// The wording was the visible half. The dangerous half is that the same stale
// set delivers real alarms, so this is a channel that reads as configured and
// would not be told anything at 3am.
func TestAChannelEnabledSinceStartupIsRecognisedAsNeedingARestart(t *testing.T) {
	enabled := &config.Config{Channels: config.Channels{
		Ntfy: &config.Ntfy{Enabled: true},
	}}

	if !channelPendingRestart(enabled, nil, "ntfy") {
		t.Error("enabled in config, absent from the running set: this is the reported bug and it was not detected")
	}
	if !channelPendingRestart(enabled, []string{"email"}, "NTFY") {
		t.Error("the name comparison is case-sensitive; the UI and the config need not agree on case")
	}
	// Running already: whatever the test failed on, it was not staleness, and
	// claiming otherwise would send somebody to restart a daemon for nothing.
	if channelPendingRestart(enabled, []string{"ntfy"}, "ntfy") {
		t.Error("a channel that IS running was reported as pending a restart")
	}
	// Genuinely not enabled anywhere: the original message is the correct one.
	if channelPendingRestart(&config.Config{}, nil, "ntfy") {
		t.Error("a channel enabled nowhere was reported as pending a restart")
	}
	if channelPendingRestart(nil, nil, "ntfy") {
		t.Error("a nil config must not claim anything")
	}
}
