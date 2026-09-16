package main

import (
	"flag"
	"strings"
	"testing"
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
