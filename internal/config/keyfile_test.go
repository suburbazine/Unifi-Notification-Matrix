package config

import (
	"path/filepath"
	"testing"
)

// captureKeyFile swaps the binding for the duration of a test and reports what
// config asked for.
func captureKeyFile(t *testing.T) *string {
	t.Helper()
	real := setKeyFile
	t.Cleanup(func() { setKeyFile = real })
	var got string
	setKeyFile = func(p string) { got = p }
	return &got
}

// THE KEY HAS TO BE WHEREVER THE CONFIG IS.
//
// The key-file tier's path used to come from $STATE_DIRECTORY, else a
// hardcoded /var/lib/notifymatrix/secret.key. Nothing ever called SetKeyFile,
// although its comment said config did.
//
// On the ordinary Linux unit those two answers coincide -- StateDirectory=
// puts the state at /var/lib/notifymatrix, which is also the data directory --
// so the difference was never exercised. The UniFi gateway unit cannot use
// StateDirectory at all, because it is always relative to /var/lib while the
// gateway keeps state on /data. $STATE_DIRECTORY was therefore unset, the
// hardcoded path won, and the daemon refused to start: it reported, correctly
// and uselessly, that the key did not match the config.
//
// $STATE_DIRECTORY is set to somewhere else DELIBERATELY. Left unset, this
// test passes against the old code on any machine that is not a systemd unit
// -- which is every developer machine and every CI runner.
func TestTheKeyFileFollowsTheDataDirectory(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", filepath.Join(t.TempDir(), "somewhere-else"))
	got := captureKeyFile(t)

	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	want := filepath.Join(dir, KeyFileName)
	if *got != want {
		t.Errorf("the key-file tier was pointed at %q, want %q -- the daemon "+
			"would look for its key in a directory it is not using", *got, want)
	}
}

// Every entry point that touches the config binds it. A first Save is what
// WRITES the key, and writing it somewhere the next Load will not look is the
// same bug one step earlier.
func TestEveryConfigEntryPointBindsTheKeyFile(t *testing.T) {
	dir := t.TempDir()
	c := Default()
	if err := Save(dir, &c); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	want := filepath.Join(dir, KeyFileName)
	for name, call := range map[string]func() error{
		"Load":         func() error { _, err := Load(dir); return err },
		"LoadOrCreate": func() error { _, err := LoadOrCreate(dir); return err },
		"Save":         func() error { c := Default(); return Save(dir, &c) },
	} {
		got := captureKeyFile(t)
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if *got != want {
			t.Errorf("%s bound the key to %q, want %q", name, *got, want)
		}
	}
}

// An empty data directory leaves the fallback alone rather than binding the
// key to whatever the process's working directory happens to be.
func TestAnEmptyDataDirectoryDoesNotRebindTheKey(t *testing.T) {
	got := captureKeyFile(t)
	bindKeyFile("   ")
	if *got != "" {
		t.Errorf("an empty data dir bound the key to %q", *got)
	}
}
