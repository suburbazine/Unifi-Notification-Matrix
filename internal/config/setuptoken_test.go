package config

import (
	"os"
	"strings"
	"testing"
)

// The token is printed to the daemon's stdout, and a Windows service has none.
// On the installation this product tells everybody to make, it was minted into
// a void and the settings page could not be claimed at all.
func TestTheTokenIsWrittenWhereAnOperatorCanFindIt(t *testing.T) {
	dir := t.TempDir()
	const token = "a-one-time-setup-token-value"

	if err := WriteSetupToken(dir, token); err != nil {
		t.Fatalf("WriteSetupToken: %v", err)
	}

	b, err := os.ReadFile(SetupTokenPath(dir))
	if err != nil {
		t.Fatalf("reading it back: %v", err)
	}
	body := string(b)
	if !strings.Contains(body, token) {
		t.Fatalf("the token is not in the file it was written to:\n%s", body)
	}
	// The file has to explain itself. Somebody finding it months later must be
	// able to tell whether it is a live credential.
	// Including the one thing that stops an administrator reading it: being
	// in the group is not enough until the process elevates, and the file has
	// to say so or it reads as broken permissions.
	for _, want := range []string{"once", "deleted", "set-password", "setup-token", "elevate"} {
		if !strings.Contains(body, want) {
			t.Errorf("the file never mentions %q, so it cannot be judged by whoever finds it:\n%s",
				want, body)
		}
	}
}

// It is spent the moment a password exists, and a file that looks like a live
// credential and is not is its own kind of problem.
func TestTheTokenFileIsRemovable(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSetupToken(dir, "something"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSetupToken(dir); err != nil {
		t.Fatalf("RemoveSetupToken: %v", err)
	}
	if _, err := os.Stat(SetupTokenPath(dir)); !os.IsNotExist(err) {
		t.Fatal("the token file survived removal")
	}
	// Removing one that is not there is the normal case at every start after
	// the first, and must not be an error.
	if err := RemoveSetupToken(dir); err != nil {
		t.Errorf("removing an absent token file reported: %v", err)
	}
}

// An empty token means there is nothing to record -- a password already
// exists -- and must clear any stale file rather than write an empty one.
func TestAnEmptyTokenClearsRatherThanWritesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSetupToken(dir, "stale"); err != nil {
		t.Fatal(err)
	}
	if err := WriteSetupToken(dir, ""); err != nil {
		t.Fatalf("WriteSetupToken with no token: %v", err)
	}
	if _, err := os.Stat(SetupTokenPath(dir)); !os.IsNotExist(err) {
		t.Fatal("a stale token file survived a start with no token")
	}
}

// Rewriting must replace, not append. A file accumulating every token this
// daemon ever minted would be a list of credentials rather than one.
func TestRewritingReplacesTheOldToken(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSetupToken(dir, "FIRST-TOKEN-VALUE"); err != nil {
		t.Fatal(err)
	}
	if err := WriteSetupToken(dir, "SECOND-TOKEN-VALUE"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(SetupTokenPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "FIRST-TOKEN-VALUE") {
		t.Fatalf("the previous token is still in the file:\n%s", b)
	}
	if !strings.Contains(string(b), "SECOND-TOKEN-VALUE") {
		t.Fatalf("the current token is missing:\n%s", b)
	}
}
