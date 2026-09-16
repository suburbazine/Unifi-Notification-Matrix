package service

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// PlaceBinary writes to the real install directory, which needs administrator
// rights. These exercise the parts that do not.
func TestTheInstallPathIsNotInsideAUserProfile(t *testing.T) {
	p := DefaultInstallPath()
	if p == "" {
		t.Fatal("there is no default install path, so install has nowhere to put anything")
	}
	// The whole point of placing the binary is to get it OUT of the places
	// LocationWarning objects to. If the destination is one of them, the
	// feature is decorative.
	if w := LocationWarning(p); w != "" {
		t.Fatalf("the default install path %s is somewhere install warns about:\n%s", p, w)
	}
}

func TestPlacingSomethingAlreadyInPlaceIsANoOp(t *testing.T) {
	// sameFile is what decides this, and it is the guard against a program
	// copying itself over itself and truncating it to nothing.
	dir := t.TempDir()
	a := filepath.Join(dir, "notifymatrix.exe")
	if err := os.WriteFile(a, []byte("the binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !sameFile(a, a) {
		t.Fatal("a file is not recognised as itself, so install would copy it over itself")
	}
	b := filepath.Join(dir, "other.exe")
	if err := os.WriteFile(b, []byte("the binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Identical CONTENTS are not the same file. Treating them as such would
	// skip an install that was genuinely needed.
	if sameFile(a, b) {
		t.Fatal("two distinct files with the same contents were treated as one")
	}
	if sameFile(a, filepath.Join(dir, "absent.exe")) {
		t.Fatal("a missing destination was treated as already in place")
	}
}

// The copy is verified because a truncated one is a service that will not
// start, found at the moment something needed watching.
func TestTheCopyIsCheckedByHash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	body := []byte("some bytes")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("hashFile = %s, want %s", got, hex.EncodeToString(sum[:]))
	}
	if _, err := hashFile(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("hashing a file that does not exist reported success")
	}
}
