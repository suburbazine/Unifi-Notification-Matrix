package fileperm

import (
	"os"
	"path/filepath"
	"testing"
)

// The Windows implementation builds a DACL from an SDDL string. A typo there
// does not fail to compile and does not fail at review -- it fails at runtime,
// on the one call whose whole job is keeping credentials off a shared machine.
// So: actually run it.
func TestRestrictSucceedsAndLeavesTheFileUsable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte("token: hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Restrict(path); err != nil {
		t.Fatalf("Restrict: %v", err)
	}

	// The account that owns the file must still be able to read it: the daemon
	// writes its own configuration and then has to read it back. A DACL that
	// locked out the writer would be discovered at the worst possible moment.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the file is unreadable to the account that wrote it: %v", err)
	}
	if string(b) != "token: hunter2\n" {
		t.Errorf("contents changed: %q", b)
	}

	// And still writable, because Save rewrites it in place every time.
	if err := os.WriteFile(path, []byte("token: hunter3\n"), 0o600); err != nil {
		t.Errorf("the file is unwritable to the account that wrote it: %v", err)
	}
}

func TestRestrictReportsAMissingFile(t *testing.T) {
	if err := Restrict(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("restricting a file that does not exist reported success")
	}
}
