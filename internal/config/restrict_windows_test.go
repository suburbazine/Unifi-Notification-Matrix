//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The token is the entire authority for claiming a fresh installation. Both
// ProgramData and Program Files grant read to Users by inheritance, so a file
// written there without a PROTECTED DACL is readable by every local account --
// and the operator would have no way of knowing.
//
// Asserted against what Windows itself reports, not against the SDDL string
// that was passed in: the interesting question is what the ACL ENDED UP as,
// and the inherited entries are the ones that have to be gone.
func TestTheTokenFileIsNotReadableByOrdinaryUsers(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSetupToken(dir, "a-token"); err != nil {
		t.Fatalf("WriteSetupToken: %v", err)
	}
	path := SetupTokenPath(dir)

	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Skipf("icacls unavailable: %v", err)
	}
	acl := string(out)
	t.Logf("icacls:\n%s", acl)

	// Nothing granting the everyone-ish principals may survive.
	for _, forbidden := range []string{
		`BUILTIN\Users`, "Everyone", `NT AUTHORITY\Authenticated Users`,
		"AUTHENTICATED USERS",
	} {
		if strings.Contains(acl, forbidden) {
			t.Errorf("the token file grants access to %s:\n%s", forbidden, acl)
		}
	}
	// And the two that must be there, or an administrator cannot read their
	// own token and the file is pointless.
	if !strings.Contains(acl, "Administrators") {
		t.Errorf("administrators cannot read the token file:\n%s", acl)
	}
	if !strings.Contains(acl, "SYSTEM") {
		t.Errorf("the service account cannot read the token file:\n%s", acl)
	}
}

// If the permissions cannot be applied, the file must NOT be left behind: a
// token readable by every local account is worse than no token file, because
// nothing would say so.
func TestAFileThatCannotBeProtectedIsNotLeftBehind(t *testing.T) {
	dir := t.TempDir()
	// A path inside a directory that does not exist: the create fails, and the
	// point is that nothing is left at the target either way.
	missing := filepath.Join(dir, "no-such-dir")
	if err := WriteSetupToken(missing, "a-token"); err == nil {
		t.Fatal("writing into a missing directory reported success")
	}
	if _, err := os.Stat(SetupTokenPath(missing)); !os.IsNotExist(err) {
		t.Fatal("a token file was left behind after a failed write")
	}
}
