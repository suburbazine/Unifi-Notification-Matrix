package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromServiceCredential(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("unifi-api-key", "abc123\n")
	write("bare", "xyz789")
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	t.Run("trailing newline is stripped", func(t *testing.T) {
		// A credential seeded from a shell redirect carries a newline, and an
		// API key with one on the end fails auth exactly like a wrong key.
		got, ok := FromServiceCredential("unifi-api-key")
		if !ok || got.Reveal() != "abc123" {
			t.Fatalf("got %q ok=%v, want %q", got.Reveal(), ok, "abc123")
		}
	})

	t.Run("value without newline is unchanged", func(t *testing.T) {
		got, _ := FromServiceCredential("bare")
		if got.Reveal() != "xyz789" {
			t.Errorf("got %q", got.Reveal())
		}
	})

	t.Run("missing credential is absent, not empty-and-ok", func(t *testing.T) {
		if _, ok := FromServiceCredential("nope"); ok {
			t.Error("reported a credential that does not exist")
		}
	})

	t.Run("path traversal is refused", func(t *testing.T) {
		// Names come from config, which is hand-editable.
		for _, bad := range []string{"../etc/shadow", "a/b", `a\b`, "..", ".", ""} {
			if _, ok := FromServiceCredential(bad); ok {
				t.Errorf("accepted %q as a credential name", bad)
			}
		}
	})
}

func TestServiceCredentialsAbsentWithoutEnv(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if ServiceCredentialsAvailable() {
		t.Error("reported credentials available with no CREDENTIALS_DIRECTORY")
	}
	if _, ok := FromServiceCredential("anything"); ok {
		t.Error("returned a credential with no CREDENTIALS_DIRECTORY")
	}
}
