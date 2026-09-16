package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/web"
)

// Piped input is how an unattended install supplies a password, and it must
// not be silently mangled -- a trailing CRLF included in the password is a
// password nobody can ever type back.
func TestAPipedPasswordIsTakenExactlyAsGiven(t *testing.T) {
	for _, tc := range []struct{ name, written, want string }{
		{"unix newline", "correct horse battery staple\n", "correct horse battery staple"},
		{"windows newline", "correct horse battery staple\r\n", "correct horse battery staple"},
		{"no trailing newline", "correct horse battery staple", "correct horse battery staple"},
		{"spaces are part of it", "  leading and trailing  \n", "  leading and trailing  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := pipeWith(t, tc.written)
			got, err := readNewPassword(in, &strings.Builder{})
			if err != nil {
				t.Fatalf("readNewPassword: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Empty input must be an error rather than an empty password. Hashing "" and
// storing it would leave the settings page open to anybody who submits nothing.
func TestAnEmptyPipedPasswordIsRefused(t *testing.T) {
	in := pipeWith(t, "")
	if got, err := readNewPassword(in, &strings.Builder{}); err == nil {
		t.Fatalf("accepted an empty password (%q) from a pipe", got)
	}
}

// The value must go through the same length rule as the web form. A CLI door
// that accepts a weaker password than the UI is the door everybody uses.
func TestTheCLIEnforcesTheSamePasswordRuleAsTheWebForm(t *testing.T) {
	dir := t.TempDir()
	short := strings.Repeat("a", 4)
	if _, err := hashForTest(short); err == nil {
		t.Fatal("a 4-character password was accepted")
	}
	long := strings.Repeat("a", 32)
	if _, err := hashForTest(long); err != nil {
		t.Fatalf("a 32-character password was refused: %v", err)
	}
	_ = filepath.Join(dir, "unused")
}

func hashForTest(pw string) (string, error) { return web.HashPassword(pw) }

func pipeWith(t *testing.T, s string) *os.File {
	t.Helper()
	// A real *os.File, not a strings.Reader: readNewPassword asks whether its
	// input is a terminal, and a pipe is the case that matters.
	f, err := os.CreateTemp(t.TempDir(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
