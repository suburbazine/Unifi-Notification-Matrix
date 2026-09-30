package firewall

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf16"
)

// encode is what powershell.exe -EncodedCommand takes: UTF-16LE, base64. It
// is used rather than -Command so that nothing in the script -- a program
// path with a quote in it, say -- is ever re-parsed by a command line.
func encode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// PowerShell runs a script with the system's Windows PowerShell and returns
// what it wrote to stdout.
//
// Stdout only, and progress silenced: with the two mixed, the first run on a
// machine prefixed the JSON with a CLIXML "Preparing modules for first use"
// record and nothing could read it. Stderr is kept for the error.
func PowerShell(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-EncodedCommand",
		encode("$ProgressPreference = 'SilentlyContinue'\n"+script))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}
