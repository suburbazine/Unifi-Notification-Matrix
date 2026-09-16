package secret

import (
	"os"
	"path/filepath"
	"strings"
)

// FromServiceCredential reads a secret that the service manager decrypted for
// us before the process started.
//
// This is the ADMINISTRATOR-PROVISIONED path, and it is deliberately separate
// from the Provider chain, because it solves a different problem.
//
// The daemon runs unprivileged (User=notifymatrix), so it cannot encrypt with
// the systemd host key -- that file is root-only. But systemd itself runs the
// decryption as root at unit start, before dropping privileges, and drops the
// plaintext into a private directory owned by the service user. So a
// credential provisioned this way gets the STRONGEST binding available on the
// machine (host+tpm2) even though the process that consumes it could never
// have produced it.
//
// Unit file:
//
//	[Service]
//	User=notifymatrix
//	LoadCredentialEncrypted=unifi-api-key:/etc/notifymatrix/unifi-api-key.cred
//
// and the operator seeds it once, with privilege, at install:
//
//	systemd-creds encrypt --name=unifi-api-key key.txt /etc/notifymatrix/unifi-api-key.cred
//
// The trade is that a credential managed this way cannot be CHANGED from the
// web UI -- rotating it means running that command again. That is the right
// trade for a site that wants keys under configuration management, and the
// wrong one for an operator who has never opened a terminal. Both must work,
// which is why this path exists alongside the Provider chain rather than
// instead of it.
//
// This path WINS when both are present: an administrator who went to the
// trouble of provisioning a credential has stated an intent, and silently
// preferring one the UI happened to write would override it.
func FromServiceCredential(name string) (Secret, bool) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", false
	}
	// The name is used as a path element, so refuse anything that could climb
	// out of the credentials directory. Names come from config, and config is
	// editable by hand.
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", false
	}
	// systemd writes the credential verbatim. A file seeded from a shell
	// redirect almost always carries a trailing newline, and an API key with a
	// newline on the end fails authentication in a way that looks like a wrong
	// key -- which is an afternoon of someone's life.
	return Secret(strings.TrimRight(string(b), "\r\n")), true
}

// ServiceCredentialsAvailable reports whether the service manager passed any
// credentials at all. Used by diagnostics to explain which path a secret came
// from, since "the UI change did not take effect" is otherwise baffling when an
// administrator-provisioned credential is overriding it.
func ServiceCredentialsAvailable() bool {
	return os.Getenv("CREDENTIALS_DIRECTORY") != ""
}
