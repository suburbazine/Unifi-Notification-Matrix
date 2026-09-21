package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// secretFields are the config keys whose values are credentials.
//
// The regex below is how a credential left in plain text is FOUND, so a secret
// field missing from this list is one this product will never notice sitting
// readable on disk -- the same silence the check exists to break.
//
// It is a list rather than something derived, because the detector works on
// RAW BYTES: it runs before the file has been parsed, on purpose, so that a
// configuration which fails to load still reports the credentials sitting in
// it. That means it cannot ask the type system what the secret fields are.
//
// TestEveryCredentialFieldIsWatched walks config.Config with reflection and
// fails if a secret.Secret field's json tag is not here. That is what keeps
// the two in step: the list is hand-written, and forgetting to extend it
// breaks the build rather than going quiet.
//
// Five of the ten were missing when an audit checked -- ack_key among them,
// which signs every acknowledgement link this product sends.
var secretFields = []string{
	"api_key", "token", "password", "link_tls_key", "link_key",
	"ack_key", "bearer", "secret", "user", "account_sid",
	// The per-application console keys. UniFi mints one key per application,
	// so a site that needs all three has three credentials in this file
	// rather than one.
	"protect_key", "access_key", "network_key",
}

// knownPrefixes are the markers a protected value carries.
var knownPrefixes = []string{
	secret.PrefixDPAPI, secret.PrefixSDCreds, secret.PrefixTPM2,
	secret.PrefixAgeKey, secret.PrefixPlain,
}

var secretLine = regexp.MustCompile(`(?m)^\s*(` + strings.Join(secretFields, "|") + `)\s*:\s*(.+?)\s*$`)

// PlaintextSecrets lists the credential fields in raw that are not protected.
//
// An operator bootstrapping by hand pastes a key straight into the file, which
// the secret package accepts on purpose -- otherwise the only way to get a key
// in is a UI that may not be running yet. But a credential that sat in a
// readable file has been exposed, and saying so is the honest half of being
// permissive: the value is re-encrypted on the next Save, and the operator
// still needs to know it was briefly in the clear so they can decide whether
// to rotate it.
//
// Field names only are returned, never values.
func PlaintextSecrets(raw []byte) []string {
	var out []string
	for _, m := range secretLine.FindAllStringSubmatch(string(raw), -1) {
		field, value := m[1], strings.Trim(m[2], `"'`)
		if value == "" {
			continue
		}
		protected := false
		for _, p := range knownPrefixes {
			if strings.HasPrefix(value, p) {
				protected = true
				break
			}
		}
		// plain: is a prefix, but it means NOT ENCRYPTED, so it is reported
		// too -- the point is what is readable, not what is labelled.
		if protected && !strings.HasPrefix(value, secret.PrefixPlain) {
			continue
		}
		out = append(out, field)
	}
	return out
}

// PlaintextWarning renders the operator-facing message, or "" when there is
// nothing to say.
func PlaintextWarning(fields []string, path string) string {
	if len(fields) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"WARNING: %d credential(s) in %s are NOT encrypted (%s).\n"+
			"         They will be encrypted the next time the configuration is saved,\n"+
			"         but they have been readable on disk until now -- treat them as\n"+
			"         exposed and rotate them if that matters.",
		len(fields), path, strings.Join(fields, ", "))
}
