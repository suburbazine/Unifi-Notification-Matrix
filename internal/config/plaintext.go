package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// secretFields are the config keys whose values are credentials.
var secretFields = []string{"api_key", "token", "password"}

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
