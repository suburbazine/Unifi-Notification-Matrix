package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/suburbazine/Unifi-Notification-Matrix/internal/secret"
)

// EVERY CREDENTIAL FIELD IS WATCHED, AND THE COMPILER IS WHAT ENFORCES IT.
//
// PlaintextSecrets works on RAW BYTES -- deliberately, so a configuration that
// fails to parse still reports the credentials sitting readable inside it --
// which means it cannot ask the type system what the secret fields are. It
// matches a hand-written list of key names instead.
//
// A hand-written list drifts. Five of the ten fields were missing when an
// audit looked, including ack_key, which signs every acknowledgement link this
// product sends: a key pasted into the file by hand would have sat there in
// the clear and nothing would have said so.
//
// So the list stays hand-written and THIS walks the real struct to check it.
// Adding a secret.Secret field without extending secretFields now fails here
// rather than going quiet for a year.
func TestEveryCredentialFieldIsWatched(t *testing.T) {
	watched := map[string]bool{}
	for _, f := range secretFields {
		watched[f] = true
	}

	found := collectSecretTags(t, reflect.TypeOf(Config{}), nil, map[reflect.Type]bool{})
	if len(found) < 8 {
		t.Fatalf("only found %d credential fields by walking Config, which is "+
			"fewer than exist; this test is not looking where it thinks it is: %v",
			len(found), found)
	}
	for tag, where := range found {
		if !watched[tag] {
			t.Errorf("%s is a secret.Secret and %q is not in secretFields, so a "+
				"credential pasted into the config file by hand would sit there "+
				"readable and nothing would report it", where, tag)
		}
	}
}

// collectSecretTags returns json tag -> where it was found, for every
// secret.Secret in the tree.
func collectSecretTags(t *testing.T, typ reflect.Type, path []string,
	seen map[reflect.Type]bool) map[string]string {

	t.Helper()
	out := map[string]string{}
	secretType := reflect.TypeOf(secret.Secret(""))

	for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Map {
		typ = typ.Elem()
		for typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
	}
	if typ.Kind() != reflect.Struct {
		return out
	}
	// Recursion guard: a config type that contains itself would otherwise
	// hang the suite rather than fail it.
	if seen[typ] {
		return out
	}
	seen[typ] = true
	defer delete(seen, typ)

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" {
			continue // unexported, never serialised
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			tag = strings.ToLower(f.Name)
		}
		where := strings.Join(append(append([]string{}, path...), f.Name), ".")

		if f.Type == secretType {
			out[tag] = where
			continue
		}
		for k, v := range collectSecretTags(t, f.Type, append(path, f.Name), seen) {
			if _, dup := out[k]; !dup {
				out[k] = v
			}
		}
	}
	return out
}

// And the detector actually reports each of them, which the reflection walk
// above does not prove: a name in the list that the regex cannot match is the
// same gap with extra steps.
func TestTheDetectorReportsEveryFieldItClaimsToWatch(t *testing.T) {
	var b strings.Builder
	for _, f := range secretFields {
		b.WriteString("  " + f + ": a-plain-value\n")
	}
	got := PlaintextSecrets([]byte(b.String()))

	reported := map[string]bool{}
	for _, f := range got {
		reported[f] = true
	}
	for _, f := range secretFields {
		if !reported[f] {
			t.Errorf("%q is in secretFields and the detector did not report it "+
				"in plain text", f)
		}
	}
}

// A PROTECTED VALUE IS NOT REPORTED, or the warning is noise and gets ignored.
func TestAProtectedValueIsNotReportedAsPlaintext(t *testing.T) {
	var b strings.Builder
	for _, f := range secretFields {
		b.WriteString("  " + f + ": " + secret.PrefixDPAPI + "abc\n")
	}
	if got := PlaintextSecrets([]byte(b.String())); len(got) != 0 {
		t.Errorf("reported protected values as plaintext: %v", got)
	}
}
