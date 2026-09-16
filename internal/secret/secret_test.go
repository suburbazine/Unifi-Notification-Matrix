package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// useRealProvider points the key-file tier at a temp directory so the test
// exercises whatever this platform actually ships, rather than a stub.
func useRealProvider(t *testing.T) {
	t.Helper()
	SetKeyFile(filepath.Join(t.TempDir(), "secret.key"))
}

const canary = "unifi-api-key-do-not-log-me"

type holder struct {
	APIKey Secret `json:"api_key"`
	Note   string `json:"note"`
}

// A Secret must be unable to reach a log line by accident. This is the whole
// reason the type exists rather than a plain string.
func TestSecretNeverRendersItself(t *testing.T) {
	s := Secret(canary)

	for name, got := range map[string]string{
		"String":  s.String(),
		"%v":      fmt.Sprintf("%v", s),
		"%s":      fmt.Sprintf("%s", s),
		"%q":      fmt.Sprintf("%q", s),
		"struct":  fmt.Sprintf("%v", holder{APIKey: s, Note: "n"}),
		"struct+": fmt.Sprintf("%+v", holder{APIKey: s, Note: "n"}),
	} {
		if strings.Contains(got, canary) {
			t.Errorf("%s leaked the secret: %s", name, got)
		}
	}

	if s.Reveal() != canary {
		t.Error("Reveal must return the plaintext")
	}
	if Secret("").String() != "" {
		t.Error("an empty secret should render empty, not <redacted>")
	}
}

func TestRoundTripThroughRealProvider(t *testing.T) {
	useRealProvider(t)

	p, err := SelectWriter()
	if err != nil {
		t.Skipf("no protection mechanism available here: %v", err)
	}
	t.Logf("using %s (machine-bound=%v)", p.Mechanism(), p.MachineBound())

	in := holder{APIKey: Secret(canary), Note: "hello"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The encoded form must not contain the plaintext, and must say how it was
	// protected.
	if strings.Contains(string(b), canary) {
		t.Fatalf("the stored form contains the plaintext: %s", b)
	}
	if !strings.Contains(string(b), p.Prefix()) {
		t.Errorf("stored form does not record the mechanism %q: %s", p.Prefix(), b)
	}

	var out holder
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.APIKey.Reveal() != canary {
		t.Errorf("round trip lost the value: %q", out.APIKey.Reveal())
	}
}

func TestEmptySecretRoundTrips(t *testing.T) {
	useRealProvider(t)
	b, err := json.Marshal(holder{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out holder
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.APIKey.IsZero() {
		t.Error("an empty secret must survive a round trip as empty")
	}
}

// Plaintext must never be chosen for us. On a machine where nothing else
// works, refusing to write is better than silently storing an API key in a
// readable file: the operator can act on a refusal and cannot act on silence.
func TestPlaintextIsNeverSelectedAutomatically(t *testing.T) {
	for _, p := range providers {
		if p.Prefix() != PrefixPlain {
			continue
		}
		if ok, _ := p.Available(); !ok {
			t.Fatal("the plain provider should report itself available; " +
				"the gate belongs in SelectWriter, not in Available")
		}
	}

	// With plaintext disallowed (the default), SelectWriter must never return
	// it even though it is always available.
	AllowPlaintext(false)
	if p, err := SelectWriter(); err == nil && p.Prefix() == PrefixPlain {
		t.Fatal("SelectWriter chose plaintext without being permitted to")
	}
}

func TestPlaintextIsHonestWhenPermitted(t *testing.T) {
	AllowPlaintext(true)
	t.Cleanup(func() { AllowPlaintext(false) })

	// Force the plain tier by name rather than hoping it is selected.
	p := providerFor(PrefixPlain)
	if p == nil {
		t.Fatal("no plain provider registered")
	}
	blob, err := p.Protect([]byte(canary))
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if string(blob) != canary {
		t.Error("the plain provider must not transform the value")
	}
	if p.MachineBound() {
		t.Error("the plain provider must not claim to be machine-bound")
	}
	if !strings.Contains(strings.ToLower(p.Mechanism()), "not encrypted") {
		t.Errorf("Mechanism() = %q; it must say plainly that it does not "+
			"encrypt, because that string is what an operator reads", p.Mechanism())
	}
}

// A value with no recognised prefix is accepted as something a human typed.
//
// Deliberate. The config file is the source of truth and is meant to be
// editable, so refusing a pasted API key for lacking a "dpapi:" prefix would
// mean the only way to bootstrap is a UI that may not be running yet. The
// caller reports it (config.PlaintextSecrets) and the next save encrypts it.
func TestAValueWithNoPrefixIsTakenAsHandEnteredPlaintext(t *testing.T) {
	for _, stored := range []string{`"a-pasted-api-key"`, `"key-with:a-colon"`} {
		var s Secret
		if err := json.Unmarshal([]byte(stored), &s); err != nil {
			t.Errorf("Unmarshal(%s) = %v, want it accepted as plaintext", stored, err)
		}
	}
}

// THE PROPERTY THAT MAKES THE ABOVE SAFE.
//
// Being permissive about unprefixed values must never mask a real decryption
// failure. A value that WAS encrypted always carries its prefix, so a damaged
// or foreign blob still has one, still reaches the decrypt path, and still
// reports as undecryptable rather than being silently handed back as if it
// were a password somebody typed.
func TestADamagedBlobStillFailsRatherThanBeingTakenAsPlaintext(t *testing.T) {
	useRealProvider(t)
	p, err := SelectWriter()
	if err != nil {
		t.Skipf("no secret mechanism available here: %v", err)
	}
	stored := fmt.Sprintf("%q", p.Prefix()+"bm90LWEtcmVhbC1ibG9i")

	var s Secret
	err = json.Unmarshal([]byte(stored), &s)
	if err == nil {
		t.Fatalf("a damaged %s blob was accepted; it would have been used as if "+
			"the ciphertext were the credential", p.Prefix())
	}
	var ue *UnprotectError
	if !errors.As(err, &ue) {
		t.Fatalf("error is %T, want *UnprotectError", err)
	}
}

// A config carried from another machine must report as FOREIGN, not as
// corrupt. When the decrypt error escapes unchanged, the caller reports it as
// a parse failure and the operator goes looking for the wrong problem.
func TestUndecryptableValueIsNotAParseError(t *testing.T) {
	useRealProvider(t)

	p, err := SelectWriter()
	if err != nil {
		t.Skipf("no protection mechanism available here: %v", err)
	}
	// Valid base64, right prefix, but not something this machine can open.
	stored := fmt.Sprintf("%q", p.Prefix()+"bm90LWEtcmVhbC1ibG9i")

	var s Secret
	err = json.Unmarshal([]byte(stored), &s)
	if err == nil {
		t.Fatal("expected a decrypt failure")
	}

	var ue *UnprotectError
	if !errors.As(err, &ue) {
		t.Fatalf("error is %T (%v), want *UnprotectError so the caller can "+
			"distinguish a foreign config from a malformed one", err, err)
	}
	if !strings.Contains(ue.Error(), "re-entered") {
		t.Errorf("the message must tell the operator what to do; got: %v", ue)
	}
}

func TestReportCoversEveryMechanism(t *testing.T) {
	rep := Report()
	if len(rep) != len(providers) {
		t.Fatalf("Report() has %d entries, want %d", len(rep), len(providers))
	}
	for _, s := range rep {
		if s.Mechanism == "" || s.Prefix == "" {
			t.Errorf("incomplete status: %+v", s)
		}
		if !s.Available && s.Reason == "" {
			t.Errorf("%s is unavailable with no reason; the reason is what "+
				"makes the diagnostics actionable", s.Mechanism)
		}
	}
}
