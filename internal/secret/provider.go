package secret

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Prefixes. These are a wire format: once a config has been written with one,
// this build and every later build must still read it.
const (
	PrefixDPAPI   = "dpapi:"
	PrefixSDCreds = "sdcreds:"
	PrefixTPM2    = "tpm2:"
	PrefixAgeKey  = "agekey:"
	PrefixPlain   = "plain:"
)

// Provider protects and unprotects values using one platform mechanism.
//
// Availability is deliberately separate from Protect: a provider that cannot
// work here must say so *before* anything is written, so the tier below it can
// be chosen and recorded. A provider that fails only at write time leaves a
// half-written config.
type Provider interface {
	// Prefix is the stored marker. Stable forever once shipped.
	Prefix() string

	// Mechanism is the human name used in operator-facing messages.
	Mechanism() string

	// Available reports whether this mechanism can be used on this machine
	// right now. The reason is shown in diagnostics when it cannot, so it must
	// be specific enough to act on -- "systemd-creds not on PATH" rather than
	// "unavailable".
	Available() (bool, string)

	// MachineBound reports whether a copy of the config, taken to another
	// machine, is useless there. This is the property being matched from DPAPI
	// machine scope, and it is what separates the real tiers from the fallback.
	MachineBound() bool

	Protect(plaintext []byte) ([]byte, error)
	Unprotect(blob []byte) ([]byte, error)
}

// providers is the platform's chain, best first. Set by the platform file in
// an init function.
var providers []Provider

// allowPlaintext gates the plain: provider. It is NEVER selected automatically:
// on a machine where every real mechanism is unavailable, refusing to write is
// better than silently storing an API key in a readable file, because the
// operator can act on a refusal and cannot act on a silence.
//
// Development builds and tests opt in explicitly.
var (
	mu             sync.RWMutex
	allowPlaintext bool
)

// AllowPlaintext permits the plain: mechanism to be selected when nothing
// better is available. Intended for development and for tests.
func AllowPlaintext(allow bool) {
	mu.Lock()
	defer mu.Unlock()
	allowPlaintext = allow
}

// ErrNoProvider means nothing on this machine can protect a secret and
// plaintext has not been permitted.
var ErrNoProvider = errors.New("no usable secret-protection mechanism")

// SelectWriter returns the best available provider for writing.
//
// Availability probes may be cached by the provider -- the systemd tier shells
// out to three helpers, and MarshalJSON calls this once per secret, so probing
// every time would spawn a dozen processes to save one config. Call Rescan
// when the machine may have changed underneath a running service: a TPM passed
// through, a systemd upgrade, or a state directory created by a packaging step
// that ran after first launch.
func SelectWriter() (Provider, error) {
	mu.RLock()
	allowPlain := allowPlaintext
	mu.RUnlock()

	var why []string
	for _, p := range providers {
		if p.Prefix() == PrefixPlain && !allowPlain {
			why = append(why, "plaintext: not permitted (this is deliberate)")
			continue
		}
		ok, reason := p.Available()
		if ok {
			return p, nil
		}
		why = append(why, p.Mechanism()+": "+reason)
	}
	return nil, fmt.Errorf("%w on this machine.\n  %s", ErrNoProvider, strings.Join(why, "\n  "))
}

// Rescan discards cached availability probes so the next SelectWriter reflects
// the machine as it is now.
func Rescan() {
	for _, p := range providers {
		if r, ok := p.(rescanner); ok {
			r.rescan()
		}
	}
}

type rescanner interface{ rescan() }

func providerFor(prefix string) Provider {
	for _, p := range providers {
		if p.Prefix() == prefix {
			return p
		}
	}
	return nil
}

// Status is one line of the diagnostics report: can this mechanism be used
// here, and if not, why not.
type Status struct {
	Mechanism    string
	Prefix       string
	Available    bool
	Reason       string
	MachineBound bool
}

// Report describes every mechanism this build knows, in preference order.
// The selfcheck surface renders it so that "why is it storing secrets in the
// weak tier" is answerable without reading the source.
func Report() []Status {
	out := make([]Status, 0, len(providers))
	for _, p := range providers {
		ok, reason := p.Available()
		if p.Prefix() == PrefixPlain {
			mu.RLock()
			allowed := allowPlaintext
			mu.RUnlock()
			if !allowed {
				ok, reason = false, "not permitted (this is deliberate)"
			}
		}
		out = append(out, Status{
			Mechanism:    p.Mechanism(),
			Prefix:       p.Prefix(),
			Available:    ok,
			Reason:       reason,
			MachineBound: p.MachineBound(),
		})
	}
	return out
}
