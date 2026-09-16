package secret

// plainProvider does not encrypt. It exists so that a build which genuinely
// cannot protect a secret can still say so honestly in the file, rather than
// writing a value under a prefix that claims protection it does not have.
//
// It is never selected automatically -- see SelectWriter and AllowPlaintext.
type plainProvider struct{}

func (plainProvider) Prefix() string    { return PrefixPlain }
func (plainProvider) Mechanism() string { return "plaintext (NOT ENCRYPTED)" }

func (plainProvider) Available() (bool, string) {
	return true, "always available; stores secrets unencrypted"
}

// MachineBound is false, and that is the whole point of the honest prefix: a
// config written this way is readable anywhere it is copied.
func (plainProvider) MachineBound() bool { return false }

func (plainProvider) Protect(plaintext []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, nil
}

func (plainProvider) Unprotect(blob []byte) ([]byte, error) {
	out := make([]byte, len(blob))
	copy(out, blob)
	return out, nil
}
