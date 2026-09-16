//go:build !windows && !linux

package secret

// Platforms other than Windows and Linux -- macOS, the BSDs -- are not shipping
// targets (ARCHITECTURE.md §10 names windows/amd64, linux/amd64, linux/arm64).
// They are supported here only so that the package builds and tests on a
// developer's machine.
//
// The key-file tier works on any Unix, so a developer gets real encryption
// rather than a plaintext fallback. macOS Keychain would be the right answer if
// macOS ever became a target; it is deliberately not stubbed in, because an
// empty Keychain provider that silently degrades is exactly the kind of
// protection-claiming-to-exist this package is built to prevent.
func init() {
	providers = []Provider{ageKeyProvider{}, plainProvider{}}
}
