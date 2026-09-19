//go:build !windows

package update

import "fmt"

// CanVerifyPublisher reports whether this platform can pin a replacement to
// the publisher of the binary already installed.
//
// False here, and that is a statement about the platform rather than a
// shortcut. Authenticode is what carries the publisher identity for these
// releases; there is no equivalent for a bare ELF binary, and the sigstore
// bundle published alongside it needs a verifier this program does not embed.
func CanVerifyPublisher() bool { return false }

// VerifyPublisher refuses to pretend.
//
// The checksum check upstream proves the download matches the manifest
// published with it -- which catches corruption, and catches nothing at all
// about an attacker able to serve both files. Installing on that basis, inside
// a program that watches somebody's cameras and doors, would be the weakest
// link in the whole product wearing the word "verified".
//
// So: no self-replacement on this platform. The update is reported, and
// verifying it is a documented two-command job with cosign, which checks the
// signing identity properly.
func VerifyPublisher(candidate, installed string) error {
	return fmt.Errorf("update: this build cannot check who signed a replacement, " +
		"so it will not install one. Verify the download with cosign (see " +
		"docs/RELEASING.md) and replace the binary yourself")
}

// SignerOf cannot answer on this platform.
//
// There is no Authenticode for an ELF binary, and the sigstore bundle
// published beside a release is not installed alongside it and would need a
// verifier this program does not embed. Returning ErrNoPublisherIdentity
// rather than an empty string is deliberate: a caller must be able to tell
// "this file is unsigned" from "this platform cannot tell you", because only
// the first of those is a finding.
func SignerOf(path string) (string, error) {
	return "", fmt.Errorf("%w", ErrNoPublisherIdentity)
}
