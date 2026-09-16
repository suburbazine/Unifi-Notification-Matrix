package probe

import "crypto/tls"

// tlsConfig builds the probe's TLS settings.
//
// insecureSkipVerify is ordinary here: UniFi consoles ship self-signed
// certificates, and a probe that refused to talk to one would refuse to talk
// to almost every console it exists for. It is safe in a way it would not be
// elsewhere, because the dialer has already guaranteed the peer is on a local
// network -- the thing certificate verification would be protecting against
// (talking to a stranger on the internet) cannot happen.
func tlsConfig(insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // see above
		MinVersion:         tls.VersionTLS12,
	}
}
