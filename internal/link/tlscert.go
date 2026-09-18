package link

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CertCommonName is what this product's Link certificate calls itself.
const CertCommonName = "notifymatrix-link"

// certLifetime is deliberately long.
//
// There is NO CA path here and no renewal story: the peer pins this exact
// certificate at pairing, so expiry would not be a security event, it would be
// an outage on a date nobody wrote down. A pin that has to be relearned on a
// schedule is a pin an operator learns to clear, and clearing a pin to make
// something work again is the trust-on-first-use relearn this product already
// calls strictly worse than no pin at all.
const certLifetime = 10 * 365 * 24 * time.Hour

// MintCertificate creates the self-signed certificate this product presents on
// the Link listener, returning it as PEM.
//
// ECDSA P-256 and standard library only. Self-signed on purpose: the peer
// trusts THIS certificate by fingerprint, learned during a pairing exchange
// that binds the fingerprint into its proof, so there is no certificate
// authority to satisfy and nothing an authority would add.
func MintCertificate(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("link: generating a key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("link: generating a serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: CertCommonName},
		// Backdated an hour so a peer whose clock is slightly behind does not
		// reject a certificate minted moments ago. The pin is what actually
		// establishes identity; these dates only have to not be in the way.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		// No DNS names or IP addresses. The peer does not verify the name --
		// it cannot, since this listener is reached by whatever address the
		// operator forwarded or typed -- it verifies the fingerprint. Listing
		// names here would imply a check nobody performs.
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("link: creating the certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("link: encoding the key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// TLSConfig builds the server configuration from a minted pair.
func TLSConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("link: loading the certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		// No client certificates. The peer authenticates every request with an
		// HMAC over its own body; a second identity at the transport layer
		// would be another key to pair, rotate and lose.
		ClientAuth: tls.NoClientCert,
	}, nil
}

// Fingerprint is the SHA-256 of the certificate's DER, as lowercase hex.
//
// This is the identity a peer pins and the value bound into the pairing proof,
// so it is computed from the DER rather than from anything a peer sends.
func Fingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("link: not a certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// NormaliseFingerprint accepts the shapes a human or another product might
// present -- colons, spaces, upper case -- and returns the canonical form.
func NormaliseFingerprint(v string) string {
	r := strings.NewReplacer(":", "", " ", "", "-", "")
	return strings.ToLower(strings.TrimSpace(r.Replace(v)))
}

// fingerprintDER is the pin computed from a certificate as it arrived on the
// wire, which is the only form a client can check it in.
func fingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
