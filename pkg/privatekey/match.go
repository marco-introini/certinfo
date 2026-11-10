package privatekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/marco-introini/certinfo/pkg/certificate"
)

// MatchesCertificate checks whether the private key corresponds to the
// public key embedded in the given certificate.
func (k *KeyInfo) MatchesCertificate(cert *certificate.CertificateInfo) (bool, string, error) {
	if k == nil || cert == nil {
		return false, "", fmt.Errorf("key and certificate are required")
	}
	if k.raw == nil {
		return false, "", fmt.Errorf("private key type %q is not supported for matching", k.KeyType)
	}

	switch priv := k.raw.(type) {
	case *rsa.PrivateKey:
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Sprintf("certificate key type is %s, private key is RSA", cert.KeyType), nil
		}
		if pub.N.Cmp(priv.N) == 0 {
			return true, "RSA public keys match", nil
		}
		return false, "RSA public keys do not match", nil

	case *ecdsa.PrivateKey:
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Sprintf("certificate key type is %s, private key is ECDSA", cert.KeyType), nil
		}
		if pub.Equal(&priv.PublicKey) {
			return true, "ECDSA public keys match", nil
		}
		return false, "ECDSA public keys do not match", nil

	case ed25519.PrivateKey:
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Sprintf("certificate key type is %s, private key is Ed25519", cert.KeyType), nil
		}
		if bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
			return true, "Ed25519 public keys match", nil
		}
		return false, "Ed25519 public keys do not match", nil

	default:
		return false, "", fmt.Errorf("unsupported private key type: %T", k.raw)
	}
}
