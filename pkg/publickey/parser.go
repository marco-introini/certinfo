package publickey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/marco-introini/certinfo/pkg/pem"
)

// PublicKeyInfo contains metadata extracted from a public key file.
type PublicKeyInfo struct {
	Filename      string
	Encoding      string
	KeyType       string
	Algorithm     string
	Bits          int
	Curve         string
	IsQuantumSafe bool
	IsWeak        bool
	WeakReasons   []string
}

func getKeyTypeAndBits(pub any) (string, int) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", key.N.BitLen()
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return "ECDSA", 256
		case elliptic.P384():
			return "ECDSA", 384
		case elliptic.P521():
			return "ECDSA", 521
		default:
			return "ECDSA", key.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		typeName := fmt.Sprintf("%T", pub)
		if strings.Contains(typeName, "mldsa") {
			return "ML-DSA", 0
		}
		if strings.Contains(typeName, "mlkem") {
			return "ML-KEM", 0
		}
		return typeName, 0
	}
}

func parsePublicKeyData(data []byte, filename string) (*PublicKeyInfo, error) {
	var pub any
	var encoding string

	if pem.IsPEM(data) {
		block, _ := pem.FindBlock(data, pem.TypePublicKey, pem.TypeRSAPublicKey, pem.TypeECPublicKey)
		if block == nil {
			return nil, fmt.Errorf("no public key found in %s", filename)
		}

		var err error
		pub, err = x509.ParsePKIXPublicKey(block)
		if err != nil {
			pub, err = x509.ParsePKCS1PublicKey(block)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		}
		encoding = "PEM"
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(data)
		if err != nil {
			pub, err = x509.ParsePKCS1PublicKey(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		}
		encoding = "DER"
	}

	info := &PublicKeyInfo{
		Filename: filename,
		Encoding: encoding,
	}
	info.KeyType, info.Bits = getKeyTypeAndBits(pub)

	switch key := pub.(type) {
	case *rsa.PublicKey:
		info.Algorithm = "RSA"
	case *ecdsa.PublicKey:
		info.Algorithm = "ECDSA"
		info.Curve = key.Curve.Params().Name
	case ed25519.PublicKey:
		info.Algorithm = "EdDSA"
	default:
		info.Algorithm = "Unknown"
	}

	if isPQCKeyType(info.KeyType) {
		info.IsQuantumSafe = true
	}

	info.evaluateWeakness()
	return info, nil
}

func isPQCKeyType(keyType string) bool {
	lower := strings.ToLower(keyType)
	return strings.Contains(lower, "ml-dsa") ||
		strings.Contains(lower, "ml-kem") ||
		strings.Contains(lower, "slh-dsa") ||
		strings.Contains(lower, "fn-dsa")
}

func (k *PublicKeyInfo) evaluateWeakness() {
	if k.KeyType == "RSA" && k.Bits < 2048 {
		k.IsWeak = true
		k.WeakReasons = append(k.WeakReasons, fmt.Sprintf("RSA key size %d is below 2048 bits", k.Bits))
	}
	if k.KeyType == "ECDSA" && k.Bits < 256 {
		k.IsWeak = true
		k.WeakReasons = append(k.WeakReasons, fmt.Sprintf("ECDSA curve size %d is below 256 bits", k.Bits))
	}
}

// ParsePublicKey parses a public key file and returns its metadata.
func ParsePublicKey(filePath string) (*PublicKeyInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return parsePublicKeyData(data, filePath)
}

// ParsePublicKeyFromBytes parses a public key from raw bytes.
func ParsePublicKeyFromBytes(data []byte, filename string) (*PublicKeyInfo, error) {
	return parsePublicKeyData(data, filename)
}
