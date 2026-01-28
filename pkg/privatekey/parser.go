package privatekey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/marco-introini/certinfo/pkg/pem"
)

type KeyInfo struct {
	Filename  string
	Encoding  string
	KeyType   string
	Algorithm string
	Bits      int
	Curve     string
}

type KeySummary struct {
	Filename string
	Encoding string
	KeyType  string
	Bits     int
	Curve    string
}

func parsePrivateKeyData(data []byte, filename string) (*KeyInfo, error) {
	var keyBytes []byte
	var encoding string

	if pem.IsPEM(data) {
		var ok bool
		keyBytes, ok = pem.FindBlock(data,
			pem.TypeECPrivateKey,
			pem.TypePrivateKey,
			pem.TypeRSAPrivateKey)
		if !ok {
			return nil, fmt.Errorf("no private key found in %s", filename)
		}
		encoding = "PEM"
	} else {
		keyBytes = data
		encoding = "DER"
	}

	return parseKey(keyBytes, filename, encoding)
}

func ParsePrivateKey(filePath string) (*KeyInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return parsePrivateKeyData(data, filePath)
}

func ParsePrivateKeyFromBytes(data []byte, filename string) (*KeyInfo, error) {
	return parsePrivateKeyData(data, filename)
}

func parseKey(der []byte, filename string, encoding string) (*KeyInfo, error) {
	info := &KeyInfo{Filename: filename, Encoding: encoding}

	key, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		info.KeyType = "RSA"
		info.Bits = key.N.BitLen()
		info.Algorithm = "PKCS#1 v1.5"
		return info, nil
	}

	ecKey, err := x509.ParseECPrivateKey(der)
	if err == nil {
		info.KeyType = "EC"
		info.Bits = ecKey.Curve.Params().BitSize
		info.Curve = ecKey.Curve.Params().Name
		info.Algorithm = "ECDSA"
		return info, nil
	}

	pkcs8Key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		switch key := pkcs8Key.(type) {
		case *rsa.PrivateKey:
			info.KeyType = "RSA"
			info.Bits = key.N.BitLen()
			info.Algorithm = "PKCS#8"
			return info, nil
		case *ecdsa.PrivateKey:
			info.KeyType = "EC"
			info.Algorithm = "PKCS#8"
			switch key.Curve {
			case elliptic.P256():
				info.Bits = 256
				info.Curve = "P-256"
			case elliptic.P384():
				info.Bits = 384
				info.Curve = "P-384"
			case elliptic.P521():
				info.Bits = 521
				info.Curve = "P-521"
			default:
				info.Bits = key.Curve.Params().BitSize
				info.Curve = key.Curve.Params().Name
			}
			return info, nil
		case ed25519.PrivateKey:
			info.KeyType = "Ed25519"
			info.Bits = 256
			info.Algorithm = "EdDSA"
			return info, nil
		}
	}

	if pkcs8Key != nil {
		info.KeyType = fmt.Sprintf("%T", pkcs8Key)
	} else {
		info.KeyType = fmt.Sprintf("%T", pkcs8Key)
	}
	return info, nil
}

func SummarizeDirectory(dirPath string) ([]KeySummary, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	summaries := make([]KeySummary, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())

		key, err := ParsePrivateKey(filePath)
		if err != nil {
			continue
		}

		summaries = append(summaries, KeySummary{
			Filename: entry.Name(),
			Encoding: key.Encoding,
			KeyType:  key.KeyType,
			Bits:     key.Bits,
			Curve:    key.Curve,
		})
	}

	return summaries, nil
}

func SummarizeDirectoryRecursive(dirPath string) ([]KeySummary, error) {
	summaries := make([]KeySummary, 0, 32)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(dirPath, path)

		key, err := ParsePrivateKey(path)
		if err != nil {
			return nil
		}

		summaries = append(summaries, KeySummary{
			Filename: relPath,
			Encoding: key.Encoding,
			KeyType:  key.KeyType,
			Bits:     key.Bits,
			Curve:    key.Curve,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summaries, nil
}
