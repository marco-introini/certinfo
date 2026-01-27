package privatekey

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

type KeyInfo struct {
	Filename  string
	KeyType   string
	Algorithm string
	Bits      int
	Curve     string
}

type KeySummary struct {
	Filename string
	KeyType  string
	Bits     int
	Curve    string
}

func ParsePrivateKey(filePath string) (*KeyInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in %s", filePath)
	}

	return parseKey(block.Bytes, filePath)
}

func ParsePrivateKeyFromBytes(data []byte, filename string) (*KeyInfo, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	return parseKey(block.Bytes, filename)
}

func parseKey(der []byte, filename string) (*KeyInfo, error) {
	info := &KeyInfo{Filename: filename}

	key, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		info.KeyType = "RSA"
		info.Bits = key.N.BitLen()
		info.Algorithm = "PKCS#1 v1.5"
		return info, nil
	}

	rsaKey, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		if key, ok := rsaKey.(*rsa.PrivateKey); ok {
			info.KeyType = "RSA"
			info.Bits = key.N.BitLen()
			info.Algorithm = "PKCS#8"
			return info, nil
		}
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
		switch any(pkcs8Key).(type) {
		case ed25519.PrivateKey:
			info.KeyType = "Ed25519"
			info.Bits = 256
			info.Algorithm = "EdDSA"
			return info, nil
		}
	}

	info.KeyType = fmt.Sprintf("%T", pkcs8Key)
	return info, nil
}

func SummarizeDirectory(dirPath string) ([]KeySummary, error) {
	var summaries []KeySummary

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())

		key, err := ParsePrivateKey(filePath)
		if err != nil {
			continue
		}

		summary := KeySummary{
			Filename: entry.Name(),
			KeyType:  key.KeyType,
			Bits:     key.Bits,
			Curve:    key.Curve,
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func SummarizeDirectoryRecursive(dirPath string) ([]KeySummary, error) {
	var summaries []KeySummary

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

		summary := KeySummary{
			Filename: relPath,
			KeyType:  key.KeyType,
			Bits:     key.Bits,
			Curve:    key.Curve,
		}

		summaries = append(summaries, summary)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summaries, nil
}
