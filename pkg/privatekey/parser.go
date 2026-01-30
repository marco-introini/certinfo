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
	"strings"

	"github.com/marco-introini/certinfo/pkg/pem"
)

type KeyInfo struct {
	Filename      string
	Encoding      string
	KeyType       string
	Algorithm     string
	Bits          int
	Curve         string
	IsQuantumSafe bool
}

type KeySummary struct {
	Filename      string
	Encoding      string
	KeyType       string
	Bits          int
	Curve         string
	IsQuantumSafe bool
}

func isPQCCheck(algo string) bool {
	lowerAlgo := strings.ToLower(algo)
	return strings.Contains(lowerAlgo, "ml-kem") ||
		strings.Contains(lowerAlgo, "ml-dsa") ||
		strings.Contains(lowerAlgo, "slh-dsa") ||
		strings.Contains(lowerAlgo, "fn-dsa") ||
		strings.Contains(lowerAlgo, "falcon") ||
		strings.Contains(lowerAlgo, "dilithium") ||
		strings.Contains(lowerAlgo, "kyber") ||
		strings.Contains(lowerAlgo, "sphincs") ||
		strings.Contains(lowerAlgo, "rainbow")
}

func detectPQCFromText(data []byte) []string {
	var pqcTypes []string
	dataStr := string(data)
	if strings.Contains(dataStr, "ML-DSA-44") || strings.Contains(dataStr, "MLDSA44") {
		pqcTypes = append(pqcTypes, "ML-DSA-44")
	}
	if strings.Contains(dataStr, "ML-DSA-65") || strings.Contains(dataStr, "MLDSA65") {
		pqcTypes = append(pqcTypes, "ML-DSA-65")
	}
	if strings.Contains(dataStr, "ML-DSA-87") || strings.Contains(dataStr, "MLDSA87") {
		pqcTypes = append(pqcTypes, "ML-DSA-87")
	}
	if strings.Contains(dataStr, "ML-KEM-512") || strings.Contains(dataStr, "MLKEM512") {
		pqcTypes = append(pqcTypes, "ML-KEM-512")
	}
	if strings.Contains(dataStr, "ML-KEM-768") || strings.Contains(dataStr, "MLKEM768") {
		pqcTypes = append(pqcTypes, "ML-KEM-768")
	}
	if strings.Contains(dataStr, "ML-KEM-1024") || strings.Contains(dataStr, "MLKEM1024") {
		pqcTypes = append(pqcTypes, "ML-KEM-1024")
	}
	if strings.Contains(dataStr, "SLH-DSA-SHA2-128S") {
		pqcTypes = append(pqcTypes, "SLH-DSA-SHA2-128S")
	}
	if strings.Contains(dataStr, "SLH-DSA-SHA2-128F") {
		pqcTypes = append(pqcTypes, "SLH-DSA-SHA2-128F")
	}
	if strings.Contains(dataStr, "SLH-DSA-SHA2-192S") {
		pqcTypes = append(pqcTypes, "SLH-DSA-SHA2-192S")
	}
	if strings.Contains(dataStr, "SLH-DSA-SHA2-192F") {
		pqcTypes = append(pqcTypes, "SLH-DSA-SHA2-192F")
	}
	if strings.Contains(dataStr, "SLH-DSA-SHA2-256S") {
		pqcTypes = append(pqcTypes, "SLH-DSA-SHA2-256S")
	}
	if strings.Contains(dataStr, "SLH-DSA-SHA2-256F") {
		pqcTypes = append(pqcTypes, "SLH-DSA-SHA2-256F")
	}
	if strings.Contains(dataStr, "FALCON-512") {
		pqcTypes = append(pqcTypes, "FALCON-512")
	}
	if strings.Contains(dataStr, "FALCON-1024") {
		pqcTypes = append(pqcTypes, "FALCON-1024")
	}
	return pqcTypes
}

func detectPQCFromOID(oid string) string {
	oidMap := map[string]string{
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
		"2.16.840.1.101.3.4.3.20": "ML-KEM-512",
		"2.16.840.1.101.3.4.3.21": "ML-KEM-768",
		"2.16.840.1.101.3.4.3.22": "ML-KEM-1024",
		"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-128S",
		"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-128F",
		"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-192S",
		"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHA2-192F",
		"2.16.840.1.101.3.4.3.27": "SLH-DSA-SHA2-256S",
		"2.16.840.1.101.3.4.3.28": "SLH-DSA-SHA2-256F",
		"2.16.840.1.101.3.4.3.29": "FALCON-512",
		"2.16.840.1.101.3.4.3.30": "FALCON-1024",
	}
	return oidMap[oid]
}

func detectPQCOIDFromError(errMsg string) string {
	for oid, name := range map[string]string{
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
		"2.16.840.1.101.3.4.4.1":  "ML-KEM-512",
		"2.16.840.1.101.3.4.4.2":  "ML-KEM-768",
		"2.16.840.1.101.3.4.4.3":  "ML-KEM-1024",
		"2.16.840.1.101.3.4.3.20": "ML-KEM-512",
		"2.16.840.1.101.3.4.3.21": "ML-KEM-768",
		"2.16.840.1.101.3.4.3.22": "ML-KEM-1024",
		"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-128S",
		"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-128F",
		"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-192S",
		"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHA2-192F",
		"2.16.840.1.101.3.4.3.27": "SLH-DSA-SHA2-256S",
		"2.16.840.1.101.3.4.3.28": "SLH-DSA-SHA2-256F",
		"2.16.840.1.101.3.4.3.29": "FALCON-512",
		"2.16.840.1.101.3.4.3.30": "FALCON-1024",
	} {
		if strings.Contains(errMsg, oid) {
			return name
		}
	}
	return ""
}

func getPQCBits(pqcType string) int {
	bitMap := map[string]int{
		"ML-DSA-44":         44,
		"ML-DSA-65":         65,
		"ML-DSA-87":         87,
		"ML-KEM-512":        512,
		"ML-KEM-768":        768,
		"ML-KEM-1024":       1024,
		"SLH-DSA-SHA2-128S": 128,
		"SLH-DSA-SHA2-128F": 128,
		"SLH-DSA-SHA2-192S": 192,
		"SLH-DSA-SHA2-192F": 192,
		"SLH-DSA-SHA2-256S": 256,
		"SLH-DSA-SHA2-256F": 256,
		"FALCON-512":        512,
		"FALCON-1024":       1024,
	}
	return bitMap[pqcType]
}

func parsePrivateKeyData(data []byte, filename string) (*KeyInfo, error) {
	var keyBytes []byte
	var encoding string

	if pem.IsPEM(data) {
		var ok bool
		keyBytes, ok = pem.FindBlock(data,
			pem.TypeECPrivateKey,
			pem.TypePrivateKey,
			pem.TypeRSAPrivateKey,
			pem.TypeMLKEMPrivateKey,
			pem.TypeMLDSAPrivateKey)
		if !ok {
			return nil, fmt.Errorf("no private key found in %s", filename)
		}
		encoding = "PEM"
	} else {
		keyBytes = data
		encoding = "DER"
	}

	pqcTypes := detectPQCFromText(data)

	return parseKey(keyBytes, filename, encoding, pqcTypes)
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

func parseKey(der []byte, filename string, encoding string, pqcTypes []string) (*KeyInfo, error) {
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
		default:
			typeName := fmt.Sprintf("%T", key)
			info.KeyType = typeName
			info.Algorithm = "PKCS#8"
			if isPQCCheck(typeName) {
				info.IsQuantumSafe = true
				if strings.Contains(strings.ToLower(typeName), "mlkem") {
					info.KeyType = "ML-KEM"
					info.Algorithm = "ML-KEM"
					info.Bits = 0
				} else if strings.Contains(strings.ToLower(typeName), "mldsa") {
					info.KeyType = "ML-DSA"
					info.Algorithm = "ML-DSA"
					info.Bits = 0
				} else if strings.Contains(strings.ToLower(typeName), "slhdsa") {
					info.KeyType = "SLH-DSA"
					info.Algorithm = "SLH-DSA"
					info.Bits = 0
				} else if strings.Contains(strings.ToLower(typeName), "fndsa") {
					info.KeyType = "FN-DSA"
					info.Algorithm = "FN-DSA"
					info.Bits = 0
				}
			}
			for _, pqc := range pqcTypes {
				info.IsQuantumSafe = true
				info.Bits = getPQCBits(pqc)
				if strings.HasPrefix(pqc, "ML-DSA") {
					info.KeyType = "ML-DSA"
					info.Algorithm = "ML-DSA"
				} else if strings.HasPrefix(pqc, "ML-KEM") {
					info.KeyType = "ML-KEM"
					info.Algorithm = "ML-KEM"
				} else if strings.HasPrefix(pqc, "SLH-DSA") {
					info.KeyType = "SLH-DSA"
					info.Algorithm = "SLH-DSA"
				} else if strings.HasPrefix(pqc, "FALCON") {
					info.KeyType = "FALCON"
					info.Algorithm = "FALCON"
				}
			}
			return info, nil
		}
	}

	pqcOID := detectPQCOIDFromError(err.Error())
	if pqcOID != "" {
		info.IsQuantumSafe = true
		info.Algorithm = "PKCS#8"
		info.Bits = getPQCBits(pqcOID)
		if strings.HasPrefix(pqcOID, "ML-DSA") {
			info.KeyType = "ML-DSA"
		} else if strings.HasPrefix(pqcOID, "ML-KEM") {
			info.KeyType = "ML-KEM"
		} else if strings.HasPrefix(pqcOID, "SLH-DSA") {
			info.KeyType = "SLH-DSA"
		} else if strings.HasPrefix(pqcOID, "FALCON") {
			info.KeyType = "FALCON"
		}
		return info, nil
	}

	info.KeyType = fmt.Sprintf("%T", pkcs8Key)
	info.Algorithm = "Unknown"
	for _, pqc := range pqcTypes {
		info.IsQuantumSafe = true
		info.Bits = getPQCBits(pqc)
		if strings.HasPrefix(pqc, "ML-DSA") {
			info.KeyType = "ML-DSA"
			info.Algorithm = "ML-DSA"
		} else if strings.HasPrefix(pqc, "ML-KEM") {
			info.KeyType = "ML-KEM"
			info.Algorithm = "ML-KEM"
		} else if strings.HasPrefix(pqc, "SLH-DSA") {
			info.KeyType = "SLH-DSA"
			info.Algorithm = "SLH-DSA"
		} else if strings.HasPrefix(pqc, "FALCON") {
			info.KeyType = "FALCON"
			info.Algorithm = "FALCON"
		}
	}
	if info.KeyType == "<nil>" && len(pqcTypes) > 0 {
		info.IsQuantumSafe = true
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
			Filename:      entry.Name(),
			Encoding:      key.Encoding,
			KeyType:       key.KeyType,
			Bits:          key.Bits,
			Curve:         key.Curve,
			IsQuantumSafe: key.IsQuantumSafe,
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
			Filename:      relPath,
			Encoding:      key.Encoding,
			KeyType:       key.KeyType,
			Bits:          key.Bits,
			Curve:         key.Curve,
			IsQuantumSafe: key.IsQuantumSafe,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summaries, nil
}
