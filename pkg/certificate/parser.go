package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marco-introini/certinfo/pkg/pem"
)

type CertificateInfo struct {
	Filename      string
	Encoding      string
	CommonName    string
	Issuer        string
	Subject       string
	NotBefore     time.Time
	NotAfter      time.Time
	Algorithm     string
	KeyType       string
	Bits          int
	SerialNumber  string
	SANs          []string
	IsCA          bool
	IsQuantumSafe bool
	PQCTypes      []string
}

func getKeyBitsAndType(pub any) (string, int) {
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
	default:
		return fmt.Sprintf("%T", pub), 0
	}
}

func isPQCSignatureAlgorithmByName(algoName string) bool {
	lowerAlgo := strings.ToLower(algoName)
	return strings.Contains(lowerAlgo, "ml-dsa") ||
		strings.Contains(lowerAlgo, "slh-dsa") ||
		strings.Contains(lowerAlgo, "fn-dsa") ||
		strings.Contains(lowerAlgo, "falcon") ||
		strings.Contains(lowerAlgo, "rainbow") ||
		strings.Contains(lowerAlgo, " sphincs") ||
		strings.Contains(lowerAlgo, "dilithium") ||
		strings.Contains(lowerAlgo, "kyber")
}

func getPQCTypesFromAlgorithmName(algoName string) []string {
	var pqcTypes []string
	lowerAlgo := strings.ToLower(algoName)

	if strings.Contains(lowerAlgo, "ml-dsa-44") || strings.Contains(lowerAlgo, "dilithium2") {
		pqcTypes = append(pqcTypes, "ML-DSA-44")
	}
	if strings.Contains(lowerAlgo, "ml-dsa-45") || strings.Contains(lowerAlgo, "dilithium3") {
		pqcTypes = append(pqcTypes, "ML-DSA-65")
	}
	if strings.Contains(lowerAlgo, "ml-dsa-87") || strings.Contains(lowerAlgo, "dilithium5") {
		pqcTypes = append(pqcTypes, "ML-DSA-87")
	}
	if strings.Contains(lowerAlgo, "slh-dsa") || strings.Contains(lowerAlgo, "sphincs") {
		if strings.Contains(lowerAlgo, "128") {
			pqcTypes = append(pqcTypes, "SLH-DSA-128")
		} else if strings.Contains(lowerAlgo, "192") {
			pqcTypes = append(pqcTypes, "SLH-DSA-192")
		} else if strings.Contains(lowerAlgo, "256") {
			pqcTypes = append(pqcTypes, "SLH-DSA-256")
		} else {
			pqcTypes = append(pqcTypes, "SLH-DSA")
		}
	}
	if strings.Contains(lowerAlgo, "fn-dsa") || strings.Contains(lowerAlgo, "falcon") {
		if strings.Contains(lowerAlgo, "128") {
			pqcTypes = append(pqcTypes, "FN-DSA-128")
		} else if strings.Contains(lowerAlgo, "192") {
			pqcTypes = append(pqcTypes, "FN-DSA-192")
		} else if strings.Contains(lowerAlgo, "256") {
			pqcTypes = append(pqcTypes, "FN-DSA-256")
		} else {
			pqcTypes = append(pqcTypes, "FN-DSA")
		}
	}
	if strings.Contains(lowerAlgo, "ml-kem") || strings.Contains(lowerAlgo, "kyber") {
		if strings.Contains(lowerAlgo, "768") || strings.Contains(lowerAlgo, "512") {
			pqcTypes = append(pqcTypes, "ML-KEM-768")
		} else if strings.Contains(lowerAlgo, "1024") || strings.Contains(lowerAlgo, "1024") {
			pqcTypes = append(pqcTypes, "ML-KEM-1024")
		} else {
			pqcTypes = append(pqcTypes, "ML-KEM")
		}
	}
	return pqcTypes
}

func parseCertificateData(data []byte, filePath string) (*CertificateInfo, error) {
	var cert *x509.Certificate
	var encoding string

	if pem.IsPEM(data) {
		certBytes, ok := pem.FindBlock(data, pem.TypeCertificate)
		if !ok {
			return nil, fmt.Errorf("no certificate found in %s", filePath)
		}
		var err error
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		encoding = "PEM"
	} else {
		var err error
		cert, err = x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		encoding = "DER"
	}

	algoName := cert.SignatureAlgorithm.String()

	info := &CertificateInfo{
		Filename:      filePath,
		Encoding:      encoding,
		CommonName:    cert.Subject.CommonName,
		Issuer:        cert.Issuer.CommonName,
		Subject:       cert.Subject.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		Algorithm:     algoName,
		SerialNumber:  cert.SerialNumber.String(),
		IsCA:          cert.IsCA,
		IsQuantumSafe: isPQCSignatureAlgorithmByName(algoName),
		PQCTypes:      getPQCTypesFromAlgorithmName(algoName),
	}
	info.KeyType, info.Bits = getKeyBitsAndType(cert.PublicKey)

	if len(cert.DNSNames) > 0 {
		info.SANs = cert.DNSNames
	}

	return info, nil
}

func ParseCertificate(filePath string) (*CertificateInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return parseCertificateData(data, filePath)
}

func ParseCertificateFromBytes(data []byte) (*CertificateInfo, error) {
	return parseCertificateData(data, "")
}
