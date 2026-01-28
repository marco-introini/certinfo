package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/marco-introini/certinfo/pkg/pem"
)

type CertificateInfo struct {
	Filename     string
	Encoding     string
	CommonName   string
	Issuer       string
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	Algorithm    string
	KeyType      string
	Bits         int
	SerialNumber string
	SANs         []string
	IsCA         bool
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

	info := &CertificateInfo{
		Filename:     filePath,
		Encoding:     encoding,
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Algorithm:    cert.SignatureAlgorithm.String(),
		SerialNumber: cert.SerialNumber.String(),
		IsCA:         cert.IsCA,
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
