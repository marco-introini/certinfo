package certificate

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type CertificateInfo struct {
	Filename     string
	CommonName   string
	Issuer       string
	Subject      string
	NotBefore    string
	NotAfter     string
	Algorithm    string
	Bits         int
	SerialNumber string
	SANs         []string
	IsCA         bool
}

func ParseCertificate(filePath string) (*CertificateInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in %s", filePath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	info := &CertificateInfo{
		Filename:     filePath,
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05"),
		Algorithm:    cert.SignatureAlgorithm.String(),
		Bits:         cert.PublicKey.(*rsa.PublicKey).Size() * 8,
		SerialNumber: cert.SerialNumber.String(),
		IsCA:         cert.IsCA,
	}

	if len(cert.DNSNames) > 0 {
		info.SANs = cert.DNSNames
	}

	return info, nil
}

func ParseCertificateFromBytes(data []byte) (*CertificateInfo, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	info := &CertificateInfo{
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05"),
		Algorithm:    cert.SignatureAlgorithm.String(),
		Bits:         cert.PublicKey.(*rsa.PublicKey).Size() * 8,
		SerialNumber: cert.SerialNumber.String(),
		IsCA:         cert.IsCA,
	}

	if len(cert.DNSNames) > 0 {
		info.SANs = cert.DNSNames
	}

	return info, nil
}
