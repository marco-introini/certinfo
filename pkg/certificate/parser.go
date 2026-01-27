package certificate

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type CertificateInfo struct {
	Filename     string
	Encoding     string
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

func isPEM(data []byte) bool {
	return bytes.HasPrefix(data, []byte("-----BEGIN"))
}

func ParseCertificate(filePath string) (*CertificateInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var cert *x509.Certificate
	var parseErr error

	var encoding string

	if isPEM(data) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM data found in %s", filePath)
		}
		cert, parseErr = x509.ParseCertificate(block.Bytes)
		encoding = "PEM"
	} else {
		cert, parseErr = x509.ParseCertificate(data)
		encoding = "DER"
	}

	if parseErr != nil {
		return nil, parseErr
	}

	info := &CertificateInfo{
		Filename:     filePath,
		Encoding:     encoding,
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
	var cert *x509.Certificate
	var parseErr error
	var encoding string

	if isPEM(data) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM data found")
		}
		cert, parseErr = x509.ParseCertificate(block.Bytes)
		encoding = "PEM"
	} else {
		cert, parseErr = x509.ParseCertificate(data)
		encoding = "DER"
	}

	if parseErr != nil {
		return nil, parseErr
	}

	info := &CertificateInfo{
		Encoding:     encoding,
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
