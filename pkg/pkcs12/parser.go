package pkcs12

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"software.sslmate.com/src/go-pkcs12"
)

type P12Info struct {
	Filename            string
	Encoding            string
	EncryptionAlgorithm string
	CertificateCount    int
	PrivateKeyCount     int
	Certificates        []P12Certificate
	PrivateKeys         []P12Key
}

type P12Certificate struct {
	Cert          *certificate.CertificateInfo
	HasPrivateKey bool
}

type P12Key struct {
	Key *privatekey.KeyInfo
}

var ErrEncryptedP12 = fmt.Errorf("PKCS#12 file is encrypted, password required")
var ErrNoEntries = fmt.Errorf("no certificates or private keys found in PKCS#12 file")

func parseP12Data(data []byte, filename string, password string) (*P12Info, error) {
	encoding := "PKCS#12"

	privateKey, leafCert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		if strings.Contains(err.Error(), "incorrect password") ||
			strings.Contains(err.Error(), "invalid password") ||
			strings.Contains(err.Error(), "pkcs12: decryption error") ||
			strings.Contains(err.Error(), "decryption password incorrect") ||
			strings.Contains(err.Error(), "password incorrect") ||
			strings.Contains(err.Error(), "pkcs12:") {
			return nil, ErrEncryptedP12
		}
		return nil, fmt.Errorf("invalid PKCS#12 file: %w", err)
	}

	p12Info := &P12Info{
		Filename:         filename,
		Encoding:         encoding,
		CertificateCount: 0,
		PrivateKeyCount:  0,
		Certificates:     []P12Certificate{},
		PrivateKeys:      []P12Key{},
	}

	if leafCert != nil {
		certInfo, err := certificate.ParseCertificateFromBytes(leafCert.Raw)
		if err == nil {
			certInfo.Filename = filename
			p12Info.Certificates = append(p12Info.Certificates, P12Certificate{
				Cert:          certInfo,
				HasPrivateKey: privateKey != nil,
			})
			p12Info.CertificateCount++
		}
	}

	for _, caCert := range caCerts {
		certInfo, err := certificate.ParseCertificateFromBytes(caCert.Raw)
		if err == nil {
			certInfo.Filename = filename
			p12Info.Certificates = append(p12Info.Certificates, P12Certificate{
				Cert:          certInfo,
				HasPrivateKey: false,
			})
			p12Info.CertificateCount++
		}
	}

	if privateKey != nil {
		var keyBytes []byte

		switch key := privateKey.(type) {
		case *rsa.PrivateKey:
			keyBytes = x509.MarshalPKCS1PrivateKey(key)
		case *ecdsa.PrivateKey:
			var err error
			keyBytes, err = x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ECDSA key: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
		}

		keyInfo, err := privatekey.ParsePrivateKeyFromBytes(keyBytes, filename, password)
		if err == nil {
			keyInfo.Filename = filename
			keyInfo.Encoding = encoding
			p12Info.PrivateKeys = append(p12Info.PrivateKeys, P12Key{Key: keyInfo})
			p12Info.PrivateKeyCount++
		}
	}

	if p12Info.CertificateCount == 0 && p12Info.PrivateKeyCount == 0 {
		return nil, ErrNoEntries
	}

	return p12Info, nil
}

func ParseP12(filePath string, password ...string) (*P12Info, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	pwd := ""
	if len(password) > 0 {
		pwd = password[0]
	}

	return parseP12Data(data, filePath, pwd)
}

func ParseP12FromBytes(data []byte, filename string, password ...string) (*P12Info, error) {
	pwd := ""
	if len(password) > 0 {
		pwd = password[0]
	}

	return parseP12Data(data, filename, pwd)
}
