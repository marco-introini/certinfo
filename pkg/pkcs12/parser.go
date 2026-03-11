package pkcs12

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"golang.org/x/crypto/pkcs12"
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

	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		if strings.Contains(err.Error(), "incorrect password") ||
			strings.Contains(err.Error(), "invalid password") ||
			strings.Contains(err.Error(), "pkcs12: decryption error") {
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

	certKeyMap := make(map[string]bool)

	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certInfo, err := certificate.ParseCertificateFromBytes(cert.Raw)
			if err != nil {
				continue
			}
			certInfo.Filename = filename

			certKeyMap[cert.Subject.CommonName] = false

			p12Info.Certificates = append(p12Info.Certificates, P12Certificate{
				Cert:          certInfo,
				HasPrivateKey: false,
			})
			p12Info.CertificateCount++

		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			keyInfo, err := privatekey.ParsePrivateKeyFromBytes(block.Bytes, filename, password)
			if err != nil {
				continue
			}
			keyInfo.Filename = filename
			keyInfo.Encoding = encoding

			p12Info.PrivateKeys = append(p12Info.PrivateKeys, P12Key{
				Key: keyInfo,
			})
			p12Info.PrivateKeyCount++
		}
	}

	for i := range p12Info.Certificates {
		cn := p12Info.Certificates[i].Cert.CommonName
		if _, ok := certKeyMap[cn]; ok {
			p12Info.Certificates[i].HasPrivateKey = true
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
