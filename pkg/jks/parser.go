package jks

import (
	"bytes"
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// JKSCertificate wraps a parsed certificate extracted from a JKS store.
type JKSCertificate struct {
	Alias string
	Cert  *certificate.CertificateInfo
}

// JKSPrivateKey wraps a parsed private key extracted from a JKS store.
type JKSPrivateKey struct {
	Alias string
	Key   *privatekey.KeyInfo
}

// JKSInfo contains the contents of a Java KeyStore file.
type JKSInfo struct {
	Filename     string
	AliasCount   int
	Certificates []JKSCertificate
	PrivateKeys  []JKSPrivateKey
}

var ErrPasswordRequired = fmt.Errorf("JKS file is protected, password required")

// ParseJKS reads a Java KeyStore file and parses its certificates and private keys.
func ParseJKS(filePath string, password ...string) (*JKSInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	pwd := ""
	if len(password) > 0 {
		pwd = password[0]
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(pwd)); err != nil {
		if pwd == "" {
			return nil, ErrPasswordRequired
		}
		return nil, fmt.Errorf("failed to load JKS: %w", err)
	}

	info := &JKSInfo{
		Filename:     filePath,
		Certificates: []JKSCertificate{},
		PrivateKeys:  []JKSPrivateKey{},
	}

	for _, alias := range ks.Aliases() {
		if ks.IsPrivateKeyEntry(alias) {
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(pwd))
			if err != nil {
				continue
			}

			keyInfo, err := privatekey.ParsePrivateKeyFromBytes(entry.PrivateKey, filePath, pwd)
			if err == nil {
				keyInfo.Filename = filePath
				info.PrivateKeys = append(info.PrivateKeys, JKSPrivateKey{
					Alias: alias,
					Key:   keyInfo,
				})
			}

			for _, cert := range entry.CertificateChain {
				certInfo, err := certificate.ParseCertificateFromBytes(cert.Content)
				if err == nil {
					certInfo.Filename = filePath
					info.Certificates = append(info.Certificates, JKSCertificate{
						Alias: alias,
						Cert:  certInfo,
					})
				}
			}
		} else if ks.IsTrustedCertificateEntry(alias) {
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				continue
			}

			certInfo, err := certificate.ParseCertificateFromBytes(entry.Certificate.Content)
			if err == nil {
				certInfo.Filename = filePath
				info.Certificates = append(info.Certificates, JKSCertificate{
					Alias: alias,
					Cert:  certInfo,
				})
			}
		}
	}

	info.AliasCount = len(ks.Aliases())
	return info, nil
}
