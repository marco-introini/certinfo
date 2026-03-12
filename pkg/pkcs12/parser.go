package pkcs12

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"software.sslmate.com/src/go-pkcs12"
)

var pkcs12OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12}

type pfxPdu struct {
	Version  int
	AuthSafe asn1.RawValue
	MacData  asn1.RawValue
}

type digestInfo struct {
	AlgorithmIdentifier asn1.RawValue
	Digest              asn1.RawValue
}

func getMacAlgorithm(data []byte) string {
	var pdu pfxPdu
	_, err := asn1.Unmarshal(data, &pdu)
	if err != nil || len(pdu.MacData.Bytes) == 0 {
		return ""
	}

	macDataBytes := pdu.MacData.Bytes

	type macDataContent struct {
		Digest     digestInfo `asn1:"tag:0"`
		MacSalt    asn1.RawValue
		Iterations asn1.RawValue
	}

	var macParsed macDataContent
	macRest, err := asn1.Unmarshal(macDataBytes, &macParsed)
	if err != nil || len(macRest) > 0 {
		var digest digestInfo
		_, err = asn1.Unmarshal(macDataBytes, &digest)
		if err != nil || len(digest.AlgorithmIdentifier.Bytes) == 0 {
			return ""
		}
		var oid asn1.ObjectIdentifier
		_, err = asn1.Unmarshal(digest.AlgorithmIdentifier.Bytes, &oid)
		if err != nil {
			return ""
		}
		return oidToName(oid.String())
	}

	if len(macParsed.Digest.AlgorithmIdentifier.Bytes) == 0 {
		return ""
	}

	var oid asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(macParsed.Digest.AlgorithmIdentifier.Bytes, &oid)
	if err != nil {
		return ""
	}

	return oidToName(oid.String())
}

func getKdfAlgorithm(data []byte) string {
	// Check for PBES2 (modern files with PBKDF2)
	// OID: 1.2.840.113549.1.5.13
	pbes2Bytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d}
	if findOIDBytes(data, pbes2Bytes) {
		// Check for PBKDF2 OID: 1.2.840.113549.1.5.12
		pbkdf2Bytes := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c}
		if findOIDBytes(data, pbkdf2Bytes) {
			return "PBKDF2"
		}
		return "PBES2"
	}

	// Check for legacy PBE algorithms
	// pbeWithSHA1And3KeyTripleDESCBC = 1.2.840.113549.1.12.1.3
	pbe3DESBytes := []byte{0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03}
	// pbeWithSHA1And40BitRC2CBC = 1.2.840.113549.1.12.1.6
	pbeRC2Bytes := []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06}

	if findOIDBytes(data, pbe3DESBytes) || findOIDBytes(data, pbeRC2Bytes) {
		return "PBKDF1"
	}

	return ""
}

func findOIDBytes(data, oidBytes []byte) bool {
	if len(oidBytes) > len(data) {
		return false
	}
	for i := 0; i <= len(data)-len(oidBytes); i++ {
		if string(data[i:i+len(oidBytes)]) == string(oidBytes) {
			return true
		}
	}
	return false
}

func oidToName(oid string) string {
	switch oid {
	case "1.3.14.3.2.26":
		return "SHA-1"
	case "2.16.840.1.101.3.4.2.1":
		return "SHA-256"
	case "2.16.840.1.101.3.4.2.2":
		return "SHA-384"
	case "2.16.840.1.101.3.4.2.3":
		return "SHA-512"
	case "1.2.840.113549.2.5":
		return "MD5"
	default:
		return oid
	}
}

type P12Info struct {
	Filename            string
	Encoding            string
	EncryptionAlgorithm string
	MacAlgorithm        string
	KdfAlgorithm        string
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

func convertBERToDERWithOpenSSL(data []byte, password string) ([]byte, error) {
	// Create temp files
	tmpIn, err := os.CreateTemp("", "p12_in_*.p12")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpIn.Name())

	tmpCert, err := os.CreateTemp("", "p12_cert_*.pem")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpCert.Name())

	tmpKey, err := os.CreateTemp("", "p12_key_*.pem")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpKey.Name())

	tmpOut, err := os.CreateTemp("", "p12_out_*.p12")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpOut.Name())

	// Write input data
	if _, err := tmpIn.Write(data); err != nil {
		return nil, err
	}
	tmpIn.Close()

	// Step 1: Extract certificate using legacy mode
	cmd := exec.Command("openssl", "pkcs12", "-in", tmpIn.Name(), "-clcerts", "-nokeys",
		"-out", tmpCert.Name(), "-passin", "pass:"+password, "-legacy")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl extract cert failed: %w", err)
	}

	// Step 2: Extract private key using legacy mode
	cmd = exec.Command("openssl", "pkcs12", "-in", tmpIn.Name(), "-nocerts", "-nodes",
		"-out", tmpKey.Name(), "-passin", "pass:"+password, "-legacy")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl extract key failed: %w", err)
	}

	// Step 3: Create new P12 with both cert and key
	cmd = exec.Command("openssl", "pkcs12", "-export", "-in", tmpCert.Name(),
		"-inkey", tmpKey.Name(), "-out", tmpOut.Name(), "-passout", "pass:"+password)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl create p12 failed: %w", err)
	}

	return os.ReadFile(tmpOut.Name())
}

func parseP12Data(data []byte, filename string, password string) (*P12Info, error) {
	encoding := "PKCS#12"
	macAlgorithm := getMacAlgorithm(data)
	kdfAlgorithm := getKdfAlgorithm(data)
	isBER := false

	privateKey, leafCert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		// Check if this is a BER file that needs conversion
		if strings.Contains(err.Error(), "indefinite length") ||
			strings.Contains(err.Error(), "not DER") {
			isBER = true

			// Try OpenSSL first if available
			if _, sslErr := exec.LookPath("openssl"); sslErr == nil && password != "" {
				derData, convertErr := convertBERToDERWithOpenSSL(data, password)
				if convertErr == nil {
					privateKey, leafCert, caCerts, err = pkcs12.DecodeChain(derData, password)
					if err == nil {
						data = derData
						encoding = "PKCS#12 (converted from BER)"
					}
				}
			}
		}
	}

	if err != nil {
		if isBER {
			return nil, fmt.Errorf("PKCS#12 file uses BER encoding (indefinite length). Please convert it to DER format using: openssl pkcs12 -in file.p12 -out file_fixed.p12 -export")
		}
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
		MacAlgorithm:     macAlgorithm,
		KdfAlgorithm:     kdfAlgorithm,
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
