package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/marco-introini/certinfo/pkg/pem"
)

type CertificateInfo struct {
	Filename              string
	Encoding              string
	CommonName            string
	Issuer                string
	Subject               string
	NotBefore             time.Time
	NotAfter              time.Time
	Algorithm             string
	KeyType               string
	Bits                  int
	SerialNumber          string
	SANs                  []string
	IsCA                  bool
	KeyUsage              x509.KeyUsage
	KeyUsageStrings       []string
	ExtKeyUsage           []x509.ExtKeyUsage
	ExtKeyUsageStrings    []string
	SubjectKeyID          string
	AuthorityKeyID        string
	CRLDistributionPoints []string
	OCSPServers           []string
	CertificatePolicies   []string
	IsQuantumSafe         bool
	PQCTypes              []string
	IsWeak                bool
	WeakReasons           []string
	PublicKey             any               `json:"-"`
	x509Certificate       *x509.Certificate `json:"-"`
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
		typeName := fmt.Sprintf("%T", pub)
		if strings.Contains(typeName, "mldsa") {
			return "ML-DSA", 0
		}
		if strings.Contains(typeName, "mlkem") {
			return "ML-KEM", 0
		}
		return typeName, 0
	}
}

func isPQCSignatureAlgorithmByName(algoName string) bool {
	lowerAlgo := strings.ToLower(algoName)
	return strings.Contains(lowerAlgo, "ml-dsa") ||
		strings.Contains(lowerAlgo, "slh-dsa") ||
		strings.Contains(lowerAlgo, "fn-dsa") ||
		strings.Contains(lowerAlgo, "falcon") ||
		strings.Contains(lowerAlgo, "rainbow") ||
		strings.Contains(lowerAlgo, "sphincs") ||
		strings.Contains(lowerAlgo, "dilithium") ||
		strings.Contains(lowerAlgo, "kyber")
}

func getPQCTypesFromAlgorithmName(algoName string) []string {
	var pqcTypes []string
	lowerAlgo := strings.ToLower(algoName)

	if strings.Contains(lowerAlgo, "ml-dsa-44") || strings.Contains(lowerAlgo, "dilithium2") {
		pqcTypes = append(pqcTypes, "ML-DSA-44")
	}
	if strings.Contains(lowerAlgo, "ml-dsa-65") || strings.Contains(lowerAlgo, "dilithium3") {
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
		if strings.Contains(lowerAlgo, "128") || strings.Contains(lowerAlgo, "512") {
			pqcTypes = append(pqcTypes, "FN-DSA-128")
		} else if strings.Contains(lowerAlgo, "192") {
			pqcTypes = append(pqcTypes, "FN-DSA-192")
		} else if strings.Contains(lowerAlgo, "256") || strings.Contains(lowerAlgo, "1024") {
			pqcTypes = append(pqcTypes, "FN-DSA-256")
		} else {
			pqcTypes = append(pqcTypes, "FN-DSA")
		}
	}
	if strings.Contains(lowerAlgo, "ml-kem") || strings.Contains(lowerAlgo, "kyber") {
		if strings.Contains(lowerAlgo, "512") {
			pqcTypes = append(pqcTypes, "ML-KEM-512")
		} else if strings.Contains(lowerAlgo, "768") {
			pqcTypes = append(pqcTypes, "ML-KEM-768")
		} else if strings.Contains(lowerAlgo, "1024") {
			pqcTypes = append(pqcTypes, "ML-KEM-1024")
		} else {
			pqcTypes = append(pqcTypes, "ML-KEM")
		}
	}
	return pqcTypes
}

func policyIdentifiersToStrings(ids []asn1.ObjectIdentifier) []string {
	var result []string
	for _, id := range ids {
		result = append(result, id.String())
	}
	return result
}

func keyUsageToStrings(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return usages
}

func extKeyUsageToString(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		return "Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape Server Gated Crypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "Microsoft Commercial Code Signing"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "Microsoft Kernel Code Signing"
	default:
		return fmt.Sprintf("Unknown (%d)", eku)
	}
}

func parseCertificateData(data []byte, filePath string) (*CertificateInfo, error) {
	var cert *x509.Certificate
	var encoding string
	var certBytes []byte

	if pem.IsPEM(data) {
		certBytes, _ = pem.FindBlock(data, pem.TypeCertificate)
		if certBytes == nil {
			return nil, fmt.Errorf("no certificate found in %s", filePath)
		}
		var err error
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		encoding = "PEM"
	} else {
		certBytes = data
		var err error
		cert, err = x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		encoding = "DER"
	}

	algoName := cert.SignatureAlgorithm.String()

	isQuantumSafe := isPQCSignatureAlgorithmByName(algoName)
	pqcTypes := getPQCTypesFromAlgorithmName(algoName)

	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		certStr := string(certBytes)
		if strings.Contains(certStr, "ML-DSA-44") {
			pqcTypes = append(pqcTypes, "ML-DSA-44")
		}
		if strings.Contains(certStr, "ML-DSA-65") {
			pqcTypes = append(pqcTypes, "ML-DSA-65")
		}
		if strings.Contains(certStr, "ML-DSA-87") {
			pqcTypes = append(pqcTypes, "ML-DSA-87")
		}
		if strings.Contains(certStr, "ML-KEM-512") || strings.Contains(certStr, "MLKEM512") {
			pqcTypes = append(pqcTypes, "ML-KEM-512")
		}
		if strings.Contains(certStr, "ML-KEM-768") || strings.Contains(certStr, "MLKEM768") {
			pqcTypes = append(pqcTypes, "ML-KEM-768")
		}
		if strings.Contains(certStr, "ML-KEM-1024") || strings.Contains(certStr, "MLKEM1024") {
			pqcTypes = append(pqcTypes, "ML-KEM-1024")
		}
		if strings.Contains(certStr, "SLH-DSA") {
			pqcTypes = append(pqcTypes, "SLH-DSA")
		}
		if strings.Contains(certStr, "FN-DSA") {
			pqcTypes = append(pqcTypes, "FN-DSA")
		}
		isQuantumSafe = len(pqcTypes) > 0
	}

	var extKeyUsageStrings []string
	for _, eku := range cert.ExtKeyUsage {
		extKeyUsageStrings = append(extKeyUsageStrings, extKeyUsageToString(eku))
	}

	info := &CertificateInfo{
		Filename:              filePath,
		Encoding:              encoding,
		CommonName:            cert.Subject.CommonName,
		Issuer:                cert.Issuer.CommonName,
		Subject:               cert.Subject.String(),
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		Algorithm:             algoName,
		SerialNumber:          cert.SerialNumber.String(),
		IsCA:                  cert.IsCA,
		KeyUsage:              cert.KeyUsage,
		KeyUsageStrings:       keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:           cert.ExtKeyUsage,
		ExtKeyUsageStrings:    extKeyUsageStrings,
		SubjectKeyID:          hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyID:        hex.EncodeToString(cert.AuthorityKeyId),
		CRLDistributionPoints: cert.CRLDistributionPoints,
		OCSPServers:           cert.OCSPServer,
		CertificatePolicies:   policyIdentifiersToStrings(cert.PolicyIdentifiers),
		IsQuantumSafe:         isQuantumSafe,
		PQCTypes:              pqcTypes,
		PublicKey:             cert.PublicKey,
		x509Certificate:       cert,
	}
	info.KeyType, info.Bits = getKeyBitsAndType(cert.PublicKey)

	info.SANs = append(info.SANs, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, net.IP(ip).String())
	}
	info.SANs = append(info.SANs, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		info.SANs = append(info.SANs, (*url.URL)(uri).String())
	}

	info.evaluateWeakness()

	return info, nil
}

func (c *CertificateInfo) evaluateWeakness() {
	algoLower := strings.ToLower(c.Algorithm)
	if strings.Contains(algoLower, "sha1") || strings.Contains(algoLower, "md5") {
		c.IsWeak = true
		c.WeakReasons = append(c.WeakReasons, "weak signature algorithm: "+c.Algorithm)
	}

	if c.KeyType == "RSA" && c.Bits < 2048 {
		c.IsWeak = true
		c.WeakReasons = append(c.WeakReasons, fmt.Sprintf("RSA key size %d is below 2048 bits", c.Bits))
	}

	if c.KeyType == "ECDSA" && c.Bits < 256 {
		c.IsWeak = true
		c.WeakReasons = append(c.WeakReasons, fmt.Sprintf("ECDSA curve size %d is below 256 bits", c.Bits))
	}

	if time.Now().After(c.NotAfter) {
		c.IsWeak = true
		c.WeakReasons = append(c.WeakReasons, "certificate is expired")
	}
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

func matchDNS(hostname, pattern string) bool {
	if strings.EqualFold(pattern, hostname) {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(strings.ToLower(hostname), strings.ToLower(suffix)) &&
			strings.Contains(hostname, ".")
	}
	return false
}

// MatchesHostname reports whether the certificate is valid for the given
// hostname. It checks DNS names, the common name and IP addresses.
func (c *CertificateInfo) MatchesHostname(hostname string) bool {
	if hostname == "" {
		return false
	}

	if ip := net.ParseIP(hostname); ip != nil {
		for _, san := range c.SANs {
			if sanIP := net.ParseIP(san); sanIP != nil && sanIP.Equal(ip) {
				return true
			}
		}
		return false
	}

	for _, san := range c.SANs {
		if matchDNS(hostname, san) {
			return true
		}
	}

	return matchDNS(hostname, c.CommonName)
}
