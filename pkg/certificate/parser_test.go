package certificate

import (
	"os"
	"path/filepath"
	"testing"
)

func getTestCertPath(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func TestParseRSACertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("traditional/rsa/server-rsa2048.crt"))
	if err != nil {
		t.Fatalf("failed to parse RSA certificate: %v", err)
	}

	if cert.Encoding != "PEM" {
		t.Errorf("expected encoding PEM, got %s", cert.Encoding)
	}
	if cert.CommonName != "localhost" {
		t.Errorf("expected CN localhost, got %s", cert.CommonName)
	}
	if cert.Issuer != "Test RSA CA 2048" {
		t.Errorf("expected issuer 'Test RSA CA 2048', got %s", cert.Issuer)
	}
	if cert.Bits != 2048 {
		t.Errorf("expected 2048 bits, got %d", cert.Bits)
	}
}

func TestParseRSACertificate3072(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("traditional/rsa/server-rsa3072.crt"))
	if err != nil {
		t.Fatalf("failed to parse RSA 3072 certificate: %v", err)
	}
	if cert.Bits != 3072 {
		t.Errorf("expected 3072 bits, got %d", cert.Bits)
	}
}

func TestParseRSACertificate4096(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("traditional/rsa/server-rsa4096.crt"))
	if err != nil {
		t.Fatalf("failed to parse RSA 4096 certificate: %v", err)
	}
	if cert.Bits != 4096 {
		t.Errorf("expected 4096 bits, got %d", cert.Bits)
	}
}

func TestParseECDSACertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("traditional/ecdsa/server-ecdsa-p256.crt"))
	if err != nil {
		t.Fatalf("failed to parse ECDSA certificate: %v", err)
	}
	if cert.CommonName != "localhost" {
		t.Errorf("expected CN localhost, got %s", cert.CommonName)
	}
}

func TestParseECDSACertificateP384(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("traditional/ecdsa/server-ecdsa-p384.crt"))
	if err != nil {
		t.Fatalf("failed to parse ECDSA P-384 certificate: %v", err)
	}
}

func TestParseECDSACertificateP521(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("traditional/ecdsa/server-ecdsa-p521.crt"))
	if err != nil {
		t.Fatalf("failed to parse ECDSA P-521 certificate: %v", err)
	}
}

func TestParseEd25519Certificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("traditional/ecdsa/server-ed25519.crt"))
	if err != nil {
		t.Fatalf("failed to parse Ed25519 certificate: %v", err)
	}
	if cert.CommonName != "localhost" {
		t.Errorf("expected CN localhost, got %s", cert.CommonName)
	}
}

func TestParseEd448Certificate(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("traditional/ecdsa/server-ed448.crt"))
	if err != nil {
		t.Fatalf("failed to parse Ed448 certificate: %v", err)
	}
}

func TestParseCertificateWithSAN(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("san-types/san-rsa.crt"))
	if err != nil {
		t.Fatalf("failed to parse certificate with SAN: %v", err)
	}
	if len(cert.SANs) == 0 {
		t.Error("expected SANs to be present")
	}
	found := false
	for _, san := range cert.SANs {
		if san == "localhost" || san == "test.local" {
			found = true
		}
	}
	if !found {
		t.Error("expected localhost or test.local in SANs")
	}
}

func TestParseWildcardCertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("wildcard/wildcard.crt"))
	if err != nil {
		t.Fatalf("failed to parse wildcard certificate: %v", err)
	}
	if cert.CommonName != "*.test.local" {
		t.Errorf("expected *.test.local, got %s", cert.CommonName)
	}
}

func TestParseSelfSignedCertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("selfsigned/rsa-selfsigned.crt"))
	if err != nil {
		t.Fatalf("failed to parse self-signed certificate: %v", err)
	}
	if cert.CommonName != cert.Issuer {
		t.Errorf("self-signed certificate issuer CN should equal subject CN, got %s vs %s", cert.Issuer, cert.CommonName)
	}
}

func TestParseExpiredCertificate(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("expired/expired.crt"))
	if err != nil {
		t.Fatalf("failed to parse expired certificate: %v", err)
	}
}

func TestParseCertificateChain(t *testing.T) {
	rootCA, err := ParseCertificate(getTestCertPath("chain/root-ca.crt"))
	if err != nil {
		t.Fatalf("failed to parse root CA: %v", err)
	}

	intermediate, err := ParseCertificate(getTestCertPath("chain/intermediate-ca.crt"))
	if err != nil {
		t.Fatalf("failed to parse intermediate CA: %v", err)
	}

	server, err := ParseCertificate(getTestCertPath("chain/server.crt"))
	if err != nil {
		t.Fatalf("failed to parse server certificate: %v", err)
	}

	if rootCA.CommonName != "Test Root CA" {
		t.Errorf("expected root CA CN 'Test Root CA', got %s", rootCA.CommonName)
	}
	if intermediate.CommonName != "Test Intermediate CA" {
		t.Errorf("expected intermediate CA CN 'Test Intermediate CA', got %s", intermediate.CommonName)
	}
	if server.CommonName != "localhost" {
		t.Errorf("expected server CN 'localhost', got %s", server.CommonName)
	}

	if server.Issuer != intermediate.CommonName {
		t.Errorf("expected server issuer to be intermediate CA, got %s", server.Issuer)
	}
	if intermediate.Issuer != rootCA.CommonName {
		t.Errorf("expected intermediate issuer to be root CA, got %s", intermediate.Issuer)
	}
}

func TestParseCertificateNotFound(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("nonexistent.crt"))
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestParseCertificateFromBytes(t *testing.T) {
	data, err := os.ReadFile(getTestCertPath("traditional/rsa/server-rsa2048.crt"))
	if err != nil {
		t.Fatalf("failed to read test cert: %v", err)
	}

	cert, err := ParseCertificateFromBytes(data)
	if err != nil {
		t.Fatalf("failed to parse certificate from bytes: %v", err)
	}
	if cert.Encoding != "PEM" {
		t.Errorf("expected PEM encoding, got %s", cert.Encoding)
	}
}

func TestParseClientCertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("client/client.crt"))
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}
	if cert.CommonName != "testclient" {
		t.Errorf("expected CN testclient, got %s", cert.CommonName)
	}
}
