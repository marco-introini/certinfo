package certificate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestCertPath(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func TestParseRSACertificate(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		expected struct {
			encoding   string
			commonName string
			issuer     string
			bits       int
		}
	}{
		{
			name:     "RSA 2048",
			certPath: "traditional/rsa/server-rsa2048.crt",
			expected: struct {
				encoding   string
				commonName string
				issuer     string
				bits       int
			}{
				encoding:   "PEM",
				commonName: "localhost",
				issuer:     "Test RSA CA 2048",
				bits:       2048,
			},
		},
		{
			name:     "RSA 3072",
			certPath: "traditional/rsa/server-rsa3072.crt",
			expected: struct {
				encoding   string
				commonName string
				issuer     string
				bits       int
			}{
				bits: 3072,
			},
		},
		{
			name:     "RSA 4096",
			certPath: "traditional/rsa/server-rsa4096.crt",
			expected: struct {
				encoding   string
				commonName string
				issuer     string
				bits       int
			}{
				bits: 4096,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificate(getTestCertPath(tt.certPath))
			require.NoError(t, err, "failed to parse RSA certificate")
			if tt.expected.encoding != "" {
				assert.Equal(t, tt.expected.encoding, cert.Encoding)
			}
			if tt.expected.commonName != "" {
				assert.Equal(t, tt.expected.commonName, cert.CommonName)
			}
			if tt.expected.issuer != "" {
				assert.Equal(t, tt.expected.issuer, cert.Issuer)
			}
			if tt.expected.bits != 0 {
				assert.Equal(t, tt.expected.bits, cert.Bits)
			}
		})
	}
}

func TestParseECDSACertificate(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		expected struct {
			commonName string
			curve      string
		}
	}{
		{
			name:     "P-256",
			certPath: "traditional/ecdsa/server-ecdsa-p256.crt",
			expected: struct {
				commonName string
				curve      string
			}{
				commonName: "localhost",
			},
		},
		{
			name:     "P-384",
			certPath: "traditional/ecdsa/server-ecdsa-p384.crt",
		},
		{
			name:     "P-521",
			certPath: "traditional/ecdsa/server-ecdsa-p521.crt",
		},
		{
			name:     "Ed25519",
			certPath: "traditional/ecdsa/server-ed25519.crt",
			expected: struct {
				commonName string
				curve      string
			}{
				commonName: "localhost",
			},
		},
		{
			name:     "Ed448",
			certPath: "traditional/ecdsa/server-ed448.crt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificate(getTestCertPath(tt.certPath))
			require.NoError(t, err, "failed to parse ECDSA certificate")
			if tt.expected.commonName != "" {
				assert.Equal(t, tt.expected.commonName, cert.CommonName)
			}
		})
	}
}

func TestParseCertificateWithSAN(t *testing.T) {
	tests := []struct {
		name          string
		certPath      string
		expectedSANs  []string
		expectedCount int
	}{
		{
			name:          "SAN RSA",
			certPath:      "san-types/san-rsa.crt",
			expectedCount: 3,
			expectedSANs:  []string{"localhost", "test.local"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificate(getTestCertPath(tt.certPath))
			require.NoError(t, err, "failed to parse certificate with SAN")
			assert.NotEmpty(t, cert.SANs, "expected SANs to be present")
			if tt.expectedCount > 0 {
				assert.Len(t, cert.SANs, tt.expectedCount)
			}
			for _, expectedSAN := range tt.expectedSANs {
				assert.Contains(t, cert.SANs, expectedSAN)
			}
		})
	}
}

func TestParseWildcardCertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("wildcard/wildcard.crt"))
	require.NoError(t, err, "failed to parse wildcard certificate")
	assert.Equal(t, "*.test.local", cert.CommonName)
}

func TestParseSelfSignedCertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("selfsigned/rsa-selfsigned.crt"))
	require.NoError(t, err, "failed to parse self-signed certificate")
	assert.Equal(t, cert.CommonName, cert.Issuer, "self-signed certificate issuer CN should equal subject CN")
}

func TestParseExpiredCertificate(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("expired/expired.crt"))
	require.NoError(t, err, "failed to parse expired certificate")
}

func TestParseCertificateChain(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		expected struct {
			commonName string
			issuer     string
		}
	}{
		{
			name:     "Root CA",
			certPath: "chain/root-ca.crt",
			expected: struct {
				commonName string
				issuer     string
			}{
				commonName: "Test Root CA",
			},
		},
		{
			name:     "Intermediate CA",
			certPath: "chain/intermediate-ca.crt",
			expected: struct {
				commonName string
				issuer     string
			}{
				commonName: "Test Intermediate CA",
			},
		},
		{
			name:     "Server",
			certPath: "chain/server.crt",
			expected: struct {
				commonName string
				issuer     string
			}{
				commonName: "localhost",
				issuer:     "Test Intermediate CA",
			},
		},
	}

	certs := make(map[string]*CertificateInfo)
	for _, tt := range tests {
		cert, err := ParseCertificate(getTestCertPath(tt.certPath))
		require.NoError(t, err, "failed to parse %s", tt.name)
		certs[tt.name] = cert
	}

	assert.Equal(t, "Test Root CA", certs["Root CA"].CommonName)
	assert.Equal(t, "Test Intermediate CA", certs["Intermediate CA"].CommonName)
	assert.Equal(t, "localhost", certs["Server"].CommonName)
	assert.Equal(t, certs["Intermediate CA"].CommonName, certs["Server"].Issuer)
	assert.Equal(t, certs["Root CA"].CommonName, certs["Intermediate CA"].Issuer)
}

func TestParseCertificateNotFound(t *testing.T) {
	_, err := ParseCertificate(getTestCertPath("nonexistent.crt"))
	assert.Error(t, err, "expected error for non-existent file")
}

func TestParseCertificateFromBytes(t *testing.T) {
	data, err := os.ReadFile(getTestCertPath("traditional/rsa/server-rsa2048.crt"))
	require.NoError(t, err, "failed to read test cert")

	cert, err := ParseCertificateFromBytes(data)
	require.NoError(t, err, "failed to parse certificate from bytes")
	assert.Equal(t, "PEM", cert.Encoding)
}

func TestParseClientCertificate(t *testing.T) {
	cert, err := ParseCertificate(getTestCertPath("client/client.crt"))
	require.NoError(t, err, "failed to parse client certificate")
	assert.Equal(t, "testclient", cert.CommonName)
}

func TestParseCertificateEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name:        "empty file",
			content:     "",
			expectError: true,
		},
		{
			name:        "invalid PEM data",
			content:     "-----BEGIN CERTIFICATE-----\nnot valid base64!!!\n-----END CERTIFICATE-----",
			expectError: true,
		},
		{
			name:        "garbage data",
			content:     "this is not a certificate",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "test.crt")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			require.NoError(t, err)

			_, err = ParseCertificate(tmpFile)
			assert.Error(t, err, "expected error for %s", tt.name)
		})
	}
}

func TestParsePQCertificate(t *testing.T) {
	tests := []struct {
		name     string
		certPath string
		expected struct {
			commonName    string
			issuer        string
			isQuantumSafe bool
			pqcTypes      []string
		}
	}{
		{
			name:     "ML-DSA-44 CA",
			certPath: "postquantum/standalone/ca-mldsa44.crt",
			expected: struct {
				commonName    string
				issuer        string
				isQuantumSafe bool
				pqcTypes      []string
			}{
				commonName:    "Test ML-DSA-44 CA",
				issuer:        "Test ML-DSA-44 CA",
				isQuantumSafe: true,
				pqcTypes:      []string{"ML-DSA-44"},
			},
		},
		{
			name:     "ML-DSA-65 CA",
			certPath: "postquantum/standalone/ca-mldsa65.crt",
			expected: struct {
				commonName    string
				issuer        string
				isQuantumSafe bool
				pqcTypes      []string
			}{
				commonName:    "Test ML-DSA-65 CA",
				issuer:        "Test ML-DSA-65 CA",
				isQuantumSafe: true,
				pqcTypes:      []string{"ML-DSA-65"},
			},
		},
		{
			name:     "ML-DSA-87 CA",
			certPath: "postquantum/standalone/ca-mldsa87.crt",
			expected: struct {
				commonName    string
				issuer        string
				isQuantumSafe bool
				pqcTypes      []string
			}{
				commonName:    "Test ML-DSA-87 CA",
				issuer:        "Test ML-DSA-87 CA",
				isQuantumSafe: true,
				pqcTypes:      []string{"ML-DSA-87"},
			},
		},
		{
			name:     "ML-DSA-44 Server",
			certPath: "postquantum/standalone/server-mldsa44.crt",
			expected: struct {
				commonName    string
				issuer        string
				isQuantumSafe bool
				pqcTypes      []string
			}{
				commonName:    "localhost",
				issuer:        "Test ML-DSA-44 CA",
				isQuantumSafe: true,
				pqcTypes:      []string{"ML-DSA-44"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificate(getTestCertPath(tt.certPath))
			require.NoError(t, err, "failed to parse PQC certificate")
			assert.Equal(t, tt.expected.commonName, cert.CommonName)
			assert.Equal(t, tt.expected.issuer, cert.Issuer)
			assert.Equal(t, tt.expected.isQuantumSafe, cert.IsQuantumSafe)
			assert.Equal(t, tt.expected.pqcTypes, cert.PQCTypes)
		})
	}
}

func TestIsPQCSignatureAlgorithmByName(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		expected bool
	}{
		{"ML-DSA", "ml-dsa-44", true},
		{"SLH-DSA", "slh-dsa-sha2-128s", true},
		{"FN-DSA", "fn-dsa", true},
		{"FALCON", "falcon-512", true},
		{"Rainbow", "rainbow", true},
		{"SPHINCS", "sphincs-sha2-128s", true},
		{"Dilithium", "dilithium2", true},
		{"Kyber", "kyber512", true},
		{"RSA", "rsaEncryption", false},
		{"ECDSA", "ecdsa-with-sha256", false},
		{"Ed25519", "ed25519", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPQCSignatureAlgorithmByName(tt.algo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPQCTypesFromAlgorithmName(t *testing.T) {
	tests := []struct {
		name     string
		algoName string
		expected []string
	}{
		{"ML-DSA-44", "ml-dsa-44", []string{"ML-DSA-44"}},
		{"ML-DSA-65", "ml-dsa-45", []string{"ML-DSA-65"}},
		{"ML-DSA-87", "ml-dsa-87", []string{"ML-DSA-87"}},
		{"ML-DSA-44 dilithium", "dilithium2", []string{"ML-DSA-44"}},
		{"ML-DSA-65 dilithium", "dilithium3", []string{"ML-DSA-65"}},
		{"ML-DSA-87 dilithium", "dilithium5", []string{"ML-DSA-87"}},
		{"SLH-DSA-128", "slh-dsa-sha2-128s", []string{"SLH-DSA-128"}},
		{"SLH-DSA-192", "slh-dsa-sha2-192s", []string{"SLH-DSA-192"}},
		{"SLH-DSA-256", "slh-dsa-sha2-256s", []string{"SLH-DSA-256"}},
		{"SLH-DSA generic", "slh-dsa", []string{"SLH-DSA"}},
		{"FN-DSA-128", "fn-dsa-128", []string{"FN-DSA-128"}},
		{"FN-DSA-192", "fn-dsa-192", []string{"FN-DSA-192"}},
		{"FN-DSA-256", "fn-dsa-256", []string{"FN-DSA-256"}},
		{"FN-DSA generic", "fn-dsa", []string{"FN-DSA"}},
		{"FALCON-512", "falcon-512", []string{"FN-DSA-128"}},
		{"FALCON-1024", "falcon-1024", []string{"FN-DSA-256"}},
		{"ML-KEM-512", "ml-kem-512", []string{"ML-KEM-512"}},
		{"ML-KEM-768", "ml-kem-768", []string{"ML-KEM-768"}},
		{"ML-KEM-1024", "ml-kem-1024", []string{"ML-KEM-1024"}},
		{"ML-KEM generic", "ml-kem", []string{"ML-KEM"}},
		{"Kyber", "kyber512", []string{"ML-KEM-512"}},
		{"RSA", "rsaEncryption", nil},
		{"ECDSA", "ecdsa-with-sha256", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPQCTypesFromAlgorithmName(tt.algoName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
