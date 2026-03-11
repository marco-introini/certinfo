package privatekey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestKeyPath(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func TestParseRSAPrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		keyPath  string
		expected struct {
			encoding string
			keyType  string
			bits     int
		}
	}{
		{
			name:    "RSA 2048",
			keyPath: "traditional/rsa/server-rsa2048.key",
			expected: struct {
				encoding string
				keyType  string
				bits     int
			}{
				encoding: "PEM",
				keyType:  "RSA",
				bits:     2048,
			},
		},
		{
			name:    "RSA 3072",
			keyPath: "traditional/rsa/server-rsa3072.key",
			expected: struct {
				encoding string
				keyType  string
				bits     int
			}{
				bits: 3072,
			},
		},
		{
			name:    "RSA 4096",
			keyPath: "traditional/rsa/server-rsa4096.key",
			expected: struct {
				encoding string
				keyType  string
				bits     int
			}{
				bits: 4096,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKey(getTestKeyPath(tt.keyPath))
			require.NoError(t, err, "failed to parse RSA private key")
			if tt.expected.encoding != "" {
				assert.Equal(t, tt.expected.encoding, key.Encoding)
			}
			if tt.expected.keyType != "" {
				assert.Equal(t, tt.expected.keyType, key.KeyType)
			}
			if tt.expected.bits != 0 {
				assert.Equal(t, tt.expected.bits, key.Bits)
			}
		})
	}
}

func TestParseECDSAPrivateKey(t *testing.T) {
	tests := []struct {
		name     string
		keyPath  string
		expected struct {
			keyType string
			curve   string
		}
	}{
		{
			name:    "P-256",
			keyPath: "traditional/ecdsa/server-ecdsa-p256.key",
			expected: struct {
				keyType string
				curve   string
			}{
				keyType: "EC",
				curve:   "P-256",
			},
		},
		{
			name:    "P-384",
			keyPath: "traditional/ecdsa/server-ecdsa-p384.key",
			expected: struct {
				keyType string
				curve   string
			}{
				curve: "P-384",
			},
		},
		{
			name:    "P-521",
			keyPath: "traditional/ecdsa/server-ecdsa-p521.key",
			expected: struct {
				keyType string
				curve   string
			}{
				curve: "P-521",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKey(getTestKeyPath(tt.keyPath))
			require.NoError(t, err, "failed to parse ECDSA private key")
			if tt.expected.keyType != "" {
				assert.Equal(t, tt.expected.keyType, key.KeyType)
			}
			if tt.expected.curve != "" {
				assert.Equal(t, tt.expected.curve, key.Curve)
			}
		})
	}
}

func TestParseEd25519PrivateKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ed25519.key"))
	require.NoError(t, err, "failed to parse Ed25519 key")
	assert.Equal(t, "Ed25519", key.KeyType)
	assert.Equal(t, 256, key.Bits)
}

func TestParseEd448PrivateKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ed448.key"))
	if err != nil {
		t.Skipf("Ed448 PKCS#8 parsing error: %v", err)
		return
	}
	if key.KeyType == "" || key.KeyType == "<nil>" {
		t.Skip("Ed448 PKCS#8 not supported in Go x509")
		return
	}
	assert.Equal(t, "Ed448", key.KeyType)
}

func TestParsePrivateKeyNotFound(t *testing.T) {
	_, err := ParsePrivateKey(getTestKeyPath("nonexistent.key"))
	assert.Error(t, err, "expected error for non-existent file")
}

func TestSummarizePrivateKeyDirectory(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "traditional", "rsa")
	summaries, err := SummarizeDirectory(dirPath)
	require.NoError(t, err, "failed to summarize key directory")
	assert.NotEmpty(t, summaries, "expected at least one key summary")
}

func TestSummarizePrivateKeyDirectoryRecursive(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs")
	summaries, err := SummarizeDirectoryRecursive(dirPath)
	require.NoError(t, err, "failed to summarize keys recursively")
	assert.GreaterOrEqual(t, len(summaries), 10, "expected many keys")
}

func TestParseCAKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/rsa/ca-rsa2048.key"))
	require.NoError(t, err, "failed to parse CA key")
	assert.Equal(t, "RSA", key.KeyType, "expected RSA key type for CA")
}

func TestParseWildcardKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("wildcard/wildcard.key"))
	require.NoError(t, err, "failed to parse wildcard key")
	assert.Equal(t, "RSA", key.KeyType)
}

func TestParseClientKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("client/client.key"))
	require.NoError(t, err, "failed to parse client key")
	assert.Equal(t, "RSA", key.KeyType)
}

func TestParseChainKeys(t *testing.T) {
	rootKey, err := ParsePrivateKey(getTestKeyPath("chain/root-ca.key"))
	require.NoError(t, err, "failed to parse root CA key")
	assert.Equal(t, 4096, rootKey.Bits, "expected 4096 bits for root CA")

	intermediateKey, err := ParsePrivateKey(getTestKeyPath("chain/intermediate-ca.key"))
	require.NoError(t, err, "failed to parse intermediate CA key")
	assert.Equal(t, 4096, intermediateKey.Bits, "expected 4096 bits for intermediate CA")
}

func TestParsePrivateKeyEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectedErr bool
	}{
		{
			name:        "empty file - returns unknown type",
			content:     "",
			expectedErr: false,
		},
		{
			name:        "garbage data - returns unknown type",
			content:     "this is not a private key",
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "test.key")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			require.NoError(t, err)

			key, err := ParsePrivateKey(tmpFile)
			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
				assert.Contains(t, key.KeyType, "nil")
			}
		})
	}
}

func TestParsePQCPrivateKeys(t *testing.T) {
	tests := []struct {
		name     string
		keyPath  string
		expected struct {
			keyType       string
			bits          int
			isQuantumSafe bool
		}
	}{
		{
			name:    "ML-DSA-44",
			keyPath: "postquantum/standalone/ca-mldsa44.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-DSA",
				bits:          44,
				isQuantumSafe: true,
			},
		},
		{
			name:    "ML-DSA-65",
			keyPath: "postquantum/standalone/ca-mldsa65.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-DSA",
				bits:          65,
				isQuantumSafe: true,
			},
		},
		{
			name:    "ML-DSA-87",
			keyPath: "postquantum/standalone/ca-mldsa87.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-DSA",
				bits:          87,
				isQuantumSafe: true,
			},
		},
		{
			name:    "ML-KEM-768",
			keyPath: "postquantum/standalone/ca-mlkem768.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-KEM",
				bits:          768,
				isQuantumSafe: true,
			},
		},
		{
			name:    "ML-KEM-1024",
			keyPath: "postquantum/standalone/ca-mlkem1024.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-KEM",
				bits:          1024,
				isQuantumSafe: true,
			},
		},
		{
			name:    "ML-DSA-44 Server",
			keyPath: "postquantum/standalone/server-mldsa44.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-DSA",
				bits:          44,
				isQuantumSafe: true,
			},
		},
		{
			name:    "Hybrid RSA ML-DSA",
			keyPath: "postquantum/hybrid-rsa/ca-mldsa.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-DSA",
				bits:          44,
				isQuantumSafe: true,
			},
		},
		{
			name:    "Hybrid ECDSA ML-DSA",
			keyPath: "postquantum/hybrid-ecdsa/ca-mldsa.key",
			expected: struct {
				keyType       string
				bits          int
				isQuantumSafe bool
			}{
				keyType:       "ML-DSA",
				bits:          44,
				isQuantumSafe: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKey(getTestKeyPath(tt.keyPath))
			require.NoError(t, err, "failed to parse PQC private key")
			if tt.expected.keyType != "" {
				assert.Equal(t, tt.expected.keyType, key.KeyType)
			}
			if tt.expected.bits != 0 {
				assert.Equal(t, tt.expected.bits, key.Bits)
			}
			assert.True(t, key.IsQuantumSafe, "expected key to be quantum safe")
		})
	}
}

func TestParseEncryptedPrivateKey(t *testing.T) {
	tests := []struct {
		name            string
		keyPath         string
		password        string
		expectedKeyType string
		expectedBits    int
		expectError     bool
		expectEncrypted bool
	}{
		{
			name:            "RSA encrypted with correct password",
			keyPath:         "traditional/rsa-encrypted/ca-rsa2048-encrypted.key",
			password:        "testpass",
			expectedKeyType: "RSA",
			expectedBits:    2048,
			expectError:     false,
		},
		{
			name:            "RSA encrypted without password",
			keyPath:         "traditional/rsa-encrypted/ca-rsa2048-encrypted.key",
			password:        "",
			expectError:     true,
			expectEncrypted: true,
		},
		{
			name:        "RSA encrypted with wrong password",
			keyPath:     "traditional/rsa-encrypted/ca-rsa2048-encrypted.key",
			password:    "wrongpassword",
			expectError: true,
		},
		{
			name:            "RSA unencrypted",
			keyPath:         "traditional/rsa/ca-rsa2048.key",
			password:        "",
			expectedKeyType: "RSA",
			expectedBits:    2048,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKey(getTestKeyPath(tt.keyPath), tt.password)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectEncrypted {
					assert.Equal(t, ErrEncryptedKey, err)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedKeyType, key.KeyType)
			assert.Equal(t, tt.expectedBits, key.Bits)
		})
	}
}

func TestIsPQCCheck(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		expected bool
	}{
		{"ML-KEM", "ml-kem-768", true},
		{"ML-DSA", "ml-dsa-44", true},
		{"SLH-DSA", "slh-dsa-sha2-128s", true},
		{"FN-DSA", "fn-dsa", true},
		{"FALCON", "falcon-512", true},
		{"Dilithium", "dilithium2", true},
		{"Kyber", "kyber512", true},
		{"SPHINCS", "sphincs-sha2-128s", true},
		{"Rainbow", "rainbow", true},
		{"RSA", "rsaEncryption", false},
		{"ECDSA", "ecdsa-with-sha256", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPQCCheck(tt.algo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectPQCFromOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      string
		expected string
	}{
		{"ML-DSA-44", "2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
		{"ML-DSA-65", "2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
		{"ML-DSA-87", "2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
		{"ML-KEM-512", "2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
		{"ML-KEM-768", "2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
		{"ML-KEM-1024", "2.16.840.1.101.3.4.4.3", "ML-KEM-1024"},
		{"SLH-DSA-128S", "2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-128S"},
		{"SLH-DSA-128F", "2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-128F"},
		{"FALCON-512", "2.16.840.1.101.3.4.3.29", "FALCON-512"},
		{"FALCON-1024", "2.16.840.1.101.3.4.3.30", "FALCON-1024"},
		{"Unknown", "1.2.3.4.5", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectPQCFromOID(tt.oid)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPQCBits(t *testing.T) {
	tests := []struct {
		name     string
		pqcType  string
		expected int
	}{
		{"ML-DSA-44", "ML-DSA-44", 44},
		{"ML-DSA-65", "ML-DSA-65", 65},
		{"ML-DSA-87", "ML-DSA-87", 87},
		{"ML-KEM-512", "ML-KEM-512", 512},
		{"ML-KEM-768", "ML-KEM-768", 768},
		{"ML-KEM-1024", "ML-KEM-1024", 1024},
		{"SLH-DSA-128S", "SLH-DSA-SHA2-128S", 128},
		{"SLH-DSA-128F", "SLH-DSA-SHA2-128F", 128},
		{"SLH-DSA-192S", "SLH-DSA-SHA2-192S", 192},
		{"SLH-DSA-256F", "SLH-DSA-SHA2-256F", 256},
		{"FALCON-512", "FALCON-512", 512},
		{"FALCON-1024", "FALCON-1024", 1024},
		{"FN-DSA-128", "FN-DSA-128", 128},
		{"FN-DSA-192", "FN-DSA-192", 192},
		{"FN-DSA-256", "FN-DSA-256", 256},
		{"Unknown", "UNKNOWN", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPQCBits(tt.pqcType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectPQCOIDFromError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected string
	}{
		{"ML-DSA-44 OID", "asn1: structure error: oid 2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
		{"ML-KEM-512 OID", "unknown oid 2.16.840.1.101.3.4.4.1", "ML-KEM-512"},
		{"ML-KEM-768 OID", "error parsing 2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
		{"ML-KEM-1024 OID", "oid 2.16.840.1.101.3.4.4.3 not recognized", "ML-KEM-1024"},
		{"SLH-DSA OID", "2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-128S"},
		{"FALCON OID", "2.16.840.1.101.3.4.3.29", "FALCON-512"},
		{"No OID", "plain RSA key", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectPQCOIDFromError(tt.errMsg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectPQCFromText(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected []string
	}{
		{"ML-DSA-44", "-----BEGIN PRIVATE KEY-----\nML-DSA-44\n-----END PRIVATE KEY-----", []string{"ML-DSA-44"}},
		{"ML-DSA-65", "-----BEGIN PRIVATE KEY-----\nMLDSA65\n-----END PRIVATE KEY-----", []string{"ML-DSA-65"}},
		{"ML-KEM-512", "-----BEGIN PRIVATE KEY-----\nMLKEM512\n-----END PRIVATE KEY-----", []string{"ML-KEM-512"}},
		{"ML-KEM-768", "-----BEGIN PRIVATE KEY-----\nML-KEM-768\n-----END PRIVATE KEY-----", []string{"ML-KEM-768"}},
		{"ML-KEM-1024", "-----BEGIN PRIVATE KEY-----\nML-KEM-1024\n-----END PRIVATE KEY-----", []string{"ML-KEM-1024"}},
		{"SLH-DSA", "-----BEGIN PRIVATE KEY-----\nSLH-DSA-SHA2-256S\n-----END PRIVATE KEY-----", []string{"SLH-DSA-SHA2-256S"}},
		{"FALCON-512", "-----BEGIN PRIVATE KEY-----\nFALCON-512\n-----END PRIVATE KEY-----", []string{"FALCON-512"}},
		{"Multiple", "-----BEGIN PRIVATE KEY-----\nML-DSA-44 ML-KEM-768\n-----END PRIVATE KEY-----", []string{"ML-DSA-44", "ML-KEM-768"}},
		{"None", "-----BEGIN PRIVATE KEY-----\nRSA-KEY\n-----END PRIVATE KEY-----", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectPQCFromText([]byte(tt.data))
			assert.Equal(t, tt.expected, result)
		})
	}
}
