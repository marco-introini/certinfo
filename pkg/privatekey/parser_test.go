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
			keyPath: "postquantum/standalone/ca-mlkem760.key",
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
