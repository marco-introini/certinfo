package pem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPEM_WithTextPrefix(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		{
			name:     "certificate with text prefix",
			filePath: "test_certs/with-text/ca-with-text.crt",
			expected: true,
		},
		{
			name:     "key with text prefix",
			filePath: "test_certs/with-text/ca-with-text.key",
			expected: true,
		},
		{
			name:     "standard certificate",
			filePath: "test_certs/traditional/rsa/ca-rsa2048.crt",
			expected: true,
		},
		{
			name:     "standard key",
			filePath: "test_certs/traditional/rsa/ca-rsa2048.key",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", tt.filePath))
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			result := IsPEM(data)
			if result != tt.expected {
				t.Errorf("IsPEM() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestFindBlock_WithTextPrefix(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test_certs/with-text/ca-with-text.crt"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	block, found := FindBlock(data, TypeCertificate)
	if !found {
		t.Error("FindBlock() should find certificate block with text prefix")
	}
	if len(block) == 0 {
		t.Error("FindBlock() returned empty block")
	}
}

func TestFindBlock_KeyWithTextPrefix(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "test_certs/with-text/ca-with-text.key"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	block, found := FindBlock(data, TypePrivateKey)
	if !found {
		t.Error("FindBlock() should find private key block with text prefix")
	}
	if len(block) == 0 {
		t.Error("FindBlock() returned empty block")
	}
}
