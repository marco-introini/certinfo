package certificate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarizeDirectory(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "traditional", "rsa")
	summaries, err := SummarizeDirectory(dirPath)
	require.NoError(t, err, "failed to summarize directory")
	assert.NotEmpty(t, summaries, "expected at least one certificate summary")

	foundValid := false
	foundExpired := false
	for _, s := range summaries {
		if s.Status == "valid" {
			foundValid = true
		}
		if s.Status == "expired" {
			foundExpired = true
		}
	}
	assert.True(t, foundValid, "expected at least one valid certificate")
	assert.False(t, foundExpired, "did not expect expired certificate in RSA directory")
}

func TestSummarizeDirectoryExpired(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "expired")
	summaries, err := SummarizeDirectory(dirPath)
	require.NoError(t, err, "failed to summarize expired directory")
	assert.NotEmpty(t, summaries, "expected at least one certificate summary")

	for _, s := range summaries {
		assert.NotEqual(t, "valid", s.Status, "did not expect valid status for expired certificate")
	}
}

func TestSummarizeDirectoryRecursive(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs")
	summaries, err := SummarizeDirectoryRecursive(dirPath)
	require.NoError(t, err, "failed to summarize directory recursively")
	assert.GreaterOrEqual(t, len(summaries), 10, "expected many certificates")
}

func TestSummarizeDirectoryNotFound(t *testing.T) {
	_, err := SummarizeDirectory("/nonexistent/path")
	assert.Error(t, err, "expected error for non-existent directory")
}

func TestSummarizeECDSA(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "traditional", "ecdsa")
	summaries, err := SummarizeDirectory(dirPath)
	require.NoError(t, err, "failed to summarize ECDSA directory")
	assert.NotEmpty(t, summaries, "expected at least one ECDSA certificate")
}

func TestSummarizeCertificateChain(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "chain")
	summaries, err := SummarizeDirectory(dirPath)
	require.NoError(t, err, "failed to summarize chain directory")
	assert.GreaterOrEqual(t, len(summaries), 3, "expected at least 3 certificates in chain")
}

func TestSummarizeDirectoryEmpty(t *testing.T) {
	emptyDir := t.TempDir()
	summaries, err := SummarizeDirectory(emptyDir)
	require.NoError(t, err, "failed to summarize empty directory")
	assert.Empty(t, summaries, "expected no summaries for empty directory")
}

func TestSummarizeDirectoryWithInvalidFiles(t *testing.T) {
	dirPath := t.TempDir()

	validCert := filepath.Join("..", "..", "test_certs", "traditional", "rsa", "server-rsa2048.crt")
	data, err := os.ReadFile(validCert)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dirPath, "valid.crt"), data, 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dirPath, "invalid.crt"), []byte("not a certificate"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dirPath, "empty.txt"), []byte{}, 0644)
	require.NoError(t, err)

	summaries, err := SummarizeDirectory(dirPath)
	require.NoError(t, err, "failed to summarize directory with invalid files")

	assert.Equal(t, 1, len(summaries), "expected only 1 valid certificate summary")
	assert.Equal(t, "valid.crt", summaries[0].Filename)
}
