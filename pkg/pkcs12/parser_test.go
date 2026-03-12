package pkcs12

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestP12Path(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func TestParseP12RSA(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		password string
		wantErr  bool
	}{
		{
			name:     "RSA 2048",
			file:     getTestP12Path("p12-format/server-rsa2048.pfx"),
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "RSA 4096",
			file:     getTestP12Path("p12-format/server-rsa4096.pfx"),
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "ECDSA P-256",
			file:     getTestP12Path("p12-format/server-ecdsa-p256.pfx"),
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "ECDSA P-384",
			file:     getTestP12Path("p12-format/server-ecdsa-p384.pfx"),
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "ECDSA P-521",
			file:     getTestP12Path("p12-format/server-ecdsa-p521.pfx"),
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "SHA-256 (modern)",
			file:     getTestP12Path("p12-format/server-sha256.pfx"),
			password: "testpass",
			wantErr:  false,
		},
		{
			name:     "wrong password",
			file:     getTestP12Path("p12-format/server-rsa2048.pfx"),
			password: "wrongpass",
			wantErr:  true,
		},
		{
			name:    "file not found",
			file:    getTestP12Path("p12-format/nonexistent.pfx"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p12, err := ParseP12(tt.file, tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, p12)
			assert.Equal(t, "PKCS#12", p12.Encoding)
			assert.Equal(t, 1, p12.CertificateCount)
			assert.Equal(t, 1, p12.PrivateKeyCount)
			assert.NotEmpty(t, p12.Certificates)
			assert.NotEmpty(t, p12.PrivateKeys)
			assert.True(t, p12.Certificates[0].HasPrivateKey)
		})
	}
}

func TestParseP12FromBytes(t *testing.T) {
	data, err := os.ReadFile(getTestP12Path("p12-format/server-rsa2048.pfx"))
	require.NoError(t, err)

	p12, err := ParseP12FromBytes(data, "test.pfx", "testpass")
	require.NoError(t, err)
	assert.NotNil(t, p12)
	assert.Equal(t, 1, p12.CertificateCount)
	assert.Equal(t, 1, p12.PrivateKeyCount)
}

func TestParseP12NoPassword(t *testing.T) {
	data, err := os.ReadFile(getTestP12Path("p12-format/server-rsa2048.pfx"))
	require.NoError(t, err)

	_, err = ParseP12FromBytes(data, "test.pfx")
	assert.ErrorIs(t, err, ErrEncryptedP12)
}

func TestParseP12WrongPassword(t *testing.T) {
	data, err := os.ReadFile(getTestP12Path("p12-format/server-rsa2048.pfx"))
	require.NoError(t, err)

	_, err = ParseP12FromBytes(data, "test.pfx", "wrongpassword")
	assert.ErrorIs(t, err, ErrEncryptedP12)
}

func TestParseP12InvalidFile(t *testing.T) {
	_, err := ParseP12(getTestP12Path("traditional/rsa/ca-rsa2048.crt"), "testpass")
	assert.Error(t, err)
}

func TestParseP12CertificateDetails(t *testing.T) {
	p12, err := ParseP12(getTestP12Path("p12-format/server-rsa2048.pfx"), "testpass")
	require.NoError(t, err)

	cert := p12.Certificates[0].Cert
	assert.NotEmpty(t, cert.CommonName)
	assert.NotEmpty(t, cert.Issuer)
	assert.NotEmpty(t, cert.Subject)
	assert.NotEmpty(t, cert.NotBefore)
	assert.NotEmpty(t, cert.NotAfter)
	assert.NotEmpty(t, cert.Algorithm)
	assert.NotEmpty(t, cert.KeyType)
	assert.NotEmpty(t, cert.Bits)
	assert.NotEmpty(t, cert.SerialNumber)
}

func TestParseP12KeyDetails(t *testing.T) {
	p12, err := ParseP12(getTestP12Path("p12-format/server-rsa2048.pfx"), "testpass")
	require.NoError(t, err)

	key := p12.PrivateKeys[0].Key
	assert.NotEmpty(t, key.KeyType)
	assert.NotEmpty(t, key.Algorithm)
	assert.NotEmpty(t, key.Bits)
}

func TestParseP12MultipleCertificates(t *testing.T) {
	certDir := "test_certs"
	entries, err := os.ReadDir(filepath.Join(certDir, "p12-format"))
	if err != nil {
		t.Skip("p12-format directory not found")
	}

	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".pfx" || filepath.Ext(entry.Name()) == ".p12" {
			count++
		}
	}
	assert.Greater(t, count, 0, "Expected at least one PKCS#12 file")
}

func TestParseP12NotFound(t *testing.T) {
	_, err := ParseP12("test_certs/nonexistent/file.pfx")
	assert.Error(t, err)
}

func TestParseP12EmptyPassword(t *testing.T) {
	data, err := os.ReadFile(getTestP12Path("p12-format/server-rsa2048.pfx"))
	require.NoError(t, err)

	_, err = ParseP12FromBytes(data, "test.pfx", "")
	assert.Error(t, err)
}
