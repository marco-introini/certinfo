package utils

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestCertPath(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func getTestKeyPath(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func captureOutput(f func()) (string, string) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = oldStdout

	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)
	return stdoutBuf.String(), ""
}

func captureStderr(f func()) string {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = oldStderr

	var stderrBuf bytes.Buffer
	stderrBuf.ReadFrom(r)
	return stderrBuf.String()
}

func TestPrintCertificateInfo(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
		check  func(output string)
	}{
		{
			name:   "Table format",
			format: FormatTable,
			check: func(output string) {
				assert.Contains(t, output, "Filename:")
				assert.Contains(t, output, "localhost")
				assert.Contains(t, output, "PEM")
				assert.Contains(t, output, "SANs:")
			},
		},
		{
			name:   "JSON format",
			format: FormatJSON,
			check: func(output string) {
				var parsed map[string]interface{}
				err := json.Unmarshal([]byte(output), &parsed)
				require.NoError(t, err, "failed to parse JSON output")
				assert.Equal(t, "test.crt", parsed["Filename"])
				assert.Equal(t, "PEM", parsed["Encoding"])
			},
		},
	}

	cert := &certificate.CertificateInfo{
		Filename:     "test.crt",
		Encoding:     "PEM",
		CommonName:   "localhost",
		Issuer:       "Test CA",
		Subject:      "localhost",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		Algorithm:    "SHA256-RSA",
		KeyType:      "RSA",
		Bits:         2048,
		SerialNumber: "1234567890",
		IsCA:         false,
		SANs:         []string{"localhost", "test.local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _ := captureOutput(func() {
				PrintCertificateInfo(cert, tt.format)
			})
			tt.check(output)
		})
	}
}

func TestPrintCertificateInfoJSONMarshalError(t *testing.T) {
	cert := &certificate.CertificateInfo{
		Filename: "test.crt",
	}

	output, _ := captureOutput(func() {
		PrintCertificateInfo(cert, FormatJSON)
	})

	assert.NotEmpty(t, output)
	assert.Contains(t, output, "Filename")
}

func TestPrintCertificateInfoEmptySANs(t *testing.T) {
	cert := &certificate.CertificateInfo{
		Filename:     "test.crt",
		Encoding:     "PEM",
		CommonName:   "localhost",
		Issuer:       "Test CA",
		Subject:      "localhost",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		Algorithm:    "SHA256-RSA",
		KeyType:      "RSA",
		Bits:         2048,
		SerialNumber: "1234567890",
		IsCA:         false,
		SANs:         []string{},
	}

	output, _ := captureOutput(func() {
		PrintCertificateInfo(cert, FormatTable)
	})

	assert.NotContains(t, output, "SANs:")
}

func TestPrintCertificateSummaries(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
		check  func(output string)
	}{
		{
			name:   "Table format",
			format: FormatTable,
			check: func(output string) {
				assert.Contains(t, output, "FILENAME")
				assert.Contains(t, output, "cert1.crt")
				assert.Contains(t, output, "cert2.crt")
			},
		},
		{
			name:   "JSON format",
			format: FormatJSON,
			check: func(output string) {
				var parsed []map[string]interface{}
				err := json.Unmarshal([]byte(output), &parsed)
				require.NoError(t, err, "failed to parse JSON output")
				assert.Len(t, parsed, 2)
				assert.Equal(t, "cert1.crt", parsed[0]["Filename"])
				assert.Equal(t, "cert2.crt", parsed[1]["Filename"])
			},
		},
	}

	summaries := []certificate.CertificateSummary{
		{
			Filename:   "cert1.crt",
			Encoding:   "PEM",
			CommonName: "server1.local",
			Issuer:     "Test CA 1",
			Status:     "valid",
		},
		{
			Filename:   "cert2.crt",
			Encoding:   "PEM",
			CommonName: "server2.local",
			Issuer:     "Test CA 2",
			Status:     "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _ := captureOutput(func() {
				PrintCertificateSummaries(summaries, tt.format)
			})
			tt.check(output)
		})
	}
}

func TestPrintCertificateSummariesJSONMarshalError(t *testing.T) {
	summaries := []certificate.CertificateSummary{
		{
			Filename: "test.crt",
		},
	}

	output, _ := captureOutput(func() {
		PrintCertificateSummaries(summaries, FormatJSON)
	})

	assert.NotEmpty(t, output)
	assert.Contains(t, output, "Filename")
}

func TestPrintKeyInfo(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
		key    *privatekey.KeyInfo
		check  func(output string)
	}{
		{
			name:   "RSA key table",
			format: FormatTable,
			key: &privatekey.KeyInfo{
				Filename:  "test.key",
				Encoding:  "PEM",
				KeyType:   "RSA",
				Algorithm: "PKCS#1 v1.5",
				Bits:      2048,
				Curve:     "",
			},
			check: func(output string) {
				assert.Contains(t, output, "Filename:")
				assert.Contains(t, output, "test.key")
				assert.Contains(t, output, "RSA")
				assert.Contains(t, output, "2048")
			},
		},
		{
			name:   "EC key with curve table",
			format: FormatTable,
			key: &privatekey.KeyInfo{
				Filename:  "test.key",
				Encoding:  "PEM",
				KeyType:   "EC",
				Algorithm: "ECDSA",
				Bits:      256,
				Curve:     "P-256",
			},
			check: func(output string) {
				assert.Contains(t, output, "Curve:")
				assert.Contains(t, output, "P-256")
			},
		},
		{
			name:   "JSON format",
			format: FormatJSON,
			key: &privatekey.KeyInfo{
				Filename:  "test.key",
				Encoding:  "PEM",
				KeyType:   "RSA",
				Algorithm: "PKCS#1 v1.5",
				Bits:      2048,
				Curve:     "",
			},
			check: func(output string) {
				var parsed map[string]interface{}
				err := json.Unmarshal([]byte(output), &parsed)
				require.NoError(t, err, "failed to parse JSON output")
				assert.Equal(t, "test.key", parsed["Filename"])
				assert.Equal(t, "RSA", parsed["KeyType"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _ := captureOutput(func() {
				PrintKeyInfo(tt.key, tt.format)
			})
			tt.check(output)
		})
	}
}

func TestPrintKeyInfoJSONMarshalError(t *testing.T) {
	key := &privatekey.KeyInfo{
		Filename: "test.key",
	}

	output, _ := captureOutput(func() {
		PrintKeyInfo(key, FormatJSON)
	})

	assert.NotEmpty(t, output)
	assert.Contains(t, output, "Filename")
}

func TestPrintKeySummaries(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
		check  func(output string)
	}{
		{
			name:   "Table format",
			format: FormatTable,
			check: func(output string) {
				assert.Contains(t, output, "FILENAME")
				assert.Contains(t, output, "key1.key")
				assert.Contains(t, output, "key2.key")
				assert.Contains(t, output, "P-256")
			},
		},
		{
			name:   "JSON format",
			format: FormatJSON,
			check: func(output string) {
				var parsed []map[string]interface{}
				err := json.Unmarshal([]byte(output), &parsed)
				require.NoError(t, err, "failed to parse JSON output")
				assert.Len(t, parsed, 2)
				assert.Equal(t, "key1.key", parsed[0]["Filename"])
				assert.Equal(t, "key2.key", parsed[1]["Filename"])
			},
		},
	}

	summaries := []privatekey.KeySummary{
		{
			Filename: "key1.key",
			Encoding: "PEM",
			KeyType:  "RSA",
			Bits:     2048,
			Curve:    "",
		},
		{
			Filename: "key2.key",
			Encoding: "PEM",
			KeyType:  "EC",
			Bits:     256,
			Curve:    "P-256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _ := captureOutput(func() {
				PrintKeySummaries(summaries, tt.format)
			})
			tt.check(output)
		})
	}
}

func TestPrintKeySummariesEmptyCurve(t *testing.T) {
	summaries := []privatekey.KeySummary{
		{
			Filename: "rsa-key.key",
			Encoding: "PEM",
			KeyType:  "RSA",
			Bits:     2048,
			Curve:    "",
		},
	}

	output, _ := captureOutput(func() {
		PrintKeySummaries(summaries, FormatTable)
	})

	parts := strings.Fields(output)
	lastPart := parts[len(parts)-1]
	assert.Equal(t, "-", lastPart, "expected empty curve to be displayed as '-'")
}

func TestPrintKeySummariesJSONMarshalError(t *testing.T) {
	summaries := []privatekey.KeySummary{
		{
			Filename: "test.key",
		},
	}

	output, _ := captureOutput(func() {
		PrintKeySummaries(summaries, FormatJSON)
	})

	assert.NotEmpty(t, output)
	assert.Contains(t, output, "Filename")
}

func TestOutputFormatConstants(t *testing.T) {
	assert.Equal(t, OutputFormat("table"), FormatTable)
	assert.Equal(t, OutputFormat("json"), FormatJSON)
}

func TestPrintCertificateSummariesMultiple(t *testing.T) {
	summaries := []certificate.CertificateSummary{
		{
			Filename:   "cert1.crt",
			Encoding:   "PEM",
			CommonName: "server1.local",
			Issuer:     "Test CA",
			Status:     "valid",
		},
		{
			Filename:   "cert2.crt",
			Encoding:   "PEM",
			CommonName: "server2.local",
			Issuer:     "Test CA",
			Status:     "expired",
		},
		{
			Filename:   "cert3.crt",
			Encoding:   "PEM",
			CommonName: "server3.local",
			Issuer:     "Test CA",
			Status:     "expiring",
		},
	}

	output, _ := captureOutput(func() {
		PrintCertificateSummaries(summaries, FormatTable)
	})

	assert.Contains(t, output, "cert1.crt")
	assert.Contains(t, output, "cert2.crt")
	assert.Contains(t, output, "cert3.crt")
	assert.Contains(t, output, "valid")
	assert.Contains(t, output, "expired")
	assert.Contains(t, output, "expiring")
}

func TestPrintKeySummariesMultiple(t *testing.T) {
	summaries := []privatekey.KeySummary{
		{
			Filename: "rsa.key",
			Encoding: "PEM",
			KeyType:  "RSA",
			Bits:     2048,
			Curve:    "",
		},
		{
			Filename: "ec.key",
			Encoding: "PEM",
			KeyType:  "EC",
			Bits:     256,
			Curve:    "P-256",
		},
		{
			Filename: "ed25519.key",
			Encoding: "PEM",
			KeyType:  "Ed25519",
			Bits:     256,
			Curve:    "",
		},
	}

	output, _ := captureOutput(func() {
		PrintKeySummaries(summaries, FormatTable)
	})

	assert.Contains(t, output, "rsa.key")
	assert.Contains(t, output, "ec.key")
	assert.Contains(t, output, "ed25519.key")
	assert.Contains(t, output, "RSA")
	assert.Contains(t, output, "EC")
	assert.Contains(t, output, "Ed25519")
}
