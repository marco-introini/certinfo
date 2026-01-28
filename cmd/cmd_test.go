package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestDataPath() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "test_certs")
}

func getTestCertPath(relPath string) string {
	return filepath.Join(getTestDataPath(), relPath)
}

func getTestKeyPath(relPath string) string {
	return filepath.Join(getTestDataPath(), relPath)
}

func runCertinfo(args ...string) (stdout, stderr string, exitCode int) {
	wd, _ := os.Getwd()
	cmd := exec.Command("go", append([]string{"run", "./main.go"}, args...)...)
	cmd.Dir = filepath.Join(wd, "..")

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode
}

func TestCertCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		exitCode  int
		checkFunc func(stdout string)
	}{
		{
			name:     "valid RSA certificate",
			args:     []string{"cert", getTestCertPath("traditional/rsa/server-rsa2048.crt")},
			wantErr:  false,
			exitCode: 0,
			checkFunc: func(stdout string) {
				assert.Contains(t, stdout, "Filename:")
				assert.Contains(t, stdout, "localhost")
				assert.Contains(t, stdout, "PEM")
				assert.Contains(t, stdout, "RSA")
			},
		},
		{
			name:     "ECDSA certificate",
			args:     []string{"cert", getTestCertPath("traditional/ecdsa/server-ecdsa-p256.crt")},
			wantErr:  false,
			exitCode: 0,
			checkFunc: func(stdout string) {
				assert.Contains(t, stdout, "EC")
				assert.Contains(t, stdout, "P-256")
			},
		},
		{
			name:     "nonexistent file",
			args:     []string{"cert", "/nonexistent/cert.crt"},
			wantErr:  true,
			exitCode: 1,
			checkFunc: func(stderr string) {
				assert.Contains(t, stderr, "Error:")
			},
		},
		{
			name:     "invalid certificate",
			args:     []string{"cert", getTestKeyPath("traditional/rsa/server-rsa2048.key")},
			wantErr:  true,
			exitCode: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, exitCode := runCertinfo(tt.args...)

			if tt.wantErr {
				assert.NotEqual(t, 0, exitCode)
			} else {
				assert.Equal(t, 0, exitCode)
			}

			if tt.checkFunc != nil {
				if strings.Contains(stderr, "Error:") {
					tt.checkFunc(stderr)
				} else {
					tt.checkFunc(stdout)
				}
			}
		})
	}
}

func TestCertCommandJSONFormat(t *testing.T) {
	stdout, _, exitCode := runCertinfo("cert", getTestCertPath("traditional/rsa/server-rsa2048.crt"), "-f", "json")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, `"Filename"`)
	assert.Contains(t, stdout, `"Encoding": "PEM"`)
	assert.Contains(t, stdout, `"KeyType": "RSA"`)
}

func TestKeyCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		exitCode  int
		checkFunc func(stdout string)
	}{
		{
			name:     "valid RSA key",
			args:     []string{"key", getTestKeyPath("traditional/rsa/server-rsa2048.key")},
			wantErr:  false,
			exitCode: 0,
			checkFunc: func(stdout string) {
				assert.Contains(t, stdout, "Filename:")
				assert.Contains(t, stdout, "RSA")
				assert.Contains(t, stdout, "2048")
			},
		},
		{
			name:     "EC key",
			args:     []string{"key", getTestKeyPath("traditional/ecdsa/server-ecdsa-p256.key")},
			wantErr:  false,
			exitCode: 0,
			checkFunc: func(stdout string) {
				assert.Contains(t, stdout, "EC")
				assert.Contains(t, stdout, "P-256")
			},
		},
		{
			name:     "nonexistent file",
			args:     []string{"key", "/nonexistent/key.key"},
			wantErr:  true,
			exitCode: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, exitCode := runCertinfo(tt.args...)

			if tt.wantErr {
				assert.NotEqual(t, 0, exitCode)
			} else {
				assert.Equal(t, 0, exitCode)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(stdout)
			}
		})
	}
}

func TestDirCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		exitCode  int
		checkFunc func(stdout string)
	}{
		{
			name:     "RSA directory",
			args:     []string{"dir", getTestCertPath("traditional/rsa")},
			wantErr:  false,
			exitCode: 0,
			checkFunc: func(stdout string) {
				assert.Contains(t, stdout, "FILENAME")
				assert.Contains(t, stdout, "server-rsa2048.crt")
			},
		},
		{
			name:     "nonexistent directory",
			args:     []string{"dir", "/nonexistent/path"},
			wantErr:  true,
			exitCode: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, exitCode := runCertinfo(tt.args...)

			if tt.wantErr {
				assert.NotEqual(t, 0, exitCode)
			} else {
				assert.Equal(t, 0, exitCode)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(stdout)
			}
		})
	}
}

func TestDirCommandRecursive(t *testing.T) {
	stdout, _, exitCode := runCertinfo("dir", getTestCertPath("traditional"), "-r")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "FILENAME")
	assert.Contains(t, stdout, "server-rsa2048.crt")
	assert.Contains(t, stdout, "server-ecdsa-p256.crt")
}

func TestKeydirCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		exitCode  int
		checkFunc func(stdout string)
	}{
		{
			name:     "RSA keys directory",
			args:     []string{"keydir", getTestKeyPath("traditional/rsa")},
			wantErr:  false,
			exitCode: 0,
			checkFunc: func(stdout string) {
				assert.Contains(t, stdout, "FILENAME")
				assert.Contains(t, stdout, "server-rsa2048.key")
			},
		},
		{
			name:     "nonexistent directory",
			args:     []string{"keydir", "/nonexistent/path"},
			wantErr:  true,
			exitCode: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, exitCode := runCertinfo(tt.args...)

			if tt.wantErr {
				assert.NotEqual(t, 0, exitCode)
			} else {
				assert.Equal(t, 0, exitCode)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(stdout)
			}
		})
	}
}

func TestKeydirCommandRecursive(t *testing.T) {
	stdout, _, exitCode := runCertinfo("keydir", getTestKeyPath("traditional"), "-r")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "FILENAME")
	assert.Contains(t, stdout, "server-rsa2048.key")
	assert.Contains(t, stdout, "server-ecdsa-p256.key")
}

func TestRootCommand(t *testing.T) {
	stdout, _, exitCode := runCertinfo()

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "certinfo")
	assert.Contains(t, stdout, "Available Commands")
}

func TestRootCommandHelp(t *testing.T) {
	stdout, _, exitCode := runCertinfo("--help")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "certinfo")
	assert.Contains(t, stdout, "Available Commands")
}

func TestCertCommandHelp(t *testing.T) {
	stdout, _, exitCode := runCertinfo("cert", "--help")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "certinfo cert")
	assert.Contains(t, stdout, "[file]")
}

func TestInvalidCommand(t *testing.T) {
	_, _, exitCode := runCertinfo("invalid-command")

	assert.NotEqual(t, 0, exitCode)
}

func TestCertCommandEmptyFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "empty.crt")
	err := os.WriteFile(tmpFile, []byte{}, 0644)
	require.NoError(t, err)

	_, stderr, exitCode := runCertinfo("cert", tmpFile)

	assert.NotEqual(t, 0, exitCode)
	assert.Contains(t, stderr, "Error:")
}

func TestDirCommandEmptyDirectory(t *testing.T) {
	emptyDir := t.TempDir()

	stdout, _, exitCode := runCertinfo("dir", emptyDir)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "FILENAME")
}
