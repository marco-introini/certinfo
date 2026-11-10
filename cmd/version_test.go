package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCommand(t *testing.T) {
	stdout, _, exitCode := runCertinfo("version")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "certinfo version")
}

func TestResolveVersionInfo(t *testing.T) {
	v, c, d := resolveVersionInfo()

	assert.NotEmpty(t, v, "version should not be empty")
	assert.NotEmpty(t, c, "commit should not be empty")
	assert.NotEmpty(t, d, "build date should not be empty")
}

func TestVersionCommandWithLdflags(t *testing.T) {
	wd, _ := os.Getwd()
	cmd := exec.Command("go", "run", "-ldflags",
		"-X github.com/marco-introini/certinfo/cmd.version=test-version -X github.com/marco-introini/certinfo/cmd.commit=abc123 -X github.com/marco-introini/certinfo/cmd.date=2026-11-10",
		".", "version")
	cmd.Dir = filepath.Join(wd, "..")

	stdout, err := cmd.Output()
	require.NoError(t, err)

	output := string(stdout)
	assert.Contains(t, output, "certinfo version test-version")
	assert.Contains(t, output, "commit: abc123")
	assert.Contains(t, output, "built: 2026-11-10")
}
