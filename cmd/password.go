package cmd

import (
	"fmt"
	"os"
	"strings"
)

const envPassword = "CERTINFO_PASSWORD"

func resolvePassword(flagPassword string, passwordFile string) (string, error) {
	if flagPassword != "" {
		return flagPassword, nil
	}

	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("failed to read password file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if env := os.Getenv(envPassword); env != "" {
		return env, nil
	}

	return "", nil
}
