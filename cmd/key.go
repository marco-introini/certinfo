package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/marco-introini/certinfo/pkg/utils"
	"github.com/spf13/cobra"
)

var keyPassword string

var keyCmd = &cobra.Command{
	Use:   "key [file]",
	Short: "Show private key information",
	Long:  "Show information about a private key file (RSA, EC, Ed25519, PQC)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password := keyPassword

		key, err := privatekey.ParsePrivateKey(args[0], password)
		if err != nil {
			if err == privatekey.ErrEncryptedKey && password == "" {
				password, err = promptPassword("Enter password for encrypted key: ")
				if err == nil {
					key, err = privatekey.ParsePrivateKey(args[0], password)
				}
			}
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}
		utils.PrintKeyInfo(key, utils.OutputFormat(format))
	},
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprintln(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(password, "\n"), nil
}

func init() {
	keyCmd.Flags().StringVarP(&keyPassword, "password", "p", "", "Password for encrypted private key")
	rootCmd.AddCommand(keyCmd)
}
