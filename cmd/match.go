package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/marco-introini/certinfo/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	matchPassword     string
	matchPasswordFile string
)

var matchCmd = &cobra.Command{
	Use:   "match [cert-file] [key-file]",
	Short: "Check if a certificate and private key match",
	Long:  "Verify that the public key in the certificate corresponds to the given private key",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		password, err := resolvePassword(matchPassword, matchPasswordFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cert, err := certificate.ParseCertificate(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		key, err := privatekey.ParsePrivateKey(args[1], password)
		if err != nil {
			if err == privatekey.ErrEncryptedKey && password == "" {
				password, err = promptPassword("Enter password for encrypted key: ")
				if err == nil {
					key, err = privatekey.ParsePrivateKey(args[1], password)
				}
			}
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		match, message, err := key.MatchesCertificate(cert)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if format == string(utils.FormatJSON) {
			output := struct {
				Match   bool   `json:"match"`
				Message string `json:"message"`
			}{
				Match:   match,
				Message: message,
			}
			utils.PrintJSON(output)
			return
		}

		if match {
			fmt.Println(message)
		} else {
			fmt.Println(message)
			os.Exit(1)
		}
	},
}

func init() {
	matchCmd.Flags().StringVarP(&matchPassword, "password", "p", "", "Password for encrypted private key")
	matchCmd.Flags().StringVar(&matchPasswordFile, "password-file", "", "File containing the password for the encrypted private key")
	rootCmd.AddCommand(matchCmd)
}
