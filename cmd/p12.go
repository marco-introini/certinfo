package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/pkcs12"
	"github.com/marco-introini/certinfo/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	p12Password     string
	p12PasswordFile string
)

var p12Cmd = &cobra.Command{
	Use:   "p12 [file]",
	Short: "Show detailed information about a PKCS#12 file",
	Long:  "Show detailed information about a single PKCS#12 file containing certificates and private keys",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password, err := resolvePassword(p12Password, p12PasswordFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		p12, err := pkcs12.ParseP12(args[0], password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		utils.PrintP12Info(p12, utils.OutputFormat(format))
	},
}

func init() {
	p12Cmd.Flags().StringVarP(&p12Password, "password", "p", "", "Password for PKCS#12 file")
	p12Cmd.Flags().StringVar(&p12PasswordFile, "password-file", "", "File containing the password for the PKCS#12 file")
	rootCmd.AddCommand(p12Cmd)
}
