package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/publickey"
	"github.com/marco-introini/certinfo/pkg/utils"
	"github.com/spf13/cobra"
)

var pubkeyCmd = &cobra.Command{
	Use:   "pubkey [file]",
	Short: "Show public key information",
	Long:  "Show information about a public key file (RSA, EC, Ed25519, PQC)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key, err := publickey.ParsePublicKey(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		utils.PrintPublicKeyInfo(key, utils.OutputFormat(format))
	},
}

func init() {
	rootCmd.AddCommand(pubkeyCmd)
}
