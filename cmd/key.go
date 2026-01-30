package cmd

import (
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/marco-introini/certinfo/pkg/utils"
	"os"

	"github.com/spf13/cobra"
)

var keyCmd = &cobra.Command{
	Use:   "key [file]",
	Short: "Show private key information",
	Long:  "Show information about a private key file (RSA, EC, Ed25519, PQC)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key, err := privatekey.ParsePrivateKey(args[0])
		if err != nil {
			os.Stderr.WriteString("Error: " + err.Error() + "\n")
			os.Exit(1)
		}
		utils.PrintKeyInfo(key, utils.OutputFormat(format))
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)
}
