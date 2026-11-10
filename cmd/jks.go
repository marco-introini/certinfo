package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/jks"
	"github.com/marco-introini/certinfo/pkg/utils"
	"github.com/spf13/cobra"
)

var (
	jksPassword     string
	jksPasswordFile string
)

var jksCmd = &cobra.Command{
	Use:   "jks [file]",
	Short: "Show information about a Java KeyStore file",
	Long:  "Show detailed information about a Java KeyStore (JKS) file containing certificates and private keys",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password, err := resolvePassword(jksPassword, jksPasswordFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		info, err := jks.ParseJKS(args[0], password)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		utils.PrintJKSInfo(info, utils.OutputFormat(format))
	},
}

func init() {
	jksCmd.Flags().StringVarP(&jksPassword, "password", "p", "", "Password for the JKS file")
	jksCmd.Flags().StringVar(&jksPasswordFile, "password-file", "", "File containing the password for the JKS file")
	rootCmd.AddCommand(jksCmd)
}
