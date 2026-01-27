package cmd

import (
	"certinfo/pkg/certificate"
	"certinfo/pkg/utils"
	"os"

	"github.com/spf13/cobra"
)

var certCmd = &cobra.Command{
	Use:   "cert [file]",
	Short: "Show detailed certificate information",
	Long:  "Show detailed information about a single X.509 certificate file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cert, err := certificate.ParseCertificate(args[0])
		if err != nil {
			os.Stderr.WriteString("Error: " + err.Error() + "\n")
			os.Exit(1)
		}
		utils.PrintCertificateInfo(cert, utils.OutputFormat(format))
	},
}

func init() {
	certCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")
	rootCmd.AddCommand(certCmd)
}
