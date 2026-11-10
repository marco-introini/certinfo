package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	certHostname string
)

var certCmd = &cobra.Command{
	Use:   "cert [file]",
	Short: "Show detailed certificate information",
	Long:  "Show detailed information about a single X.509 certificate file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cert, err := certificate.ParseCertificate(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if certHostname != "" && !cert.MatchesHostname(certHostname) {
			_, _ = fmt.Fprintf(os.Stderr, "Error: certificate is not valid for hostname %q\n", certHostname)
			os.Exit(1)
		}

		utils.PrintCertificateInfo(cert, utils.OutputFormat(format))
	},
}

func init() {
	rootCmd.AddCommand(certCmd)
	certCmd.Flags().StringVar(&certHostname, "hostname", "", "Verify the certificate is valid for the given hostname")
}
