package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/spf13/cobra"
)

var (
	caFiles   []string
	checkCRL  bool
	checkOCSP bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify [cert-file]",
	Short: "Verify a certificate chain",
	Long:  "Verify the certificate chain against the system trust store or a custom CA bundle",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cert, err := certificate.ParseCertificate(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		opts := certificate.VerifyOptions{
			CAFiles:   caFiles,
			CheckCRL:  checkCRL,
			CheckOCSP: checkOCSP,
		}
		err = cert.Verify(opts)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Certificate chain is valid")
	},
}

func init() {
	verifyCmd.Flags().StringSliceVar(&caFiles, "ca", nil, "CA certificate file(s) to use for verification")
	verifyCmd.Flags().BoolVar(&checkCRL, "crl", false, "Also check Certificate Revocation Lists (CRL)")
	verifyCmd.Flags().BoolVar(&checkOCSP, "ocsp", false, "Also check OCSP responders")
	rootCmd.AddCommand(verifyCmd)
}
