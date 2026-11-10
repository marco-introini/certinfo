package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	failOnExpired      bool
	failOnExpiringSoon bool
)

var dirCmd = &cobra.Command{
	Use:   "dir [directory]",
	Short: "Summarize certificates in a directory",
	Long:  "Summarize all X.509 certificates in a directory (CN and expiration)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var summaries []certificate.CertificateSummary
		var err error

		if recursive {
			summaries, err = certificate.SummarizeDirectoryRecursive(args[0])
		} else {
			summaries, err = certificate.SummarizeDirectory(args[0])
		}

		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		utils.PrintCertificateSummaries(summaries, utils.OutputFormat(format))

		for _, s := range summaries {
			if failOnExpired && s.Status == "expired" {
				os.Exit(2)
			}
			if failOnExpiringSoon && s.Status == "expiring soon" {
				os.Exit(2)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
	dirCmd.Flags().BoolVar(&failOnExpired, "fail-on-expired", false, "Exit with code 2 if any certificate is expired")
	dirCmd.Flags().BoolVar(&failOnExpiringSoon, "fail-on-expiring-soon", false, "Exit with code 2 if any certificate is expiring soon")
}
