package cmd

import (
	"certinfo/pkg/certificate"
	"certinfo/pkg/utils"
	"os"

	"github.com/spf13/cobra"
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
			os.Stderr.WriteString("Error: " + err.Error() + "\n")
			os.Exit(1)
		}

		utils.PrintCertificateSummaries(summaries, utils.OutputFormat(format))
	},
}

func init() {
	dirCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")
	dirCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Search recursively")
	rootCmd.AddCommand(dirCmd)
}
