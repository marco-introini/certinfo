package cmd

import (
	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/marco-introini/certinfo/pkg/utils"
	"os"

	"github.com/spf13/cobra"
)

var keydirCmd = &cobra.Command{
	Use:   "keydir [directory]",
	Short: "Summarize private keys in a directory",
	Long:  "Summarize all private keys in a directory (type and bits)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var summaries []privatekey.KeySummary
		var err error

		if recursive {
			summaries, err = privatekey.SummarizeDirectoryRecursive(args[0])
		} else {
			summaries, err = privatekey.SummarizeDirectory(args[0])
		}

		if err != nil {
			os.Stderr.WriteString("Error: " + err.Error() + "\n")
			os.Exit(1)
		}

		utils.PrintKeySummaries(summaries, utils.OutputFormat(format))
	},
}

func init() {
	keydirCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")
	keydirCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Search recursively")
	rootCmd.AddCommand(keydirCmd)
}
