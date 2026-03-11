package cmd

import (
	"os"

	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/marco-introini/certinfo/pkg/utils"

	"github.com/spf13/cobra"
)

var keydirPassword string

var keydirCmd = &cobra.Command{
	Use:   "keydir [directory]",
	Short: "Summarize private keys in a directory",
	Long:  "Summarize all private keys in a directory (type and bits)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var summaries []privatekey.KeySummary
		var err error

		if recursive {
			summaries, err = privatekey.SummarizeDirectoryRecursive(args[0], keydirPassword)
		} else {
			summaries, err = privatekey.SummarizeDirectory(args[0], keydirPassword)
		}

		if err != nil {
			os.Stderr.WriteString("Error: " + err.Error() + "\n")
			os.Exit(1)
		}

		utils.PrintKeySummaries(summaries, utils.OutputFormat(format))
	},
}

func init() {
	keydirCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Search recursively")
	keydirCmd.Flags().StringVarP(&keydirPassword, "password", "p", "", "Password for encrypted private keys")
	rootCmd.AddCommand(keydirCmd)
}
