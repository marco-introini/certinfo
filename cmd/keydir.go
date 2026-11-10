package cmd

import (
	"fmt"
	"os"

	"github.com/marco-introini/certinfo/pkg/privatekey"
	"github.com/marco-introini/certinfo/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	keydirPassword     string
	keydirPasswordFile string
)

var keydirCmd = &cobra.Command{
	Use:   "keydir [directory]",
	Short: "Summarize private keys in a directory",
	Long:  "Summarize all private keys in a directory (type and bits)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password, err := resolvePassword(keydirPassword, keydirPasswordFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		var summaries []privatekey.KeySummary
		if recursive {
			summaries, err = privatekey.SummarizeDirectoryRecursive(args[0], password)
		} else {
			summaries, err = privatekey.SummarizeDirectory(args[0], password)
		}

		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		utils.PrintKeySummaries(summaries, utils.OutputFormat(format))
	},
}

func init() {
	keydirCmd.Flags().StringVarP(&keydirPassword, "password", "p", "", "Password for encrypted private keys")
	keydirCmd.Flags().StringVar(&keydirPasswordFile, "password-file", "", "File containing the password for encrypted private keys")
	rootCmd.AddCommand(keydirCmd)
}
