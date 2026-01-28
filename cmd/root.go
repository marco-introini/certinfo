package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "certinfo",
	Short: "Analyze certificates and private keys",
	Long:  `A CLI tool to analyze X.509 certificates and private keys (RSA, EC, DSA)`,
}

var format string
var recursive bool

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")
	rootCmd.PersistentFlags().BoolVarP(&recursive, "recursive", "r", false, "Search recursively")
}
