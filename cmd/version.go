package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// resolveVersionInfo returns the best available version, commit and build date.
// Values injected at build time via -ldflags take priority. When they are not
// set (for example when running from source with go run), build info populated
// by the Go toolchain is used as a fallback.
func resolveVersionInfo() (v, c, d string) {
	v, c, d = version, commit, date

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v, c, d
	}

	if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}

	if c == "unknown" || d == "unknown" {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if c == "unknown" {
					c = setting.Value
				}
			case "vcs.time":
				if d == "unknown" {
					d = setting.Value
				}
			}
		}
	}

	return v, c, d
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Show the current version of certinfo",
	Run: func(cmd *cobra.Command, args []string) {
		v, c, d := resolveVersionInfo()
		fmt.Printf("certinfo version %s (commit: %s, built: %s)\n", v, c, d)
	},
}

func init() {
	v, _, _ := resolveVersionInfo()
	rootCmd.Version = v
	rootCmd.AddCommand(versionCmd)
}
