package utils

import (
	"os"
	"strings"

	"golang.org/x/term"
)

var ColorsEnabled = false

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	Bold        = "\033[1m"
)

func EnableColors() {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		ColorsEnabled = false
		return
	}
	ColorsEnabled = isStdoutTTY()
}

func DisableColors() {
	ColorsEnabled = false
}

func isStdoutTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func Color(s string, color string) string {
	if !ColorsEnabled {
		return s
	}
	return color + s + ColorReset
}

// VisibleLen returns the length of the string without ANSI color sequences.
func VisibleLen(s string) int {
	if !strings.Contains(s, "\033[") {
		return len(s)
	}
	visible := true
	length := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			visible = false
			continue
		}
		if !visible && s[i] == 'm' {
			visible = true
			continue
		}
		if visible {
			length++
		}
	}
	return length
}
