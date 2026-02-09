package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/privatekey"
)

type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
)

const dateFormat = "2006-01-02 15:04:05"

func init() {
	if _, ok := os.LookupEnv("NO_COLOR"); !ok && os.Getenv("TERM") != "" {
		ColorsEnabled = true
	}
}

func formatDate(t time.Time) string {
	return t.Format(dateFormat)
}

func PrintCertificateInfo(cert *certificate.CertificateInfo, format OutputFormat) {
	if format == FormatJSON {
		jsonBytes, err := json.MarshalIndent(cert, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonBytes))
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "Filename:\t%s\n", cert.Filename)
	fmt.Fprintf(w, "Encoding:\t%s\n", cert.Encoding)
	fmt.Fprintf(w, "Common Name:\t%s\n", cert.CommonName)
	fmt.Fprintf(w, "Issuer:\t%s\n", cert.Issuer)
	fmt.Fprintf(w, "Subject:\t%s\n", cert.Subject)
	fmt.Fprintf(w, "Not Before:\t%s\n", formatDate(cert.NotBefore))
	fmt.Fprintf(w, "Not After:\t%s\n", formatDate(cert.NotAfter))
	fmt.Fprintf(w, "Algorithm:\t%s\n", cert.Algorithm)
	fmt.Fprintf(w, "Bits:\t%d\n", cert.Bits)
	fmt.Fprintf(w, "Serial Number:\t%s\n", cert.SerialNumber)
	fmt.Fprintf(w, "Is CA:\t%v\n", cert.IsCA)
	fmt.Fprintf(w, "Quantum Safe:\t%v\n", cert.IsQuantumSafe)
	if len(cert.PQCTypes) > 0 {
		fmt.Fprintf(w, "PQC Types:\t%v\n", cert.PQCTypes)
	}

	if len(cert.SANs) > 0 {
		fmt.Fprintf(w, "SANs:\t%v\n", cert.SANs)
	}
	if len(cert.ExtKeyUsageStrings) > 0 {
		fmt.Fprintf(w, "Ext Key Usage:\t%v\n", cert.ExtKeyUsageStrings)
	}
}

func padRight(s string, width int) string {
	vlen := VisibleLen(s)
	if vlen >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vlen)
}

func PrintCertificateSummaries(summaries []certificate.CertificateSummary, format OutputFormat) {
	if format == FormatJSON {
		jsonBytes, err := json.MarshalIndent(summaries, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonBytes))
		return
	}

	headers := []string{"FILENAME", "ENCODING", "CN", "ISSUER", "STATUS", "QUANTUM SAFE", "PQC TYPES"}
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, s := range summaries {
		pqcTypes := "-"
		if len(s.PQCTypes) > 0 {
			pqcTypes = strings.Join(s.PQCTypes, ", ")
		}
		data := []string{s.Filename, s.Encoding, s.CommonName, s.Issuer, s.Status, "Yes", pqcTypes}
		if !s.IsQuantumSafe {
			data[5] = "No"
		}
		for i, d := range data {
			if len(d) > colWidths[i] {
				colWidths[i] = len(d)
			}
		}
	}

	// Print headers
	for i, h := range headers {
		text := h
		if ColorsEnabled {
			text = Color(h, Bold+ColorCyan)
		}
		fmt.Print(padRight(text, colWidths[i]))
		if i < len(headers)-1 {
			fmt.Print("  ")
		}
	}
	fmt.Println()

	// Print rows
	for _, s := range summaries {
		pqcTypes := "-"
		if len(s.PQCTypes) > 0 {
			pqcTypes = strings.Join(s.PQCTypes, ", ")
		}

		status := s.Status
		qs := "No"
		if s.IsQuantumSafe {
			qs = "Yes"
		}

		if ColorsEnabled {
			switch s.Status {
			case "valid":
				status = Color(s.Status, ColorGreen)
			case "expired":
				status = Color(s.Status, ColorRed)
			case "expiring":
				status = Color(s.Status, ColorYellow)
			}
			if s.IsQuantumSafe {
				qs = Color(qs, ColorGreen)
			} else {
				qs = Color(qs, ColorYellow)
			}
		}

		row := []string{
			padRight(s.Filename, colWidths[0]),
			padRight(s.Encoding, colWidths[1]),
			padRight(s.CommonName, colWidths[2]),
			padRight(s.Issuer, colWidths[3]),
			padRight(status, colWidths[4]),
			padRight(qs, colWidths[5]),
			padRight(pqcTypes, colWidths[6]),
		}
		for i, cell := range row {
			fmt.Print(cell)
			if i < len(row)-1 {
				fmt.Print("  ")
			}
		}
		fmt.Println()
	}
}

func PrintKeyInfo(key *privatekey.KeyInfo, format OutputFormat) {
	if format == FormatJSON {
		jsonBytes, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonBytes))
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "Filename:\t%s\n", key.Filename)
	fmt.Fprintf(w, "Encoding:\t%s\n", key.Encoding)
	fmt.Fprintf(w, "Key Type:\t%s\n", key.KeyType)
	fmt.Fprintf(w, "Algorithm:\t%s\n", key.Algorithm)
	fmt.Fprintf(w, "Bits:\t%d\n", key.Bits)
	fmt.Fprintf(w, "Quantum Safe:\t%v\n", key.IsQuantumSafe)
	if key.Curve != "" {
		fmt.Fprintf(w, "Curve:\t%s\n", key.Curve)
	}
}

func PrintKeySummaries(summaries []privatekey.KeySummary, format OutputFormat) {
	if format == FormatJSON {
		jsonBytes, err := json.MarshalIndent(summaries, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonBytes))
		return
	}

	headers := []string{"FILENAME", "ENCODING", "TYPE", "BITS", "QUANTUM SAFE"}
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, s := range summaries {
		bitsStr := fmt.Sprintf("%d", s.Bits)
		qs := "Yes"
		if !s.IsQuantumSafe {
			qs = "No"
		}
		data := []string{s.Filename, s.Encoding, s.KeyType, bitsStr, qs}
		for i, d := range data {
			if len(d) > colWidths[i] {
				colWidths[i] = len(d)
			}
		}
	}

	// Print headers
	for i, h := range headers {
		text := h
		if ColorsEnabled {
			text = Color(h, Bold+ColorCyan)
		}
		fmt.Print(padRight(text, colWidths[i]))
		if i < len(headers)-1 {
			fmt.Print("  ")
		}
	}
	fmt.Println()

	// Print rows
	for _, s := range summaries {
		qs := "No"
		if s.IsQuantumSafe {
			qs = "Yes"
		}

		if ColorsEnabled {
			if s.IsQuantumSafe {
				qs = Color(qs, ColorGreen)
			} else {
				qs = Color(qs, ColorYellow)
			}
		}

		row := []string{
			padRight(s.Filename, colWidths[0]),
			padRight(s.Encoding, colWidths[1]),
			padRight(s.KeyType, colWidths[2]),
			padRight(fmt.Sprintf("%d", s.Bits), colWidths[3]),
			padRight(qs, colWidths[4]),
		}
		for i, cell := range row {
			fmt.Print(cell)
			if i < len(row)-1 {
				fmt.Print("  ")
			}
		}
		fmt.Println()
	}
}
