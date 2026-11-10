package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/marco-introini/certinfo/pkg/certificate"
	"github.com/marco-introini/certinfo/pkg/pkcs12"
	"github.com/marco-introini/certinfo/pkg/privatekey"
)

func writef(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

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
	defer func() { _ = w.Flush() }()

	writef(w, "Filename:\t%s\n", cert.Filename)
	writef(w, "Encoding:\t%s\n", cert.Encoding)
	writef(w, "Common Name:\t%s\n", cert.CommonName)
	writef(w, "Issuer:\t%s\n", cert.Issuer)
	writef(w, "Subject:\t%s\n", cert.Subject)
	writef(w, "Not Before:\t%s\n", formatDate(cert.NotBefore))
	writef(w, "Not After:\t%s\n", formatDate(cert.NotAfter))
	writef(w, "Algorithm:\t%s\n", cert.Algorithm)
	writef(w, "Bits:\t%d\n", cert.Bits)
	writef(w, "Serial Number:\t%s\n", cert.SerialNumber)
	writef(w, "Is CA:\t%v\n", cert.IsCA)
	writef(w, "Quantum Safe:\t%v\n", cert.IsQuantumSafe)
	if len(cert.PQCTypes) > 0 {
		writef(w, "PQC Types:\t%v\n", cert.PQCTypes)
	}

	if len(cert.SANs) > 0 {
		writef(w, "SANs:\t%v\n", cert.SANs)
	}
	if len(cert.ExtKeyUsageStrings) > 0 {
		writef(w, "Ext Key Usage:\t%v\n", cert.ExtKeyUsageStrings)
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
			case "expiring soon":
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
	defer func() { _ = w.Flush() }()

	writef(w, "Filename:\t%s\n", key.Filename)
	writef(w, "Encoding:\t%s\n", key.Encoding)
	writef(w, "Key Type:\t%s\n", key.KeyType)
	writef(w, "Algorithm:\t%s\n", key.Algorithm)
	writef(w, "Bits:\t%d\n", key.Bits)
	writef(w, "Quantum Safe:\t%v\n", key.IsQuantumSafe)
	if key.Curve != "" {
		writef(w, "Curve:\t%s\n", key.Curve)
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

func PrintP12Info(p12 *pkcs12.P12Info, format OutputFormat) {
	if format == FormatJSON {
		type jsonOutput struct {
			Filename                string                        `json:"filename"`
			Encoding                string                        `json:"encoding"`
			MacAlgorithm            string                        `json:"macAlgorithm"`
			MacIterations           int                           `json:"macIterations"`
			KdfAlgorithm            string                        `json:"kdfAlgorithm"`
			KeyEncryptionAlgorithm  string                        `json:"keyEncryptionAlgorithm"`
			CertEncryptionAlgorithm string                        `json:"certEncryptionAlgorithm"`
			CertificateCount        int                           `json:"certificateCount"`
			PrivateKeyCount         int                           `json:"privateKeyCount"`
			Certificates            []certificate.CertificateInfo `json:"certificates"`
			PrivateKeys             []privatekey.KeyInfo          `json:"privateKeys"`
		}
		out := jsonOutput{
			Filename:                p12.Filename,
			Encoding:                p12.Encoding,
			MacAlgorithm:            p12.MacAlgorithm,
			MacIterations:           p12.MacIterations,
			KdfAlgorithm:            p12.KdfAlgorithm,
			KeyEncryptionAlgorithm:  p12.KeyEncryptionAlgorithm,
			CertEncryptionAlgorithm: p12.CertEncryptionAlgorithm,
			CertificateCount:        p12.CertificateCount,
			PrivateKeyCount:         p12.PrivateKeyCount,
			Certificates:            []certificate.CertificateInfo{},
			PrivateKeys:             []privatekey.KeyInfo{},
		}
		for _, c := range p12.Certificates {
			out.Certificates = append(out.Certificates, *c.Cert)
		}
		for _, k := range p12.PrivateKeys {
			out.PrivateKeys = append(out.PrivateKeys, *k.Key)
		}
		jsonBytes, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonBytes))
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer func() { _ = w.Flush() }()

	writef(w, "Filename:\t%s\n", p12.Filename)
	writef(w, "Encoding:\t%s\n", p12.Encoding)
	if p12.MacAlgorithm != "" {
		if p12.MacIterations > 1 {
			writef(w, "MAC Algorithm:\t%s (%d iter)\n", p12.MacAlgorithm, p12.MacIterations)
		} else {
			writef(w, "MAC Algorithm:\t%s\n", p12.MacAlgorithm)
		}
	}
	if p12.KdfAlgorithm != "" {
		writef(w, "KDF Algorithm:\t%s\n", p12.KdfAlgorithm)
	}
	if p12.KeyEncryptionAlgorithm != "" {
		writef(w, "Key Encryption:\t%s\n", p12.KeyEncryptionAlgorithm)
	}
	if p12.CertEncryptionAlgorithm != "" {
		writef(w, "Cert Encryption:\t%s\n", p12.CertEncryptionAlgorithm)
	}
	writef(w, "Certificate Count:\t%d\n", p12.CertificateCount)
	writef(w, "Private Key Count:\t%d\n", p12.PrivateKeyCount)
	writef(w, "\n")

	for i, c := range p12.Certificates {
		writef(w, "--- Certificate %d ---\n", i+1)
		PrintCertificateInfo(c.Cert, format)
		if c.HasPrivateKey {
			writef(w, "Has Private Key:\tYes\n")
		}
		writef(w, "\n")
	}

	for i, k := range p12.PrivateKeys {
		writef(w, "--- Private Key %d ---\n", i+1)
		PrintKeyInfo(k.Key, format)
		writef(w, "\n")
	}
}
