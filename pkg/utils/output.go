package utils

import (
	"encoding/json"
	"fmt"
	"os"
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

	if len(cert.SANs) > 0 {
		fmt.Fprintf(w, "SANs:\t%v\n", cert.SANs)
	}
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

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "FILENAME\tENCODING\tCN\tISSUER\tSTATUS\n")
	for _, s := range summaries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			s.Filename, s.Encoding, s.CommonName, s.Issuer, s.Status)
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

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "FILENAME\tENCODING\tTYPE\tBITS\tCURVE\n")
	for _, s := range summaries {
		curve := s.Curve
		if curve == "" {
			curve = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			s.Filename, s.Encoding, s.KeyType, s.Bits, curve)
	}
}
