package certificate

import (
	"os"
	"path/filepath"
	"time"
)

type CertificateSummary struct {
	Filename   string
	Encoding   string
	CommonName string
	Issuer     string
	Status     string
}

func SummarizeDirectory(dirPath string) ([]CertificateSummary, error) {
	var summaries []CertificateSummary

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())

		cert, err := ParseCertificate(filePath)
		if err != nil {
			continue
		}

		summary := CertificateSummary{
			Filename:   entry.Name(),
			Encoding:   cert.Encoding,
			CommonName: cert.CommonName,
			Issuer:     cert.Issuer,
		}

		notAfter, _ := time.Parse("2006-01-02 15:04:05", cert.NotAfter)
		daysUntil := int(time.Until(notAfter).Hours() / 24)

		if daysUntil < 0 {
			summary.Status = "expired"
		} else if daysUntil < 30 {
			summary.Status = "expiring soon"
		} else {
			summary.Status = "valid"
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func SummarizeDirectoryRecursive(dirPath string) ([]CertificateSummary, error) {
	var summaries []CertificateSummary

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(dirPath, path)

		cert, err := ParseCertificate(path)
		if err != nil {
			return nil
		}

		summary := CertificateSummary{
			Filename:   relPath,
			Encoding:   cert.Encoding,
			CommonName: cert.CommonName,
			Issuer:     cert.Issuer,
		}

		notAfter, _ := time.Parse("2006-01-02 15:04:05", cert.NotAfter)
		daysUntil := int(time.Until(notAfter).Hours() / 24)

		if daysUntil < 0 {
			summary.Status = "expired"
		} else if daysUntil < 30 {
			summary.Status = "expiring soon"
		} else {
			summary.Status = "valid"
		}

		summaries = append(summaries, summary)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summaries, nil
}
