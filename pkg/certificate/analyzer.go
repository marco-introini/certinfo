package certificate

import (
	"os"
	"path/filepath"
	"time"
)

const daysUntilExpiring = 30

func getCertStatus(notAfter time.Time) string {
	daysUntil := int(time.Until(notAfter).Hours() / 24)

	if daysUntil < 0 {
		return "expired"
	} else if daysUntil < daysUntilExpiring {
		return "expiring soon"
	}
	return "valid"
}

type CertificateSummary struct {
	Filename      string
	Encoding      string
	CommonName    string
	Issuer        string
	Status        string
	IsQuantumSafe bool
	PQCTypes      []string
}

func SummarizeDirectory(dirPath string) ([]CertificateSummary, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	summaries := make([]CertificateSummary, 0, len(entries))

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
			Filename:      entry.Name(),
			Encoding:      cert.Encoding,
			CommonName:    cert.CommonName,
			Issuer:        cert.Issuer,
			Status:        getCertStatus(cert.NotAfter),
			IsQuantumSafe: cert.IsQuantumSafe,
			PQCTypes:      cert.PQCTypes,
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func SummarizeDirectoryRecursive(dirPath string) ([]CertificateSummary, error) {
	summaries := make([]CertificateSummary, 0, 32)

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
			Filename:      relPath,
			Encoding:      cert.Encoding,
			CommonName:    cert.CommonName,
			Issuer:        cert.Issuer,
			Status:        getCertStatus(cert.NotAfter),
			IsQuantumSafe: cert.IsQuantumSafe,
			PQCTypes:      cert.PQCTypes,
		}

		summaries = append(summaries, summary)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return summaries, nil
}
