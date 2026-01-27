package certificate

import (
	"path/filepath"
	"testing"
)

func TestSummarizeDirectory(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "traditional", "rsa")
	summaries, err := SummarizeDirectory(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize directory: %v", err)
	}

	if len(summaries) == 0 {
		t.Error("expected at least one certificate summary")
	}

	var foundValid, foundExpired bool
	for _, s := range summaries {
		if s.Status == "valid" {
			foundValid = true
		}
		if s.Status == "expired" {
			foundExpired = true
		}
	}
	if !foundValid {
		t.Error("expected at least one valid certificate")
	}
	if foundExpired {
		t.Error("did not expect expired certificate in RSA directory")
	}
}

func TestSummarizeDirectoryExpired(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "expired")
	summaries, err := SummarizeDirectory(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize expired directory: %v", err)
	}

	if len(summaries) == 0 {
		t.Error("expected at least one certificate summary")
	}

	for _, s := range summaries {
		if s.Status == "valid" {
			t.Error("did not expect valid status for expired certificate")
		}
	}
}

func TestSummarizeDirectoryRecursive(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs")
	summaries, err := SummarizeDirectoryRecursive(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize directory recursively: %v", err)
	}

	if len(summaries) < 10 {
		t.Errorf("expected many certificates, got %d", len(summaries))
	}
}

func TestSummarizeDirectoryNotFound(t *testing.T) {
	_, err := SummarizeDirectory("/nonexistent/path")
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestSummarizeECDSA(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "traditional", "ecdsa")
	summaries, err := SummarizeDirectory(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize ECDSA directory: %v", err)
	}

	if len(summaries) == 0 {
		t.Error("expected at least one ECDSA certificate")
	}
}

func TestSummarizeCertificateChain(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "chain")
	summaries, err := SummarizeDirectory(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize chain directory: %v", err)
	}

	if len(summaries) < 3 {
		t.Errorf("expected at least 3 certificates in chain, got %d", len(summaries))
	}
}
