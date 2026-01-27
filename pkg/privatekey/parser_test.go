package privatekey

import (
	"path/filepath"
	"testing"
)

func getTestKeyPath(relPath string) string {
	return filepath.Join("..", "..", "test_certs", relPath)
}

func TestParseRSAPrivateKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/rsa/server-rsa2048.key"))
	if err != nil {
		t.Fatalf("failed to parse RSA private key: %v", err)
	}
	if key.Encoding != "PEM" {
		t.Errorf("expected PEM encoding, got %s", key.Encoding)
	}
	if key.KeyType != "RSA" {
		t.Errorf("expected RSA key type, got %s", key.KeyType)
	}
	if key.Bits != 2048 {
		t.Errorf("expected 2048 bits, got %d", key.Bits)
	}
}

func TestParseRSAPrivateKey3072(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/rsa/server-rsa3072.key"))
	if err != nil {
		t.Fatalf("failed to parse RSA 3072 key: %v", err)
	}
	if key.Bits != 3072 {
		t.Errorf("expected 3072 bits, got %d", key.Bits)
	}
}

func TestParseRSAPrivateKey4096(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/rsa/server-rsa4096.key"))
	if err != nil {
		t.Fatalf("failed to parse RSA 4096 key: %v", err)
	}
	if key.Bits != 4096 {
		t.Errorf("expected 4096 bits, got %d", key.Bits)
	}
}

func TestParseECDSAPrivateKeyP256(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ecdsa-p256.key"))
	if err != nil {
		t.Fatalf("failed to parse ECDSA P-256 key: %v", err)
	}
	if key.KeyType != "EC" {
		t.Errorf("expected EC key type, got %s", key.KeyType)
	}
	if key.Curve != "P-256" {
		t.Errorf("expected P-256 curve, got %s", key.Curve)
	}
}

func TestParseECDSAPrivateKeyP384(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ecdsa-p384.key"))
	if err != nil {
		t.Fatalf("failed to parse ECDSA P-384 key: %v", err)
	}
	if key.Curve != "P-384" {
		t.Errorf("expected P-384 curve, got %s", key.Curve)
	}
}

func TestParseECDSAPrivateKeyP521(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ecdsa-p521.key"))
	if err != nil {
		t.Fatalf("failed to parse ECDSA P-521 key: %v", err)
	}
	if key.Curve != "P-521" {
		t.Errorf("expected P-521 curve, got %s", key.Curve)
	}
}

func TestParseEd25519PrivateKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ed25519.key"))
	if err != nil {
		t.Fatalf("failed to parse Ed25519 key: %v", err)
	}
	if key.KeyType != "Ed25519" {
		t.Errorf("expected Ed25519 key type, got %s", key.KeyType)
	}
	if key.Bits != 256 {
		t.Errorf("expected 256 bits, got %d", key.Bits)
	}
}

func TestParseEd448PrivateKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/ecdsa/server-ed448.key"))
	if err != nil {
		t.Skipf("Ed448 PKCS#8 parsing error: %v", err)
		return
	}
	if key.KeyType == "" || key.KeyType == "<nil>" {
		t.Skip("Ed448 PKCS#8 not supported in Go x509")
		return
	}
	if key.KeyType != "Ed448" {
		t.Errorf("expected Ed448 key type, got %s", key.KeyType)
	}
}

func TestParsePrivateKeyNotFound(t *testing.T) {
	_, err := ParsePrivateKey(getTestKeyPath("nonexistent.key"))
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestSummarizePrivateKeyDirectory(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs", "traditional", "rsa")
	summaries, err := SummarizeDirectory(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize key directory: %v", err)
	}
	if len(summaries) == 0 {
		t.Error("expected at least one key summary")
	}
}

func TestSummarizePrivateKeyDirectoryRecursive(t *testing.T) {
	dirPath := filepath.Join("..", "..", "test_certs")
	summaries, err := SummarizeDirectoryRecursive(dirPath)
	if err != nil {
		t.Fatalf("failed to summarize keys recursively: %v", err)
	}
	if len(summaries) < 10 {
		t.Errorf("expected many keys, got %d", len(summaries))
	}
}

func TestParseCAKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("traditional/rsa/ca-rsa2048.key"))
	if err != nil {
		t.Fatalf("failed to parse CA key: %v", err)
	}
	if key.KeyType != "RSA" {
		t.Errorf("expected RSA key type for CA, got %s", key.KeyType)
	}
}

func TestParseWildcardKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("wildcard/wildcard.key"))
	if err != nil {
		t.Fatalf("failed to parse wildcard key: %v", err)
	}
	if key.KeyType != "RSA" {
		t.Errorf("expected RSA key type, got %s", key.KeyType)
	}
}

func TestParseClientKey(t *testing.T) {
	key, err := ParsePrivateKey(getTestKeyPath("client/client.key"))
	if err != nil {
		t.Fatalf("failed to parse client key: %v", err)
	}
	if key.KeyType != "RSA" {
		t.Errorf("expected RSA key type, got %s", key.KeyType)
	}
}

func TestParseChainKeys(t *testing.T) {
	rootKey, err := ParsePrivateKey(getTestKeyPath("chain/root-ca.key"))
	if err != nil {
		t.Fatalf("failed to parse root CA key: %v", err)
	}
	if rootKey.Bits != 4096 {
		t.Errorf("expected 4096 bits for root CA, got %d", rootKey.Bits)
	}

	intermediateKey, err := ParsePrivateKey(getTestKeyPath("chain/intermediate-ca.key"))
	if err != nil {
		t.Fatalf("failed to parse intermediate CA key: %v", err)
	}
	if intermediateKey.Bits != 4096 {
		t.Errorf("expected 4096 bits for intermediate CA, got %d", intermediateKey.Bits)
	}
}
