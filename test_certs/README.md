# Test Certificates Directory

This directory contains various test certificates for testing certinfo-go.

## Structure

### traditional/
Traditional certificates using RSA and ECDSA algorithms.

- **rsa/**: RSA certificates (2048, 3072, 4096 bit)
- **ecdsa/**: ECDSA certificates (P-256, P-384, P-521, Ed25519, Ed448)

### chain/
Certificate chain (root -> intermediate -> server)

### selfsigned/
Self-signed certificates (no CA)

### expired/
Expired certificates for testing validation

### san-types/
Certificates with Subject Alternative Names (SAN)

### client/
Client certificates for mTLS testing

### wildcard/
Wildcard certificates (*.test.local)

### p12-format/
PKCS#12 format certificates (password: testpass)

### with-text/
Certificates and keys with descriptive text prefix before PEM blocks (for testing PEM parsing)

## Usage

All keys without password protection can be read directly.
Keys with `-passout pass:test` or `-passout pass:testpass` require:
- OpenSSL: `-passin pass:test`
- Go: Use `x509.DecodePKCS1PrivateKey` or `x509.ParsePKCS8PrivateKey` with decrypted key
