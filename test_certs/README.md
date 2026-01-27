# Test Certificates Directory

This directory contains various test certificates for testing certinfo-go.

## Structure

### traditional/
Traditional certificates using RSA and ECDSA algorithms.

- **rsa/**: RSA certificates
  - `ca-rsa2048.crt/key` - CA with RSA 2048-bit
  - `ca-rsa3072.crt/key` - CA with RSA 3072-bit
  - `ca-rsa4096.crt/key` - CA with RSA 4096-bit
  - `server-*.crt/key` - Server certificates signed by respective CAs

- **ecdsa/**: ECDSA certificates
  - `ca-ecdsa-p256.crt/key` - CA with ECDSA P-256
  - `ca-ecdsa-p384.crt/key` - CA with ECDSA P-384
  - `ca-ecdsa-p521.crt/key` - CA with ECDSA P-521
  - `ca-ed25519.crt/key` - CA with Ed25519
  - `ca-ed448.crt/key` - CA with Ed448
  - `server-*.crt/key` - Server certificates signed by respective CAs

### chain/
Certificate chain (root -> intermediate -> server)
- `root-ca.crt/key` - Root CA
- `intermediate-ca.crt/key` - Intermediate CA
- `server.crt/key` - Server certificate signed by intermediate CA

### selfsigned/
Self-signed certificates (no CA)
- `rsa-selfsigned.crt/key` - Self-signed RSA
- `ecdsa-selfsigned.crt/key` - Self-signed ECDSA

### expired/
Expired certificates for testing validation
- `expired.crt/key` - Certificate that expired today

### san-types/
Certificates with Subject Alternative Names (SAN)
- `san-rsa.crt/key` - RSA certificate with SAN (localhost, test.local, IPs)
- `san-ecdsa.crt/key` - ECDSA certificate with SAN

### client/
Client certificates for mTLS testing
- `client.crt/key` - Certificate with clientAuth extended key usage

### wildcard/
Wildcard certificates
- `wildcard.crt/key` - *.test.local wildcard certificate

### p12-format/
PKCS#12 format certificates
- `server-rsa2048.pfx` - RSA server certificate in PFX format
- `server-ecdsa-p256.pfx` - ECDSA server certificate in PFX format

Password for PFX files: `testpass`

### postquantum/
Post-quantum / quantum-safe certificates.
Note: Currently contains configuration templates for PQC algorithms.
ML-DSA and ML-KEM require OpenSSL 3.x with PQC provider enabled.

## Usage

All keys without password protection can be read directly.
Keys with `-passout pass:test` or `-passout pass:testpass` require:
- OpenSSL: `-passin pass:test`
- Go: Use `x509.DecodePKCS1PrivateKey` or `x509.ParsePKCS8PrivateKey` with decrypted key
