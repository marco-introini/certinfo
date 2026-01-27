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
- `root-ca.crt/key` - Root CA (4096-bit RSA)
- `intermediate-ca.crt/key` - Intermediate CA (4096-bit RSA)
- `server.crt/key` - Server certificate (2048-bit RSA) signed by intermediate CA

### selfsigned/
Self-signed certificates (no CA)
- `rsa-selfsigned.crt/key` - Self-signed RSA (2048-bit)
- `ecdsa-selfsigned.crt/key` - Self-signed ECDSA (P-256)

### expired/
Expired certificates for testing validation
- `expired.crt/key` - Certificate with 0 days validity (already expired)

### san-types/
Certificates with Subject Alternative Names (SAN)
- `san-rsa.crt/key` - RSA certificate with SAN (localhost, test.local, 127.0.0.1, ::1)
- `san-ecdsa.crt/key` - ECDSA certificate with same SANs

### client/
Client certificates for mTLS testing
- `client.crt/key` - Certificate with `clientAuth` extended key usage

### wildcard/
Wildcard certificates
- `wildcard.crt/key` - `*.test.local` wildcard certificate

### p12-format/
PKCS#12 format certificates (password: `testpass`)
- `server-rsa2048.pfx` - RSA server certificate in PFX format
- `server-ecdsa-p256.pfx` - ECDSA server certificate in PFX format

## Generation

Use the scripts in the project root to regenerate all certificates:

```bash
# Generate all traditional certificates
./generate_certs.sh

# Generate post-quantum certificates (requires OpenSSL with PQC provider)
./generate_pqc_certs.sh
```

## Notes

- All keys are decrypted (no password) for testing purposes
- Ed448 keys in PKCS#8 format may not parse on some Go versions
- ML-DSA/ML-KEM certificates require OpenSSL with PQC provider
