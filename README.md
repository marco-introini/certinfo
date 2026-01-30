# Certinfo

A CLI tool to analyze X.509 certificates and private keys (RSA, ECDSA, Ed25519, PQC) written in Go.

## Features

- Analyze single X.509 certificate files with detailed information
- Scan directories for certificates with summary output
- Parse private keys (RSA, ECDSA, Ed25519, ML-KEM, ML-DSA, SLH-DSA, FN-DSA) with key characteristics
- Output in table or JSON format
- Recursive directory scanning support
- Supports both PEM and DER encoding formats
- Post-Quantum Cryptography (PQC) support
- Test suite with 42+ tests covering all functionality

## Supported Formats

### Certificate Types

| Type | Description | Key Sizes/Curves |
|------|-------------|------------------|
| RSA | RSA certificates | 2048, 3072, 4096 bits |
| ECDSA | Elliptic Curve DSA | P-256, P-384, P-521 |
| Ed25519 | EdDSA certificates | 256 bits (fixed) |
| Ed448 | EdDSA certificates | 448 bits (fixed) |
| PQC | Post-Quantum Cryptography | ML-DSA, SLH-DSA, FN-DSA |
| Self-signed | Certificates without CA | All above types |

Note: Ed25519 and Ed448 certificates are supported for parsing. Key type is detected based on the public key algorithm.

### Certificate Extensions

- Subject Alternative Names (SAN)
- Wildcard certificates (`*.example.com`)
- Client certificates (mTLS with `clientAuth` EKU)
- CA certificates

### Certificate Status

- **valid** - Certificate is currently valid
- **expired** - Certificate has expired
- **expiring soon** - Certificate expires within 30 days

### Private Key Formats

| Format | Type | Notes |
|--------|------|-------|
| PKCS#1 | RSA, EC | Traditional format (`BEGIN RSA PRIVATE KEY`) |
| PKCS#8 | RSA, EC, Ed25519, PQC | Encapsulated format (`BEGIN PRIVATE KEY`) |
| DER | All | Binary format without PEM headers |

### Post-Quantum Cryptography (PQC)

| Algorithm | Type | Description |
|-----------|------|-------------|
| ML-DSA | Signature | Dilithium signature algorithm (NIST FIPS 204) |
| SLH-DSA | Signature | Sphincs+ signature algorithm (NIST FIPS 205) |
| FN-DSA | Signature | Falcon signature algorithm (NIST FIPS 206) |
| ML-KEM | Key Encapsulation | Kyber KEM algorithm (NIST FIPS 203) |

### Encodings

- **PEM** (base64 with `-----BEGIN ...-----` headers)
- **DER** (binary ASN.1 format)

## Installation

### Homebrew (macOS/Linux)

```bash
brew install marco-introini/tap/certinfo
```

### GitHub Releases

Download the latest binary from the [GitHub Releases](https://github.com/marco-introini/certinfo/releases) page:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_darwin_arm64.tar.gz | tar xz
chmod +x certinfo
sudo mv certinfo /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_darwin_x86_64.tar.gz | tar xz
chmod +x certinfo
sudo mv certinfo /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_linux_x86_64.tar.gz | tar xz
chmod +x certinfo
sudo mv certinfo /usr/local/bin/

# Linux (ARM64)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_linux_arm64.tar.gz | tar xz
chmod +x certinfo
sudo mv certinfo /usr/local/bin/

# Windows
# Download certinfo_windows_amd64.zip from releases page
Expand-Archive certinfo_windows_amd64.zip -DestinationPath certinfo
```

### Go Install

```bash
go install github.com/marco-introini/certinfo@latest
```

### From Source

```bash
git clone https://github.com/marco-introini/certinfo.git
cd certinfo
go build -o certinfo ./main.go
```

## Usage

```
certinfo [command] [flags]
```

### Available Commands

#### `cert` - Analyze a Single Certificate

Show detailed information about an X.509 certificate file. Supports both PEM and DER formats.

```bash
certinfo cert <certificate.pem>
certinfo cert <certificate.der>
```

**Flags:**
- `-f, --format string` - Output format (table, json) (default: table)

**Example Output:**
```
Filename:       certificate.pem
Encoding:       PEM
Common Name:    example.com
Issuer:         Let's Encrypt
Subject:        CN=example.com
Not Before:     2024-01-01 00:00:00
Not After:      2025-01-01 00:00:00
Algorithm:      SHA256-RSA
Key Type:       RSA
Bits:           2048
Serial Number:  1234567890abcdef
Is CA:          false
Quantum Safe:   false
SANs:           [example.com www.example.com]
```

#### `dir` - Summarize Certificates in a Directory

List all certificates in a directory with summary information (CN and expiration).

```bash
certinfo dir <directory/>
```

**Flags:**
- `-f, --format string` - Output format (table, json) (default: table)
- `-r, --recursive` - Search recursively through subdirectories

**Example Output:**
```
FILENAME          ENCODING  CN          ISSUER        STATUS    QUANTUM SAFE  PQC TYPES
cert.pem          PEM       example.com  Let's Encrypt  valid     No            -
expired.pem       PEM       old.example  DigiCert       expired   No            -
pqc.pem           PEM       pqc.test     PQC CA         valid     Yes           ML-DSA-44
```

#### `key` - Analyze a Private Key

Show information about a private key file. Supports both PEM and DER formats.

```bash
certinfo key <key.pem>
certinfo key <key.der>
```

**Supports:**
- RSA keys (PKCS#1, PKCS#8)
- EC keys (P-256, P-384, P-521)
- Ed25519 keys
- PQC keys (ML-KEM, ML-DSA, SLH-DSA, FN-DSA)

**Flags:**
- `-f, --format string` - Output format (table, json) (default: table)

**Example Output:**
```
Filename:       privatekey.pem
Encoding:       PEM
Key Type:       RSA
Algorithm:      PKCS#1 v1.5
Bits:           2048
Quantum Safe:   false
```

#### `keydir` - Summarize Private Keys in a Directory

List all private keys in a directory with summary information.

```bash
certinfo keydir <directory/>
```

**Flags:**
- `-f, --format string` - Output format (table, json) (default: table)
- `-r, --recursive` - Search recursively through subdirectories

**Example Output:**
```
FILENAME              ENCODING  TYPE       BITS    QUANTUM SAFE
rsa2048.key           PEM       RSA        2048    No
ec256.key             PEM       EC         256     No
ed25519.key           PEM       Ed25519    256     No
ml-dsa.key            PEM       ML-DSA     44      Yes
ml-kem.key            PEM       ML-KEM     768     Yes
```

### Global Flags

- `-h, --help` - Help for any command
- `-c, --no-color` - Disable color output

## Output Formats

### Table Format (Default)

Human-readable tab-separated output with alignment.

### JSON Format

Machine-readable JSON output suitable for scripting.

```bash
certinfo cert certificate.pem --format json
```

### Color Output

Color output is enabled by default for terminal output. Use `--no-color` or `-c` to disable colors.

```bash
certinfo cert certificate.pem --no-color
certinfo cert certificate.pem -c
```

## Examples

### Check a Single Certificate (PEM or DER)

```bash
certinfo cert /path/to/certificate.pem
certinfo cert /path/to/certificate.der
```

### Check All Certificates in a Directory

```bash
certinfo dir ./certs/
```

### Recursively Scan for Certificates

```bash
certinfo dir ./certs/ --recursive
```

### Check a Private Key (PEM or DER)

```bash
certinfo key /path/to/privatekey.pem
certinfo key /path/to/privatekey.der
```

### Export Certificate Summary as JSON

```bash
certinfo dir ./certs/ --format json > summary.json
```

### Disable Color Output

```bash
certinfo cert /path/to/certificate.pem --no-color
certinfo dir ./certs/ -c
```

## Build

```bash
go build -o certinfo ./main.go
```

## Testing

### Running Tests

```bash
go test ./... -v
```

### Test Certificates

The project includes a comprehensive set of test certificates in `test_certs/`:

```
test_certs/
├── traditional/
│   ├── rsa/           # RSA 2048, 3072, 4096 (CA + server)
│   └── ecdsa/         # P-256, P-384, P-521, Ed25519, Ed448
├── chain/             # Root → Intermediate → Server
├── selfsigned/        # Self-signed RSA + ECDSA
├── expired/           # Expired certificates
├── san-types/         # Certificates with SAN extensions
├── client/            # Client certificates (mTLS)
├── wildcard/          # Wildcard certificates (*.test.local)
├── p12-format/        # PKCS#12 bundles (password: testpass)
└── postquantum/       # PQC certificates and keys
```

### Regenerating Test Certificates

```bash
# Traditional certificates
./generate_certs.sh

# Post-quantum certificates (requires OpenSSL with PQC provider)
./generate_pqc_certs.sh
```

### Test Coverage

- Certificate parsing (RSA, ECDSA, Ed25519, Ed448, PQC)
- Key parsing (RSA, ECDSA, Ed25519, ML-KEM, ML-DSA, SLH-DSA, FN-DSA)
- Directory scanning (recursive and non-recursive)
- SAN and wildcard handling
- Status detection (valid, expired, expiring soon)
- PQC algorithm detection

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.