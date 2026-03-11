# Certinfo

A CLI tool to analyze X.509 certificates and private keys (RSA, ECDSA, Ed25519, PQC) written in Go.

## Features

- Analyze single X.509 certificate files with detailed information
- Scan directories for certificates with summary output
- Parse private keys (RSA, ECDSA, Ed25519, ML-KEM, ML-DSA, SLH-DSA, FN-DSA) with key characteristics
- Parse PKCS#12 (.p12/.pfx) files containing certificates and private keys
- Support for password-protected/encrypted private keys (interactive or via flag)
- Support for password-protected PKCS#12 files (via `-p` flag)
- Output in table or JSON format
- Recursive directory scanning support
- Supports both PEM and DER encoding formats
- Post-Quantum Cryptography (PQC) support
- Extended Key Usage (EKU) display for detailed certificate analysis
- Test suite with 100+ tests covering all functionality

## Supported Formats

### Certificate Types

| Type        | Description               | Key Sizes/Curves        |
| ----------- | ------------------------- | ----------------------- |
| RSA         | RSA certificates          | 2048, 3072, 4096 bits   |
| ECDSA       | Elliptic Curve DSA        | P-256, P-384, P-521     |
| Ed25519     | EdDSA certificates        | 256 bits (fixed)        |
| Ed448       | EdDSA certificates        | 448 bits (fixed)        |
| PQC         | Post-Quantum Cryptography | ML-DSA, SLH-DSA, FN-DSA |
| Self-signed | Certificates without CA   | All above types         |

Note: Ed25519 and Ed448 certificates are supported for parsing. Key type is detected based on the public key algorithm.

### Certificate Extensions

- Subject Alternative Names (SAN)
- Extended Key Usage (EKU) - Server Authentication, Client Authentication, Code Signing, Email Protection, etc.
- Wildcard certificates (`*.example.com`)
- Client certificates (mTLS with `clientAuth` EKU)
- CA certificates

### Certificate Status

- **valid** - Certificate is currently valid
- **expired** - Certificate has expired
- **expiring soon** - Certificate expires within 30 days

### Private Key Formats

| Format    | Type                  | Notes                                               |
| --------- | --------------------- | --------------------------------------------------- |
| PKCS#1    | RSA, EC               | Traditional format (`BEGIN RSA PRIVATE KEY`)        |
| PKCS#8    | RSA, EC, Ed25519, PQC | Encapsulated format (`BEGIN PRIVATE KEY`)           |
| DER       | All                   | Binary format without PEM headers                   |
| Encrypted | RSA, EC               | Password-protected keys (prompted or via `-p` flag) |

### PKCS#12 Files

| Type       | Description                                    | Notes                          |
| ---------- | -----------------------------------------------| ------------------------------ |
| PKCS#12    | Combined certificate and private key bundle   | Password required via `-p` flag |

**Supported:**
- RSA certificates with private keys
- ECDSA (P-256, P-384, P-521) certificates with private keys
- Hybrid certificates (RSA/ECDSA + PQC)

**Not supported (library limitation):**
- Pure PQC certificates (ML-DSA standalone) in PKCS#12
- Ed25519/Ed448 private keys in PKCS#12

**Note:** PKCS#12 files created with OpenSSL may require the `-legacy` flag for compatibility:
```bash
openssl pkcs12 -export -legacy -out bundle.pfx -inkey key.pem -in cert.pem
```

### Post-Quantum Cryptography (PQC)

| Algorithm | Type              | Description                                   |
| --------- | ----------------- | --------------------------------------------- |
| ML-DSA    | Signature         | Dilithium signature algorithm (NIST FIPS 204) |
| SLH-DSA   | Signature         | Sphincs+ signature algorithm (NIST FIPS 205)  |
| FN-DSA    | Signature         | Falcon signature algorithm (NIST FIPS 206)    |
| ML-KEM    | Key Encapsulation | Kyber KEM algorithm (NIST FIPS 203)           |

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
- `-p, --password string` - Password for encrypted private keys

**Example Output:**

```
Filename:       privatekey.pem
Encoding:       PEM
Key Type:       RSA
Algorithm:      PKCS#1 v1.5
Bits:           2048
Quantum Safe:   false
```

**Encrypted Keys:**

For password-protected private keys, use the `-p` flag or omit the password to be prompted interactively:

```bash
certinfo key encrypted-key.pem -p mypassword
certinfo key encrypted-key.pem  # Will prompt for password
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

#### `p12` - Analyze a PKCS#12 File

Show detailed information about a PKCS#12 (.p12/.pfx) file containing certificates and private keys.

```bash
certinfo p12 <file.p12>
```

**Flags:**

- `-f, --format string` - Output format (table, json) (default: table)
- `-p, --password string` - Password for PKCS#12 file (required)

**Example:**

```bash
certinfo p12 bundle.p12 -p mypassword
```

**Example Output:**

```
Filename:           bundle.p12
Encoding:           PKCS#12
Certificate Count:  1
Private Key Count:  1

--- Certificate 1 ---
Filename:       bundle.p12
Encoding:       DER
Common Name:    localhost
Issuer:         My CA
Not Before:     2026-01-01 00:00:00
Not After:      2027-01-01 00:00:00
Algorithm:      SHA256-RSA
Bits:           2048
Serial Number:  1234567890
Is CA:          false
Quantum Safe:   false
Has Private Key:  Yes

--- Private Key 1 ---
Filename:      bundle.p12
Encoding:      PKCS#12
Key Type:      RSA
Algorithm:     PKCS#1 v1.5
Bits:          2048
Quantum Safe:  false
```

**Note:** PKCS#12 files created with OpenSSL may require the `-legacy` flag:
```bash
openssl pkcs12 -export -legacy -out bundle.p12 -inkey key.pem -in cert.pem
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

### Check an Encrypted/Protected Private Key

```bash
certinfo key /path/to/encrypted-key.pem -p mypassword
certinfo key /path/to/encrypted-key.pem  # Interactive password prompt
```

### Check Private Keys in a Directory (with encrypted keys)

```bash
certinfo keydir /path/to/keys/ -p mypassword
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

### Check a PKCS#12 File

```bash
certinfo p12 /path/to/bundle.p12 -p mypassword
certinfo p12 /path/to/bundle.pfx -p mypassword --format json
```

### Generate Compatible PKCS#12 with OpenSSL

```bash
openssl pkcs12 -export -legacy -out bundle.p12 -inkey key.pem -in cert.pem
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
│   ├── rsa-encrypted/ # Encrypted RSA keys (password: testpass)
│   └── ecdsa/         # P-256, P-384, P-521, Ed25519, Ed448
├── chain/             # Root → Intermediate → Server
├── selfsigned/        # Self-signed RSA + ECDSA
├── expired/           # Expired certificates
├── san-types/         # Certificates with SAN extensions
├── client/            # Client certificates (mTLS)
├── wildcard/          # Wildcard certificates (*.test.local)
├── p12-format/        # PKCS#12 bundles (password: testpass)
│   ├── server-rsa2048.pfx
│   ├── server-rsa4096.pfx
│   ├── server-ecdsa-p256.pfx
│   ├── server-ecdsa-p384.pfx
│   ├── server-ecdsa-p521.pfx
│   └── server-ed25519.pfx
└── postquantum/       # PQC certificates and keys
    └── p12/           # PKCS#12 with hybrid certificates
        ├── server-hybrid-rsa.pfx
        └── server-hybrid-ecdsa.pfx
```

**PKCS#12 test files** are generated with OpenSSL using `-legacy` flag for compatibility.

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
- PKCS#12 parsing (RSA, ECDSA certificates with private keys)
- Encrypted key parsing (password-protected keys)
- PKCS#12 password handling (correct, wrong, missing)
- Directory scanning (recursive and non-recursive)
- SAN and wildcard handling
- Extended Key Usage (EKU) parsing and display
- Status detection (valid, expired, expiring soon)
- PQC algorithm detection

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
