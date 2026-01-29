# Certinfo

A CLI tool to analyze X.509 certificates and private keys (RSA, EC, Ed25519) written in Go.

## Features

- Analyze single X.509 certificate files with detailed information
- Scan directories for certificates with summary output
- Parse private keys (RSA, EC, Ed25519) with key characteristics
- Output in table or JSON format
- Recursive directory scanning support
- Supports both PEM and DER encoding formats
- Test suite with 42+ tests covering all functionality

## Supported Formats

### Certificate Types

| Type | Description | Key Sizes/Curves |
|------|-------------|------------------|
| RSA | RSA certificates | 2048, 3072, 4096 bits |
| ECDSA | Elliptic Curve DSA | P-256, P-384, P-521 |
| Ed25519 | Edwards Curve DSA | 256 bits (fixed) |
| Ed448 | Edwards Curve DSA | 456 bits (fixed) |
| Self-signed | Certificates without CA | All above types |

### Certificate Extensions

- Subject Alternative Names (SAN)
- Wildcard certificates (`*.example.com`)
- Certificate chains (Root → Intermediate → Leaf)
- Client certificates (mTLS with `clientAuth` EKU)
- CA certificates

### Private Key Formats

| Format | Type | Notes |
|--------|------|-------|
| PKCS#1 | RSA, EC | Traditional format (`BEGIN RSA PRIVATE KEY`) |
| PKCS#8 | RSA, EC, Ed25519 | Encapsulated format (`BEGIN PRIVATE KEY`) |
| EC PARAMETERS | EC | Separate curve parameters supported |
| DER | All | Binary format without PEM headers |

### Encodings

- **PEM** (base64 with `-----BEGIN ...-----` headers)
- **DER** (binary ASN.1 format)

## Installation

### Homebrew (macOS/Linux)

```bash
brew install marco-introini/tap/certinfo
```

### Direct Download

Download the latest binary from the [GitHub Releases](https://github.com/marco-introini/certinfo/releases) page:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_darwin_arm64.tar.gz | tar xz
chmod +x certinfo
mv certinfo /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_darwin_x86_64.tar.gz | tar xz
chmod +x certinfo
mv certinfo /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_linux_x86_64.tar.gz | tar xz
chmod +x certinfo
sudo mv certinfo /usr/local/bin/

# Linux (ARM64)
curl -L https://github.com/marco-introini/certinfo/releases/latest/download/certinfo_linux_arm64.tar.gz | tar xz
chmod +x certinfo
sudo mv certinfo /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/marcobagio/certinfo-go.git
cd certinfo-go
go build -o certinfo ./main.go
```

### Install Globally

```bash
go install ./main.go
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
Common Name:    example.com
Issuer:         Let's Encrypt
Subject:        CN=example.com
Not Before:     2024-01-01 00:00:00
Not After:      2025-01-01 00:00:00
Algorithm:      SHA256-RSA
Bits:           2048
Serial Number:  1234567890abcdef
Is CA:          false
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
FILENAME          ENCODING  CN          ISSUER        STATUS
cert.pem          PEM       example.com  Let's Encrypt  valid
expired.pem       PEM       old.example  DigiCert       expired
```

#### `key` - Analyze a Private Key

Show information about a private key file. Supports both PEM and DER formats.

```bash
certinfo key <key.pem>
certinfo key <key.der>
```

**Supports:**
- RSA keys (PKCS#1, PKCS#8)
- EC keys
- Ed25519 keys

**Flags:**
- `-f, --format string` - Output format (table, json) (default: table)

**Example Output:**
```
Filename:   privatekey.pem
Key Type:   RSA
Algorithm:  PKCS#1 v1.5
Bits:       2048
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
FILENAME              TYPE       BITS    CURVE
rsa2048.key           RSA        2048    -
ec256.key             EC         256     P-256
ed25519.key           Ed25519    256     -
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

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

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
└── p12-format/        # PKCS#12 bundles (password: testpass)
```

### Regenerating Test Certificates

```bash
# Traditional certificates
./generate_certs.sh

# Post-quantum certificates (requires OpenSSL with PQC provider)
./generate_pqc_certs.sh
```

### Test Coverage

- Certificate parsing (all types and formats)
- Key parsing (RSA, ECDSA, Ed25519, Ed448)
- Directory scanning (recursive and non-recursive)
- Certificate chain verification
- SAN and wildcard handling
- Status detection (valid, expired, expiring soon)
