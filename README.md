# Certinfo

A CLI tool to analyze X.509 certificates and private keys (RSA, EC, DSA) written in Go.

## Features

- Analyze single X.509 certificate files with detailed information
- Scan directories for certificates with summary output
- Parse private keys (RSA, EC, Ed25519) with key characteristics
- Output in table or JSON format
- Recursive directory scanning support
- Supports both PEM and DER encoding formats

## Installation

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
FILENAME                  CN                    ISSUER         EXPIRES              STATUS
cert.pem                  example.com           Let's Encrypt  2025-01-01 00:00:00  valid
expired.pem               old.example.com       DigiCert       2023-06-15 12:00:00  expired
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

## Output Formats

### Table Format (Default)

Human-readable tab-separated output with alignment.

### JSON Format

Machine-readable JSON output suitable for scripting.

```bash
certinfo cert certificate.pem --format json
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

## Build

```bash
go build -o certinfo ./main.go
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
