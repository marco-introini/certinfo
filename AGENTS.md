# AGENTS.md

This document provides guidelines for AI agents working on the certinfo-go codebase.

## Build Commands

### Build Binary
```bash
go build -o certinfo .
```

### Install Globally
```bash
go install .
```

### Run Locally
```bash
go run . <command> <args>
```

## Test Commands

### Run All Tests
```bash
go test ./... -v
```

### Run Tests in Specific Package
```bash
go test ./pkg/certificate -v
go test ./pkg/privatekey -v
```

### Run Single Test
```bash
go test ./pkg/certificate -run TestParseRSACertificate -v
go test -run TestParseECDSACertificate ./...
```

### Run Tests with Coverage
```bash
go test ./... -cover
```

### Test Specific File
```bash
go test -v ./pkg/certificate/parser_test.go ./pkg/certificate/parser.go
```

## Code Style Guidelines

### Imports
- Group imports: standard library first, then third-party packages
- Use blank line between import groups
- Example:
  ```go
  import (
      "bytes"
      "crypto/ecdsa"
      "crypto/elliptic"
      "crypto/rsa"
      "crypto/x509"
      "encoding/pem"
      "fmt"
      "os"
      "path/filepath"

      "github.com/spf13/cobra"
  )
  ```

### Naming Conventions
- **Packages**: lowercase, single word or short phrase (e.g., `certificate`, `privatekey`, `utils`, `cmd`)
- **Types**: PascalCase, descriptive (e.g., `CertificateInfo`, `KeySummary`, `OutputFormat`)
- **Functions**: PascalCase, verb-first for operations (e.g., `ParseCertificate`, `SummarizeDirectory`)
- **Variables**: camelCase, clear and concise (e.g., `filePath`, `parseErr`, `keyBytes`)
- **Constants**: PascalCase for exported, camelCase for unexported (e.g., `FormatTable`, `FormatJSON`)
- **Interfaces**: Single-method interfaces named after the action (e.g., `Reader`, `Writer`) or with -er suffix (e.g., `Parser`)

### Error Handling
- Return errors to callers; don't log and continue
- Use `fmt.Errorf` for formatted error messages: `fmt.Errorf("no PEM data found in %s", filePath)`
- Check errors immediately after calls
- Use `if err != nil { return nil, err }` pattern
- For test failures requiring immediate exit: `t.Fatalf("message: %v", err)`
- For test assertions: `t.Errorf("expected X, got %s", actual)`

### Type Definitions
- Use structs for data containers (e.g., `CertificateInfo`, `KeySummary`)
- Use type aliases for constants (e.g., `type OutputFormat string`)
- Export only types and functions that need to be accessed from other packages
- Keep fields flat in structs; avoid nested structures for simple data

### Function Design
- Keep functions focused on single responsibility
- Prefer returning `(*Type, error)` for parsing/creation functions
- Helper functions should be unexported (lowercase) unless needed externally
- Use named return values sparingly (only when improves clarity)

### File Organization
- One main type per file when possible
- Related functionality in same package
- Tests in `<file>_test.go` alongside implementation
- Package structure:
  - `cmd/` - CLI command handlers (Cobra): root, cert, dir, key, keydir, p12, match, pubkey, verify, version, jks
  - `pkg/certificate/` - Certificate parsing (parser.go), analysis (analyzer.go) and chain verification (verify.go)
  - `pkg/privatekey/` - Private key parsing (parser.go) and certificate matching (match.go)
  - `pkg/pkcs12/` - PKCS#12 file parsing (parser.go)
  - `pkg/publickey/` - Public key parsing (parser.go)
  - `pkg/jks/` - Java KeyStore parsing (parser.go)
  - `pkg/pem/` - PEM format handling (pem.go)
  - `pkg/utils/` - Shared output formatting utilities (output.go)

### Formatting
- Use `gofmt` (default Go formatter)
- No comments on exported functions unless documenting behavior
- Avoid commented-out code
- Use tabs for indentation (gofmt default)

### Testing Patterns
See guidelines in @.ai/testing_guidelines.md

### CLI Commands (Cobra)
- Root command in `cmd/root.go`
- Subcommands: `cert`, `dir`, `key`, `keydir`, `p12`, `match`, `pubkey`, `verify`, `version`, `jks` in separate files
- Shared helpers in `cmd/password.go` (password resolution from flag, file or environment)
- Global flags defined in `cmd/root.go` (`format`, `recursive`, `no-color`)
- Use `cobra.Command.Execute()` pattern with error handling and `os.Exit(1)`

### Output Formatting
- Use `text/tabwriter` for table output
- JSON output via `encoding/json.MarshalIndent`
- CSV output via `encoding/csv` for summary commands
- Format selection via `OutputFormat` type (`FormatTable`, `FormatJSON`, `FormatCSV`)
- Consistent field ordering in struct definitions and output
- EKU (Extended Key Usage) displayed only in detailed certificate output (`cert` command), not in summary tables

### External Dependencies

Prioritize standard library and golang.org/x/ packages for system and terminal handling to minimize supply-chain risks.

## Project Overview

- **Language**: Go 1.26
- **Module**: `github.com/marco-introini/certinfo`
- **Dependencies**: `github.com/spf13/cobra` for CLI, `software.sslmate.com/src/go-pkcs12` for PKCS#12, `github.com/pavlo-v-chernykh/keystore-go/v4` for JKS
- **Purpose**: CLI tool to analyze X.509 certificates, private keys, PKCS#12 and JKS keystores
- **Features**: Parse RSA, ECDSA, Ed25519, Ed448, PQC keys; support PEM/DER formats; directory scanning; certificate/key matching; chain verification with CRL/OCSP; table, JSON and CSV output

## Package Structure

- `main.go` - Entry point that calls `cmd.Execute()`
- `cmd/` - CLI command handlers (Cobra)
  - `root.go` - Root command with global flags (`format`, `recursive`)
  - `cert.go` - Single certificate analysis
  - `dir.go` - Directory certificate scanning
  - `key.go` - Private key analysis
  - `keydir.go` - Directory private key scanning
- `pkg/certificate/` - Certificate parsing and analysis
  - `parser.go` - X.509 certificate parsing
  - `analyzer.go` - Certificate analysis (expiration, status)
- `pkg/privatekey/` - Private key parsing
  - `parser.go` - RSA, EC, Ed25519, Ed448 key parsing
- `pkg/pem/` - PEM format handling
  - `pem.go` - PEM block detection and decoding
- `pkg/utils/` - Shared utilities
  - `output.go` - Table and JSON output formatting

## Test Certificates

Located in `test_certs/` with organized subdirectories:
- `traditional/rsa/` - RSA 2048, 3072, 4096
- `traditional/ecdsa/` - P-256, P-384, P-521, Ed25519, Ed448
- `selfsigned/` - Self-signed certificates
- `expired/` - Expired certificates
- `san-types/` - SAN extensions
- `client/` - Client certificates (mTLS)
- `wildcard/` - Wildcard certificates
