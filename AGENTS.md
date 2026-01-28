# AGENTS.md

This document provides guidelines for AI agents working on the certinfo-go codebase.

## Build Commands

### Build Binary
```bash
go build -o certinfo ./main.go
```

### Install Globally
```bash
go install ./main.go
```

### Run Locally
```bash
go run ./main.go <command> <args>
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
  - `cmd/` - CLI command handlers (Cobra): root, cert, dir, key, keydir
  - `pkg/certificate/` - Certificate parsing (parser.go) and analysis (analyzer.go)
  - `pkg/privatekey/` - Private key parsing (parser.go)
  - `pkg/pem/` - PEM format handling (pem.go)
  - `pkg/utils/` - Shared output formatting utilities (output.go)

### Formatting
- Use `gofmt` (default Go formatter)
- No comments on exported functions unless documenting behavior
- Avoid commented-out code
- Use tabs for indentation (gofmt default)

### Testing Patterns
- Test file per implementation file: `parser.go` → `parser_test.go`
- Helper function for test paths: `getTestCertPath(relPath string) string`
- Test certificates in `test_certs/` directory with organized subdirectories
- Use table-driven tests for multiple similar test cases
- Test error cases (e.g., `TestParseCertificateNotFound`)

### CLI Commands (Cobra)
- Root command in `cmd/root.go`
- Subcommands: `cert`, `dir`, `key`, `keydir` in separate files
- Global flags defined in `cmd/root.go` (`format`, `recursive`)
- Use `cobra.Command.Execute()` pattern with error handling and `os.Exit(1)`

### Output Formatting
- Use `text/tabwriter` for table output
- JSON output via `encoding/json.MarshalIndent`
- Format selection via `OutputFormat` type (`FormatTable`, `FormatJSON`)
- Consistent field ordering in struct definitions and output

## Project Overview

- **Language**: Go 1.25
- **Module**: `github.com/marco-introini/certinfo`
- **Dependencies**: `github.com/spf13/cobra v1.8.0` for CLI
- **Purpose**: CLI tool to analyze X.509 certificates and private keys
- **Features**: Parse RSA, ECDSA, Ed25519, Ed448 keys; support PEM/DER formats; directory scanning; table and JSON output; 42+ tests

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
