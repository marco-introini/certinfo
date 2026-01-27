# Plan: CLI per Analisi Certificati e Chiavi Private

## Obiettivo
Creare un'applicazione CLI in Go con Cobra per analizzare:
- Certificati X.509 (file singoli o directory)
- Chiavi private (RSA, EC, ecc.)

## Comandi

### Certificato Singolo
```bash
certinfo cert.pem
```
Output dettagliato:
- Common Name (CN)
- Issuer
- Subject
- Data scadenza
- Algoritmo firma
- Bit strength
- Serial number
-SAN extensions

### Directory Certificati
```bash
certinfo ./certs/
```
Output sintetico:
- Filename
- CN
- Data scadenza
- Status (valid/expired)

### Chiave Privata
```bash
certinfo key.pem
```
Output:
- Tipo chiave (RSA/EC/DSA)
- Bit length
- Algoritmo

### Directory Chiavi
```bash
certinfo ./keys/
```
Output sintetico:
- Filename
- Tipo chiave
- Bit length

## Flag Globali
- `--format` (json/table/text)
- `--verbose` per output esteso

## Struttura Progetto
```
certinfo/
├── cmd/
│   └── root.go
├── pkg/
│   ├── certificate/
│   │   ├── parser.go
│   │   └── analyzer.go
│   ├── privatekey/
│   │   ├── parser.go
│   │   └── analyzer.go
│   └── utils/
│       └── output.go
├── main.go
└── go.mod
```

## Dipendenze
- `github.com/spf13/cobra`
- Standard library: crypto/x509, crypto, os, path/filepath, encoding/pem

## Formato Output

### Table (default)
```
FILENAME        CN                    EXPIRES             STATUS
cert.pem        example.com           2026-01-01          valid
```

### JSON
```json
{
  "filename": "cert.pem",
  "common_name": "example.com",
  "issuer": "Let's Encrypt",
  "expires": "2026-01-01T00:00:00Z",
  "algorithm": "SHA256-RSA",
  "bits": 2048
}
```

## Considerazioni
- Standard library per parsing (x509.ParseCertificate, x509.ParsePKCS1PrivateKey, x509.ParseECPrivateKey)
- Gestione errori chiara
- Supporto PEM e DER
- Ricerca ricorsiva directory con flag `--recursive`
