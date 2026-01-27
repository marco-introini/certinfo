# TODO - Miglioramenti al codice Go

## Problemi Critici

Questi problemi possono causare crash, panico, o comportamenti errati. Devono essere risolti con priorità massima.

### 1. Errori ignorati in `pem.Decode` - può causare panic
**File:** `pkg/certificate/parser.go:66`, `pkg/certificate/parser.go:108`, `pkg/privatekey/parser.go:48`, `pkg/privatekey/parser.go:76`

Il risultato di `pem.Decode()` ha un secondo valore di ritorno (`rest`) che viene ignorato. Se il file PEM contiene più blocchi, questi vengono persi.

```go
// Attuale
block, _ := pem.Decode(data)

// Proposto
block, rest := pem.Decode(data)
if block == nil {
    return nil, fmt.Errorf("no PEM data found")
}
// Gestire anche 'rest' se necessario
```

### 2. Parsing duplicato PKCS8 - sovrascrive errori
**File:** `pkg/privatekey/parser.go:109`, `pkg/privatekey/parser.go:128`

`ParsePKCS8PrivateKey` viene chiamato due volte con gli stessi dati. La prima chiamata sovrascrive l'errore della chiamata a `ParsePKCS1PrivateKey`, rendendo impossibile distinguere quale parser ha fallito.

```go
// Attuale (riga 109-117)
rsaKey, err := x509.ParsePKCS8PrivateKey(der)
if err == nil {
    // ...
}
// Poi di nuovo a riga 128:
pkcs8Key, err := x509.ParsePKCS8PrivateKey(der)  // err sovrascritto!
```

### 3. Tipo di chiave sconosciuta - potenziale panic
**File:** `pkg/privatekey/parser.go:162`

Quando nessun parser ha successo, `pkcs8Key` potrebbe essere `nil` se `ParsePKCS8PrivateKey` ha fallito, causando un panic con `fmt.Sprintf("%T", nil)`.

```go
// Attuale
info.KeyType = fmt.Sprintf("%T", pkcs8Key)

// Proposto
if pkcs8Key != nil {
    info.KeyType = fmt.Sprintf("%T", pkcs8Key)
} else {
    info.KeyType = "unknown"
}
```

### 4. Errori ignorati in `time.Parse` - status certificato errato
**File:** `pkg/certificate/analyzer.go:44`, `pkg/certificate/analyzer.go:87`

Il parsing della data potrebbe fallire silenziosamente. Gli errori vengono ignorati con `_`, portando a calcoli di status errati.

```go
// Attuale
notAfter, _ := time.Parse("2006-01-02 15:04:05", cert.NotAfter)
daysUntil := int(time.Until(notAfter).Hours() / 24)  // notAfter è zero time!

// Proposto
notAfter, err := time.Parse("2006-01-02 15:04:05", cert.NotAfter)
if err != nil {
    summary.Status = "unknown"
    return
}
daysUntil := int(time.Until(notAfter).Hours() / 24)
```

### 5. Errori ignorati in `json.MarshalIndent` - nessun output su errore
**File:** `pkg/utils/output.go:22`, `pkg/utils/output.go:49`, `pkg/utils/output.go:66`, `pkg/utils/output.go:86`

Gli errori di marshaling JSON vengono ignorati. Se il marshaling fallisce, non c'è output e l'errore è invisibile.

```go
// Attuale
jsonBytes, _ := json.MarshalIndent(cert, "", "  ")

// Proposto
jsonBytes, err := json.MarshalIndent(cert, "", "  ")
if err != nil {
    fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
    return
}
```

---

## Errori da Sistemare

Questi problemi non causano crash ma rappresentano bug, code smell, o mancanza di best practices. Dovrebbero essere risolti.

### 6. Magic number hardcoded per giorni di scadenza
**File:** `pkg/certificate/analyzer.go:49`, `pkg/certificate/analyzer.go:93`

Il valore 30 per i giorni di scadenza è hardcoded. Difficile da mantenere e modificare.

```go
// Proposto
const ExpiringSoonDays = 30

// Poi usare:
if daysUntil < ExpiringSoonDays {
    summary.Status = "expiring soon"
}
```

### 7. Magic string per formato data ripetuta
**File:** `pkg/certificate/parser.go:87-88`, `pkg/certificate/parser.go:128-129`, `pkg/certificate/analyzer.go:44`, `pkg/certificate/analyzer.go:87`

Il formato data è ripetuto come stringa in 4 posizioni. Una costante migliora la manutenibilità.

```go
const DateFormat = "2006-01-02 15:04:05"
```

### 8. Errori wrapping con `%w` invece di `%v`
**File:** `pkg/certificate/parser.go:68`, `pkg/certificate/parser.go:110`, `pkg/privatekey/parser.go:60`, `pkg/privatekey/parser.go:88`

Usare `%w` per wrapping degli errori mantiene lo stack trace e permette `errors.Is`/`errors.As`.

```go
// Attuale
return nil, fmt.Errorf("no PEM data found in %s", filePath)

// Proposto
return nil, fmt.Errorf("no PEM data found in %s: %w", filePath, err)
```

### 9. Pre-allocazione slice mancante
**File:** `pkg/certificate/analyzer.go:17`, `pkg/certificate/analyzer.go:61`, `pkg/privatekey/parser.go:166`, `pkg/privatekey/parser.go:200`

Le slice vengono estese dinamicamente con `append` senza pre-allocazione. Impatto sulle performance.

```go
// Proposto
entries, err := os.ReadDir(dirPath)
if err != nil {
    return nil, err
}

summaries := make([]CertificateSummary, 0, len(entries))
```

### 10. Parsing inefficiente delle date
**File:** `pkg/certificate/analyzer.go:44-45`, `pkg/certificate/analyzer.go:87-88`

Si formatta una data in stringa e poi la si re-parsa. Spreco di CPU.

```go
// Proposto: In CertificateInfo usare time.Time invece di string
type CertificateInfo struct {
    NotBefore time.Time  // invece di string
    NotAfter  time.Time
}
```

### 11. Flag `-f` duplicato in ogni comando
**File:** `cmd/root.go:16`, `cmd/cert.go:27`, `cmd/key.go:27`, `cmd/dir.go:36`, `cmd/keydir.go:36`

Ogni comando definisce il flag `-f` separatamente. Meglio definirlo in `rootCmd` e lasciare che i sottocomandi lo ereditino.

```go
// In root.go
rootCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json)")

// Rimuovere dai singoli comandi
```

### 12. Usare `any` invece di `interface{}`
**File:** `pkg/certificate/parser.go:30`

Go 1.18+ permette `any` come alias per `interface{}`. Più idiomatico.

```go
// Attuale
func getKeyBitsAndType(pub interface{}) (string, int) {

// Proposto
func getKeyBitsAndType(pub any) (string, int) {
```

### 13. Exit codes inconsistente
**File:** `cmd/cert.go:20`, `cmd/key.go:20`, `cmd/dir.go:28`, `cmd/keydir.go:28`

Tutti i comandi usano `os.Exit(1)`, ma non c'è un modo coerente di gestire codici di errore specifici.

---

## Nice to Have

Miglioramenti opzionali, refactoring, e best practices. Basso impatto sulla stabilità.

### 14. Funzione `isPEM` duplicata
**File:** `pkg/certificate/parser.go:50`, `pkg/privatekey/parser.go:33`

La funzione `isPEM` è identica in entrambi i file. Creare un package comune `pkg/pem`.

### 15. Logica di parsing PEM duplicata
**File:** `pkg/certificate/parser.go:65-75`, `pkg/certificate/parser.go:107-117`, `pkg/privatekey/parser.go:46-65`, `pkg/privatekey/parser.go:74-93`

La logica per determinare se un file è PEM e decodificarlo è ripetuta 4 volte.

### 16. Logica di calcolo status duplicata
**File:** `pkg/certificate/analyzer.go:44-53`, `pkg/certificate/analyzer.go:87-96`

Il calcolo dello stato del certificato è duplicato. Creare una funzione helper.

### 17. Magic string per header tabella
**File:** `pkg/utils/output.go:57`, `pkg/utils/output.go:94`

Le intestazioni delle tabelle sono hardcoded.

### 18. Aggiornare versione Go
**File:** `go.mod:3`

Il progetto usa Go 1.21. Considerare l'upgrade a Go 1.25.

### 19. Usare `context.Context` per cancellazione
**File:** `cmd/*.go`, `pkg/certificate/analyzer.go`, `pkg/privatekey/parser.go`

Nessun uso di `context.Context`. Per operazioni ricorsive, permettere cancellazione.

```go
func SummarizeDirectoryRecursive(ctx context.Context, dirPath string) ([]CertificateSummary, error)
```

### 20. Usare `filepath.Clean` per normalizzare percorsi
**File:** `pkg/certificate/analyzer.go:30`, `pkg/privatekey/parser.go:179`

I percorsi potrebbero beneficiare di normalizzazione.

### 21. Copertura test insufficiente
Non sono stati trovati test per `cmd/` e `pkg/utils/`.

### 22. Test per casi edge mancanti
- File vuoti
- File corrotti
- File con encoding misto
- Chiavi criptate (con password)

### 23. Commenti godoc mancanti
Aggiungere commenti godoc per le funzioni pubbliche.

### 24. Estrarre package `encoding`
Creare un package `pkg/encoding` per logica PEM/DER condivisa.

### 25. Unificare output formatting con generici
**File:** `pkg/utils/output.go`

Le funzioni `Print*` sono molto simili. Go 1.18+ permette generici.

```go
func PrintSummary[T any](summaries []T, headers []string, format OutputFormat)
```

---

## Supporto Post-Quantum (PQC)

Aggiungere supporto per certificati e chiavi post-quantum (algoritmi NIST standardizzati).

### Prerequisiti

### 26. Aggiornare versione Go
**File:** `go.mod:3`

Il supporto post-quantum in `crypto/x509` è disponibile da Go 1.23. Aggiornare a Go 1.24+.

```go
// Attuale
go 1.21

// Proposto
go 1.24
```

### Algoritmi Supportati

| Tipo | Go Type | Bits | Note |
|------|---------|------|------|
| ML-KEM-768 | `mlkem.PublicKey` | 1184 | KEM post-quantum |
| ML-KEM-1024 | `mlkem.PublicKey` | 1568 | KEM post-quantum |
| ML-DSA-44 | signature | - | Firme quanttum-safe |
| ML-DSA-65 | signature | - | Firme quanttum-safe |
| ML-DSA-87 | signature | - | Firme quanttum-safe |
| SLH-DSA-SHA2 | signature | - | Firme quanttum-safe |
| SLH-DSA-SHAKE | signature | - | Firme quanttum-safe |
| FN-DSA | signature | - | Firme quanttum-safe |

### Modifiche al Parser Certificati

### 27. Aggiornare `getKeyBitsAndType()` per PQC
**File:** `pkg/certificate/parser.go:30`

Aggiungere riconoscimento chiavi ML-KEM.

```go
import "crypto/mlkem"

// Attuale
func getKeyBitsAndType(pub any) (string, int) {
    switch key := pub.(type) {
    case *rsa.PublicKey:
        return "RSA", key.N.BitLen()
    case *ecdsa.PublicKey:
        // ...
    default:
        return fmt.Sprintf("%T", pub), 0
    }
}

// Proposto
func getKeyBitsAndType(pub any) (string, int) {
    switch key := pub.(type) {
    case *rsa.PublicKey:
        return "RSA", key.N.BitLen()
    case *ecdsa.PublicKey:
        // gestione ECDSA esistente
    case *mlkem.PublicKey:
        return "ML-KEM", key.Size() * 8  // 768=768, 1024=1024
    default:
        return fmt.Sprintf("%T", pub), 0
    }
}
```

### 28. Aggiornare `CertificateInfo` per PQC
**File:** `pkg/certificate/parser.go:14`

Aggiungere campi per indicare resistenza quantistica.

```go
type CertificateInfo struct {
    // ... campi esistenti ...
    QuantumSafe bool   // true se l'algoritmo è resistente ai量子攻击
    PQCType     string // "ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "hybrid"
}
```

### 29. Aggiornare parsing algoritmo firma PQC
**File:** `pkg/certificate/parser.go:89`

Il campo `Algorithm` deve riconoscere algoritmi PQC.

```go
// In ParseCertificate, dopo info.KeyType, info.Bits
info.QuantumSafe = IsQuantumSafeAlgorithm(cert.SignatureAlgorithm)
info.PQCType = GetPQCType(cert.SignatureAlgorithm)

// Funzioni helper da aggiungere
func IsQuantumSafeAlgorithm(algo x509.SignatureAlgorithm) bool {
    switch algo {
    case x509.MLDSASHA256, x509.MLDSASHA384, x509.MLDSASHA512,
         x509.SLHDSASHA256, x509.SLHDSASHA512,
         x509.FALCON512, x509.FALCON1024:
        return true
    default:
        return false
    }
}

func GetPQCType(algo x509.SignatureAlgorithm) string {
    switch algo {
    case x509.MLDSASHA256, x509.MLDSASHA384, x509.MLDSASHA512:
        return "ML-DSA"
    case x509.SLHDSASHA256, x509.SLHDSASHA512:
        return "SLH-DSA"
    case x509.FALCON512, x509.FALCON1024:
        return "FALCON"
    default:
        return ""
    }
}
```

### Modifiche al Parser Chiavi Private

### 30. Aggiornare `parseKey()` per chiavi PQC
**File:** `pkg/privatekey/parser.go:98`

Aggiungere parsing per `mlkem.PrivateKey`.

```go
import "crypto/mlkem"

// Attuale
func parseKey(der []byte, filename string, encoding string) (*KeyInfo, error) {
    info := &KeyInfo{Filename: filename, Encoding: encoding}

    key, err := x509.ParsePKCS1PrivateKey(der)
    if err == nil {
        // ...
    }
    // ... altri parser ...
}

// Proposto
func parseKey(der []byte, filename string, encoding string) (*KeyInfo, error) {
    info := &KeyInfo{Filename: filename, Encoding: encoding}

    // Parser tradizionali
    key, err := x509.ParsePKCS1PrivateKey(der)
    if err == nil {
        info.KeyType = "RSA"
        info.Bits = key.N.BitLen()
        info.Algorithm = "PKCS#1 v1.5"
        return info, nil
    }

    // ... altri parser tradizionali ...

    // Parser PQC (solo DER, non PEM diretto)
    mlkemKey, err := mlkem.ParsePrivateKey(der)
    if err == nil {
        info.KeyType = "ML-KEM"
        info.Bits = mlkemKey.Size() * 8
        info.Algorithm = "ML-KEM"
        info.Curve = fmt.Sprintf("ML-KEM-%d", info.Bits)
        return info, nil
    }

    // ... gestione altri casi ...
}
```

### Modifiche all'Output

### 31. Aggiornare `PrintCertificateInfo()` per PQC
**File:** `pkg/utils/output.go:20`

Aggiungere campo "Quantum Safe" nell'output.

```go
func PrintCertificateInfo(cert *certificate.CertificateInfo, format OutputFormat) {
    // ... JSON esistente ...

    w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
    defer w.Flush()

    // ... campi esistenti ...
    fmt.Fprintf(w, "Key Type:\t%s\n", cert.KeyType)
    fmt.Fprintf(w, "Bits:\t%d\n", cert.Bits)

    if cert.QuantumSafe {
        fmt.Fprintf(w, "Quantum Safe:\tYes (%s)\n", cert.PQCType)
    } else {
        fmt.Fprintf(w, "Quantum Safe:\tNo\n")
    }

    // ... SANs ...
}
```

### 32. Aggiornare `PrintCertificateSummaries()` per PQC
**File:** `pkg/utils/output.go:47`

Aggiungere colonna "Quantum Safe" nella tabella summary.

```go
fmt.Fprintf(w, "FILENAME\tENCODING\tCN\tISSUER\tSTATUS\tPQC\n")
for _, s := range summaries {
    pq := "-"
    if s.QuantumSafe {
        pq = s.PQCType
    }
    fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
        s.Filename, s.Encoding, s.CommonName, s.Issuer, s.Status, pq)
}
```

### Modifiche all'Analyzer

### 33. Aggiornare `CertificateSummary` per PQC
**File:** `pkg/certificate/analyzer.go:9`

```go
type CertificateSummary struct {
    Filename    string
    Encoding    string
    CommonName  string
    Issuer      string
    Status      string
    QuantumSafe bool
    PQCType     string
}
```

### 34. Aggiornare funzioni di summary per PQC
**File:** `pkg/certificate/analyzer.go:17-59`, `pkg/certificate/analyzer.go:61-108`

Popolare i nuovi campi PQC.

```go
summary := CertificateSummary{
    Filename:    entry.Name(),
    Encoding:    cert.Encoding,
    CommonName:  cert.CommonName,
    Issuer:      cert.Issuer,
    Status:      calculateCertStatus(cert.NotAfter),
    QuantumSafe: cert.QuantumSafe,
    PQCType:     cert.PQCType,
}
```

### Test

### 35. Generare certificati PQC per test
Creare script di test che genera certificati ibridi e PQC puri.

```go
// pkg/certificate/pqc_test.go
package certificate

import (
    "crypto/tls"
    "testing"
)

func TestParseHybridCertificate(t *testing.T) {
    // Generare certificato ibrido RSA + ML-KEM
    // Testare parsing
}

func TestParsePQCCertificate(t *testing.T) {
    // Generare certificato PQC puro (se supported da Go)
    // Testare parsing
}
```

### 36. Test per chiavi PQC
**File:** `pkg/privatekey/pqc_test.go`

```go
package privatekey

func TestParseMLKEMKey(t *testing.T) {
    // Generare chiave ML-KEM
    // Testare parsing
}
```

### Note di Implementazione

- **Certificati ibridi**: Go supporta già certificati ibridi (tradizionale + PQC). Il parsing deve riconoscere entrambi.
- **ML-KEM keys**: Le chiavi ML-KEM sono disponibili in `crypto/mlkem` da Go 1.23.
- **PEM format**: I certificati PQC usano lo stesso formato PEM/DER.
- **Fallback**: Se un algoritmo non è riconosciuto, mostrare il tipo originale (es. "ML-KEM-768").

### Riferimenti

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Go crypto/mlkem package](https://pkg.go.dev/crypto/mlkem)
- [Go x509 - PQC support](https://pkg.go.dev/crypto/x509#pkg-constants)

---

## Funzionalità Aggiuntive

Funzionalità extra richieste per migliorare l'utilità del programma.

### 37. Confronto chiave privata e certificato
**File:** Nuovo `pkg/matching/matcher.go`, nuovo comando `cmd/match.go`

Verificare se una chiave privata corrisponde a un certificato (stesso subject, stessa chiave pubblica).

```bash
# Usage
certinfo match --cert server.crt --key server.key
# Output: "Match: YES" o "Match: NO"
```

**Implementazione:**

```go
// pkg/matching/matcher.go
package matching

import (
    "crypto/x509"
    "os"
)

type MatchResult struct {
    Match       bool
    Reason      string
    CertSubject string
    KeyType     string
}

func MatchKeyToCert(certPath, keyPath string) (*MatchResult, error) {
    // 1. Parse certificato
    cert, err := os.ReadFile(certPath)
    if err != nil {
        return nil, err
    }

    // 2. Parse chiave privata
    key, err := os.ReadFile(keyPath)
    if err != nil {
        return nil, err
    }

    // 3. Estrarre public key da entrambi
    certPubKey, err := extractPublicKeyFromCert(cert)
    if err != nil {
        return nil, err
    }

    keyPubKey, err := extractPublicKeyFromKey(key)
    if err != nil {
        return nil, err
    }

    // 4. Confrontare (stesso tipo e stessa chiave)
    return comparePublicKeys(certPubKey, keyPubKey)
}

func comparePublicKeys(a, b any) (*MatchResult, error) {
    // Confrontare RSA, ECDSA, Ed25519
    // Restituire Match=true/false con motivo
}
```

**Nuovo comando CLI:**

```go
// cmd/match.go
var matchCmd = &cobra.Command{
    Use:   "match --cert <cert> --key <key>",
    Short: "Check if private key matches certificate",
    Long:  "Verify that a private key corresponds to a certificate",
    Run: func(cmd *cobra.Command, args []string) {
        result, err := matching.MatchKeyToCert(certFile, keyFile)
        // output colorato
    },
}
```

### 38. Supporto file PKCS#12 (`.pfx`, `.p12`)
**File:** Nuovo `pkg/pkcs12/parser.go`, nuovo comando `cmd/p12.go`

Leggere file PKCS#12 con password opzionale, estrarre certificato e chiave privata.

```bash
# Usage
certinfo p12 file.pfx [--password secret]
# Output: certificate + key info estratti
```

**Implementazione:**

```go
// pkg/pkcs12/parser.go
package pkcs12

import (
    "crypto/x509"
    "encoding/pem"
    "os"
)

type P12Content struct {
    Certificate *x509.Certificate
    PrivateKey  any  // *rsa.PrivateKey, *ecdsa.PrivateKey, etc.
    CAChain     []*x509.Certificate
}

func ParseP12(filePath string, password []byte) (*P12Content, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    blocks, err := pkcs12.ToPEM(data, password)
    if err != nil {
        return nil, err
    }

    var content P12Content
    for _, block := range blocks {
        switch block.Type {
        case "CERTIFICATE":
            cert, _ := x509.ParseCertificate(block.Bytes)
            content.Certificate = cert
        case "PRIVATE KEY":
            key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
            content.PrivateKey = key
        case "CERTIFICATE CHAIN":
            // gestire CA chain
        }
    }

    return &content, nil
}
```

**Dipendenza da aggiungere:**

```bash
go get github.com/youmark/pkcs8
# oppure usare golang.org/x/crypto/pkcs12
```

**Nuovo comando CLI:**

```go
// cmd/p12.go
var p12Cmd = &cobra.Command{
    Use:   "p12 [file.p12]",
    Short: "Parse PKCS#12 file",
    Long:  "Extract certificate and private key from PKCS#12 file",
    Run: func(cmd *cobra.Command, args []string) {
        content, err := pkcs12.ParseP12(args[0], []byte(password))
        // output cert + key info
    },
}

func init() {
    p12Cmd.Flags().StringVarP(&password, "password", "p", "", "PKCS#12 password")
}
```

### 39. Colorazione output nel terminale
**File:** `pkg/utils/output.go`, `pkg/utils/colors.go`

Aggiungere colori ANSI per migliorare leggibilità.

**Implementazione:**

```go
// pkg/utils/colors.go
package utils

import "os"

var (
    Reset  = "\033[0m"
    Red    = "\033[31m"
    Green  = "\033[32m"
    Yellow = "\033[33m"
    Blue   = "\033[34m"
    Bold   = "\033[1m"
)

func ShouldUseColors() bool {
    // Disabilitare colori se non è un terminale TTY
    return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

type ColorTheme struct {
    Header   string
    Valid    string
    Expired  string
    Warning  string
    PQC      string
}

var DefaultTheme = ColorTheme{
    Header:  Blue + Bold,
    Valid:   Green,
    Expired: Red,
    Warning: Yellow,
    PQC:     Green + Bold,
}

func PrintCertificateInfoColored(cert *certificate.CertificateInfo, format OutputFormat) {
    if !ShouldUseColors() || format == FormatJSON {
        PrintCertificateInfo(cert, format)
        return
    }

    theme := DefaultTheme

    w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
    defer w.Flush()

    // Header con colori
    fmt.Fprintf(w, "%sFilename:%s\t%s\n", theme.Header, Reset, cert.Filename)
    fmt.Fprintf(w, "%sEncoding:%s\t%s\n", theme.Header, Reset, cert.Encoding)

    // Status colorato
    statusColor := theme.Valid
    if cert.Status == "expired" {
        statusColor = theme.Expired
    } else if cert.Status == "expiring soon" {
        statusColor = theme.Warning
    }
    fmt.Fprintf(w, "%sStatus:%s\t%s%s%s\n", theme.Header, Reset, statusColor, cert.Status, Reset)

    // PQC colorato
    if cert.QuantumSafe {
        fmt.Fprintf(w, "%sQuantum Safe:%s\t%s%s%s\n", theme.Header, Reset, theme.PQC, cert.PQCType, Reset)
    }
}
```

**Dipendenza:**

```bash
go get github.com/mattn/go-isatty
```

### 40. Analisi sicurezza del certificato
**File:** Nuovo `pkg/security/analyzer.go`, nuovo comando `cmd/audit.go`

Verificare problemi di sicurezza: key length, algoritmi deboli, estensioni rischiose.

```bash
# Usage
certinfo audit server.crt
# Output: lista warning/error con severity
```

**Implementazione:**

```go
// pkg/security/analyzer.go
package security

type SecurityIssue struct {
    Severity   string  // "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    Category   string
    Message    string
    Remediation string
}

type SecurityReport struct {
    Score         int            // 0-100
    Issues        []SecurityIssue
    Summary       string
}

func AnalyzeCertificate(cert *certificate.CertificateInfo) *SecurityReport {
    var issues []SecurityIssue

    // Check: Key length
    if cert.KeyType == "RSA" && cert.Bits < 2048 {
        issues = append(issues, SecurityIssue{
            Severity:   "CRITICAL",
            Category:   "Key Strength",
            Message:    fmt.Sprintf("RSA key too short: %d bits (minimum 2048)", cert.Bits),
            Remediation: "Generate new certificate with RSA 2048+ or use ECDSA",
        })
    }

    // Check: Algoritmi obsoleti
    weakAlgos := map[string]bool{
        "SHA1WithRSAEncryption": true,
        "MD5":                   true,
    }
    if weakAlgos[cert.Algorithm] {
        issues = append(issues, SecurityIssue{
            Severity:   "CRITICAL",
            Category:   "Signature Algorithm",
            Message:    fmt.Sprintf("Weak signature algorithm: %s", cert.Algorithm),
            Remediation: "Use SHA-256 or SHA-384 with RSA/ECDSA",
        })
    }

    // Check: Certificato CA disabilitato per uso server
    if cert.IsCA {
        issues = append(issues, SecurityIssue{
            Severity:   "HIGH",
            Category:   "Usage",
            Message:    "Certificate has CA flag enabled",
            Remediation: "Ensure this is intentional for intermediate CA",
        })
    }

    // Check: NotAfter troppo lontano (>398 days per browser trust)
    // Parsare la data e calcolare giorni

    // Check: Subject vuoto o CN mancante
    if cert.CommonName == "" {
        issues = append(issues, SecurityIssue{
            Severity:   "MEDIUM",
            Category:   "Subject",
            Message:    "Certificate has no Common Name",
            Remediation: "Add CN or SAN for identification",
        })
    }

    return &SecurityReport{
        Score:  calculateScore(issues),
        Issues: issues,
        Summary: summarize(issues),
    }
}

func calculateScore(issues []SecurityIssue) int {
    // Calcolare score basato su severità
    score := 100
    for _, issue := range issues {
        switch issue.Severity {
        case "CRITICAL":
            score -= 40
        case "HIGH":
            score -= 25
        case "MEDIUM":
            score -= 10
        case "LOW":
            score -= 5
        }
    }
    if score < 0 {
        score = 0
    }
    return score
}
```

**Nuovo comando CLI:**

```go
// cmd/audit.go
var auditCmd = &cobra.Command{
    Use:   "audit [certfile]",
    Short: "Analyze certificate security",
    Long:  "Check certificate for security issues and vulnerabilities",
    Run: func(cmd *cobra.Command, args []string) {
        cert, err := certificate.ParseCertificate(args[0])
        report := security.AnalyzeCertificate(cert)
        // output report con colori
    },
}
```

**Output esempio:**

```
=== Security Audit Report ===
Score: 65/100

CRITICAL (Key Strength):
  - RSA key too short: 1024 bits (minimum 2048)
  Remediation: Generate new certificate with RSA 2048+ or use ECDSA

HIGH (Signature Algorithm):
  - Weak signature algorithm: SHA1WithRSAEncryption
  Remediation: Use SHA-256 or SHA-384 with RSA/ECDSA

MEDIUM (Validity):
  - Certificate expires in 401 days (>398 days for browser trust)
```

### Riepilogo Funzionalità

| # | Funzionalità | Priorità | Difficoltà |
|---|--------------|----------|------------|
| 37 | Confronto chiave-certificato | Alta | Media |
| 38 | Supporto PKCS#12 | Alta | Media |
| 39 | Colorazione output | Media | Bassa |
| 40 | Analisi sicurezza | Alta | Media-Alta |
