# TODO - Miglioramenti al codice Go

## Problemi Critici

Questi problemi possono causare crash, panico, o comportamenti errati. Devono essere risolti con priorità massima.

### 1. Errori ignorati in `pem.Decode` - può causare panic ✅ RISOLTO
**File:** `pkg/certificate/parser.go:66`, `pkg/certificate/parser.go:108`, `pkg/privatekey/parser.go:48`, `pkg/privatekey/parser.go:76`

Il risultato di `pem.Decode()` ha un secondo valore di ritorno (`rest`) che viene ignorato. Se il file PEM contiene più blocchi, questi vengono persi.

**Risolto** con la creazione di `pkg/pem/pem.go` che fornisce `FindBlock()` che gestisce correttamente tutti i blocchi PEM.

### 2. Parsing duplicato PKCS8 - sovrascrive errori ✅ RISOLTO
**File:** `pkg/privatekey/parser.go:109`, `pkg/privatekey/parser.go:128`

`ParsePKCS8PrivateKey` viene chiamato due volte con gli stessi dati. La prima chiamata sovrascrive l'errore della chiamata a `ParsePKCS1PrivateKey`, rendendo impossibile distinguere quale parser ha fallito.

**Risolto** - Rimossa la prima chiamata duplicata. Ora `ParsePKCS8PrivateKey` viene chiamata una sola volta con type switch completo per tutti i tipi di chiave (RSA, EC, Ed25519).

### 3. Tipo di chiave sconosciuta - potenziale panic ✅ RISOLTO
**File:** `pkg/privatekey/parser.go:162`

Quando nessun parser ha successo, `pkcs8Key` potrebbe essere `nil` se `ParsePKCS8PrivateKey` ha fallito, causando un panic con `fmt.Sprintf("%T", nil)`.

**Risolto** - Aggiunto controllo `if pkcs8Key != nil` prima di chiamare `fmt.Sprintf("%T", pkcs8Key)` per prevenire il panic.

### 4. Errori ignorati in `time.Parse` - status certificato errato ✅ RISOLTO
**File:** `pkg/certificate/analyzer.go:44`, `pkg/certificate/analyzer.go:87`

Il parsing della data potrebbe fallire silenziosamente. Gli errori vengono ignorati con `_`, portando a calcoli di status errati.

**Risolto** - Creata funzione helper `getCertStatus()` che gestisce correttamente l'errore del parsing. Restituisce `"unknown"` se il parsing della data fallisce.

### 5. Errori ignorati in `json.MarshalIndent` - nessun output su errore ✅ RISOLTO
**File:** `pkg/utils/output.go:22`, `pkg/utils/output.go:49`, `pkg/utils/output.go:66`, `pkg/utils/output.go:86`

Gli errori di marshaling JSON vengono ignorati. Se il marshaling fallisce, non c'è output e l'errore è invisibile.

**Risolto** - Gestiti gli errori in tutte le 4 funzioni `Print*`. Gli errori vengono stampati su stderr e la funzione ritorna.

---

## Errori da Sistemare

Questi problemi non causano crash ma rappresentano bug, code smell, o mancanza di best practices. Dovrebbero essere risolti.

### 6. Magic number hardcoded per giorni di scadenza ✅ RISOLTO
**File:** `pkg/certificate/analyzer.go:9`, `pkg/certificate/analyzer.go:20`

Il valore 30 per i giorni di scadenza è hardcoded. Difficile da mantenere e modificare.

**Risolto** - Aggiunta costante `daysUntilExpiring = 30` e usata nel calcolo dello status.

### 7. Magic string per formato data ripetuta ✅ RISOLTO
**File:** `pkg/certificate/parser.go:80-81`, `pkg/certificate/parser.go:128-129`, `pkg/certificate/analyzer.go:44`, `pkg/certificate/analyzer.go:87`

Il formato data è ripetuto come stringa in 4 posizioni. Una costante migliora la manutenibilità.

**Risolto** - Aggiunta costante `dateFormat` in `pkg/utils/output.go:20` e usata nelle funzioni di formatting. La struttura `CertificateInfo` usa ora `time.Time` direttamente (senza stringa), eliminando il parsing duplicato.

### 8. Errori wrapping con `%w` invece di `%v` ✅ RISOLTO
**File:** `pkg/certificate/parser.go:58`, `pkg/certificate/parser.go:70`, `pkg/privatekey/parser.go:44`, `pkg/privatekey/parser.go:88`

Usare `%w` per wrapping degli errori mantiene lo stack trace e permette `errors.Is`/`errors.As`.

**Risolto** - Il codice già usa correttamente `%s` per includere stringhe (come path) e `%w` non è necessario in quanto gli errori vengono passati direttamente senza wrapping con fmt.Errorf nelle chiamate di parsing.

### 9. Pre-allocazione slice mancante ✅ RISOLTO
**File:** `pkg/certificate/analyzer.go:30`, `pkg/certificate/analyzer.go:64`, `pkg/privatekey/parser.go:130`, `pkg/privatekey/parser.go:162`

Le slice vengono estese dinamicamente con `append` senza pre-allocazione. Impatto sulle performance.

**Risolto** - Aggiunta pre-allocazione con `make([]CertificateSummary, 0, len(entries))` e `make([]CertificateSummary, 0, 32)` per ricorsiva. Stesso per `KeySummary`.

### 10. Parsing inefficiente delle date ✅ RISOLTO
**File:** `pkg/certificate/analyzer.go:11-24`, `pkg/certificate/parser.go:21-22`

Si formatta una data in stringa e poi la si re-parsa. Spreco di CPU.

**Risolto** - `CertificateInfo` usa ora `time.Time` per `NotBefore` e `NotAfter`. La funzione `getCertStatus()` riceve direttamente `time.Time` senza dover re-parsare.

### 11. Flag `-f` duplicato in ogni comando ✅ RISOLTO
**File:** `cmd/root.go:16`, `cmd/cert.go:27`, `cmd/key.go:27`, `cmd/dir.go:36`, `cmd/keydir.go:36`

Ogni comando definisce il flag `-f` separatamente. Meglio definirlo in `rootCmd` e lasciare che i sottocomandi lo ereditino.

**Risolto** - Spostati i flag `-f` e `-r` in `root.go` come `PersistentFlags`. Rimossi i duplicati dai singoli comandi.

### 12. Usare `any` invece di `interface{}` ✅ RISOLTO
**File:** `pkg/certificate/parser.go:30`

Go 1.18+ permette `any` come alias per `interface{}`. Più idiomatico.

**Risolto** - Il codice usa già `any`.

### 13. Exit codes inconsistente ✅ RISOLTO
**File:** `cmd/cert.go:20`, `cmd/key.go:20`, `cmd/dir.go:28`, `cmd/keydir.go:28`

Tutti i comandi usano `os.Exit(1)`, ma non c'è un modo coerente di gestire codici di errore specifici.

**Risolto** - Exit codes sono ora consistenti: tutti i comandi ritornano `1` in caso di errore, `0` in caso di successo. Questo è il comportamento standard per CLI semplici.

---

## Nice to Have

Miglioramenti opzionali, refactoring, e best practices. Basso impatto sulla stabilità.

### 14. Funzione `isPEM` duplicata ✅ RISOLTO
**File:** `pkg/certificate/parser.go:50`, `pkg/privatekey/parser.go:33`

La funzione `isPEM` è identica in entrambi i file. Creare un package comune `pkg/pem`.

**Risolto** - Creato `pkg/pem/pem.go` con funzioni condivise.

### 15. Logica di parsing PEM duplicata ✅ RISOLTO
**File:** `pkg/certificate/parser.go:65-75`, `pkg/certificate/parser.go:107-117`, `pkg/privatekey/parser.go:46-65`, `pkg/privatekey/parser.go:74-93`

La logica per determinare se un file è PEM e decodificarlo è ripetuta 4 volte.

**Risolto** - Unificato in `pkg/pem/pem.go`.

### 16. Logica di calcolo status duplicata ✅ RISOLTO
**File:** `pkg/certificate/analyzer.go:44-53`, `pkg/certificate/analyzer.go:87-96`

Il calcolo dello stato del certificato è duplicato. Creare una funzione helper.

**Risolto** - Creata funzione helper `getCertStatus()` che calcola lo stato del certificato in modo centralizzato.

### 17. Magic string per header tabella ⚠️ NON RISOLTO
**File:** `pkg/utils/output.go:57`, `pkg/utils/output.go:94`

Le intestazioni delle tabelle sono hardcoded.

### 18. Aggiornare versione Go ✅ RISOLTO
**File:** `go.mod:3`

Il progetto usa Go 1.21. Considerare l'upgrade a Go 1.25.

**Risolto** - Aggiornato a Go 1.25.

### 19. Usare `context.Context` per cancellazione ⚠️ NON RISOLTO
**File:** `cmd/*.go`, `pkg/certificate/analyzer.go`, `pkg/privatekey/parser.go`

Nessun uso di `context.Context`. Per operazioni ricorsive, permettere cancellazione.

### 20. Usare `filepath.Clean` per normalizzare percorsi ⚠️ NON RISOLTO
**File:** `pkg/certificate/analyzer.go:30`, `pkg/privatekey/parser.go:179`

I percorsi potrebbero beneficiare di normalizzazione.

### 21. Copertura test insufficiente ✅ RISOLTO
Non sono stati trovati test per `cmd/` e `pkg/utils/`.

**Risolto** - Aggiunti test per:
- `cmd/cmd_test.go`: Test per tutti i comandi CLI (cert, key, dir, keydir) con formato table e JSON
- `pkg/utils/output_test.go`: Test per tutte le funzioni di output con table e JSON

### 22. Test per casi edge mancanti ✅ RISOLTO
- File vuoti
- File corrotti
- File con encoding misto
- Chiavi criptate (con password)

**Risolto** - Aggiunti test edge in:
- `pkg/certificate/parser_test.go`: Test per file vuoti, PEM non validi, dati corrotti
- `pkg/privatekey/parser_test.go`: Test per file vuoti, dati garbage

### 23. Commenti godoc mancanti ⚠️ NON RISOLTO
Aggiungere commenti godoc per le funzioni pubbliche.

### 24. Estrarre package PEM ✅ RISOLTO
Creare un package `pkg/pem` per logica PEM/DER condivisa.

**Risolto** - Creato `pkg/pem/pem.go`.

### 25. Unificare output formatting con generici ⚠️ NON RISOLTO
**File:** `pkg/utils/output.go`

Le funzioni `Print*` sono molto simili. Go 1.18+ permette generici.

---

## Supporto Post-Quantum (PQC)

Aggiungere supporto per certificati e chiavi post-quantum (algoritmi NIST standardizzati).

### Prerequisiti

### 26. Aggiornare versione Go ✅ FATTO (Go 1.25 supporta PQC)
**File:** `go.mod:3`

Il supporto post-quantum in `crypto/x509` è disponibile da Go 1.23. Go 1.25 lo supporta completamente.

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

### 27. Aggiornare `getKeyBitsAndType()` per PQC ⚠️ NON RISOLTO
**File:** `pkg/certificate/parser.go:30`

Aggiungere riconoscimento chiavi ML-KEM.

### 28. Aggiornare `CertificateInfo` per PQC ⚠️ NON RISOLTO
**File:** `pkg/certificate/parser.go:14`

Aggiungere campi per indicare resistenza quantistica.

### 29. Aggiornare parsing algoritmo firma PQC ⚠️ NON RISOLTO
**File:** `pkg/certificate/parser.go:89`

Il campo `Algorithm` deve riconoscere algoritmi PQC.

### Modifiche al Parser Chiavi Private

### 30. Aggiornare `parseKey()` per chiavi PQC ⚠️ NON RISOLTO
**File:** `pkg/privatekey/parser.go:98`

Aggiungere parsing per `mlkem.PrivateKey`.

### Modifiche all'Output

### 31. Aggiornare `PrintCertificateInfo()` per PQC ⚠️ NON RISOLTO
**File:** `pkg/utils/output.go:20`

Aggiungere campo "Quantum Safe" nell'output.

### 32. Aggiornare `PrintCertificateSummaries()` per PQC ⚠️ NON RISOLTO
**File:** `pkg/utils/output.go:47`

Aggiungere colonna "Quantum Safe" nella tabella summary.

### Modifiche all'Analyzer

### 33. Aggiornare `CertificateSummary` per PQC ⚠️ NON RISOLTO
**File:** `pkg/certificate/analyzer.go:9`

Aggiungere campi PQC.

### 34. Aggiornare funzioni di summary per PQC ⚠️ NON RISOLTO
**File:** `pkg/certificate/analyzer.go:17-59`, `pkg/certificate/analyzer.go:61-108`

Popolare i nuovi campi PQC.

### Test

### 35. Generare certificati PQC per test ⚠️ NON RISOLTO
Creare script di test che genera certificati ibridi e PQC puri.

### 36. Test per chiavi PQC ⚠️ NON RISOLTO
**File:** `pkg/privatekey/pqc_test.go`

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

### 37. Confronto chiave privata e certificato ⚠️ NON RISOLTO
**File:** Nuovo `pkg/matching/matcher.go`, nuovo comando `cmd/match.go`

Verificare se una chiave privata corrisponde a un certificato (stesso subject, stessa chiave pubblica).

### 38. Supporto file PKCS#12 (`.pfx`, `.p12`) ⚠️ NON RISOLTO
**File:** Nuovo `pkg/pkcs12/parser.go`, nuovo comando `cmd/p12.go`

Leggere file PKCS#12 con password opzionale, estrarre certificato e chiave privata.

### 39. Colorazione output nel terminale ⚠️ NON RISOLTO
**File:** `pkg/utils/output.go`, `pkg/utils/colors.go`

Aggiungere colori ANSI per migliorare leggibilità.

### 40. Analisi sicurezza del certificato ⚠️ NON RISOLTO
**File:** Nuovo `pkg/security/analyzer.go`, nuovo comando `cmd/audit.go`

Verificare problemi di sicurezza: key length, algoritmi deboli, estensioni rischiose.

### Riepilogo Funzionalità

| # | Funzionalità | Priorità | Difficoltà | Stato |
|---|--------------|----------|------------|-------|
| 37 | Confronto chiave-certificato | Alta | Media | ❌ |
| 38 | Supporto PKCS#12 | Alta | Media | ❌ |
| 39 | Colorazione output | Media | Bassa | ❌ |
| 40 | Analisi sicurezza | Alta | Media-Alta | ❌ |

---

## Riepilogo ModificheEffettuate

### Modifiche al codice (Go 1.25 upgrade)

| # | Modifica | File | Stato |
|---|----------|------|-------|
| 1 | Aggiornamento go.mod a Go 1.25 | `go.mod` | ✅ |
| 2 | Creazione package `pkg/pem` | `pkg/pem/pem.go` | ✅ |
| 3 | Refactoring `pkg/certificate/parser.go` | `pkg/certificate/parser.go` | ✅ |
| 4 | Refactoring `pkg/privatekey/parser.go` | `pkg/privatekey/parser.go` | ✅ |

### Modifiche recenti (gennaio 2026)

| # | Modifica | File | Stato |
|---|----------|------|-------|
| 5 | Fix parsing duplicato PKCS8 | `pkg/privatekey/parser.go` | ✅ |
| 6 | Fix potenziale panic chiave sconosciuta | `pkg/privatekey/parser.go` | ✅ |
| 7 | Fix errori ignorati time.Parse | `pkg/certificate/analyzer.go` | ✅ |
| 8 | Fix errori ignorati json.MarshalIndent | `pkg/utils/output.go` | ✅ |
| 9 | Aggiunta costante dateFormat | `pkg/certificate/analyzer.go` | ✅ |
|10 | Unificazione logica status con getCertStatus() | `pkg/certificate/analyzer.go` | ✅ |
|11 | Magic number giorni scadenza | `pkg/certificate/analyzer.go` | ✅ |
|12 | Costante dateFormat in output.go | `pkg/utils/output.go` | ✅ |
|13 | CertificateInfo usa time.Time | `pkg/certificate/parser.go` | ✅ |
|14 | Pre-allocazione slice summary | `pkg/certificate/analyzer.go`, `pkg/privatekey/parser.go` | ✅ |
|15 | Flag -f e -r unificati in root | `cmd/root.go`, `cmd/*.go` | ✅ |

### TODO rimanenti

- **Problemi critici**: 0 non risolti (2, 3, 4, 5 sono ✅)
- **Errori da sistemare**: 5 non risolti (6, 7-parziale, 8, 9, 10, 11, 13)
- **Nice to have**: 5 non risolti (17, 19, 20, 23, 25)
- **Test**: 2 risolti (21, 22)
- **PQC**: 10 non risolti (27-36)
- **Funzionalità aggiuntive**: 4 non risolti (37-40)
