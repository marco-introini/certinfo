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

## Problemi Critici Aggiuntivi

### 26. Loop infinito in `FindBlock` con file PEM malformed

**File:** `pkg/pem/pem.go:31-45`

**Problema:** Se un file PEM è malformed (senza `-----END-----`), `pem.Decode` restituisce sempre un block non-nil ma con dati parziali, causando un loop infinito che consuma memoria fino all'OOM.

**Rimedio:** Aggiungere limite `maxPEMBlocks = 100` e controllo `len(rest) == 0`.

### 27. Errori silenziati in `filepath.Walk`

**File:** `pkg/certificate/analyzer.go:71-74`, `pkg/privatekey/parser.go:377-380`

**Problema:** Qualsiasi errore (permessi, file corrotto, filesystem) viene silenziato. L'utente non sa quali file sono stati saltati.

**Rimedio:** Implementare callback per errori o logging strutturato.

### 28. Nessun limite dimensione file

**File:** `pkg/certificate/parser.go:196-199`, `pkg/privatekey/parser.go:190-193`

**Problema:** `os.ReadFile` legge file interi senza limiti. Rischio OOM con file malevoli.

**Rimedio:** Aggiungere costante `maxFileSizeBytes = 50 * 1024 * 1024` e validazione.

### 29. Parsing PKCS8 con loop PQC incompleto

**File:** `pkg/privatekey/parser.go:278-294`

**Problema:** Il loop `for _, pqc := range pqcTypes` non ha break, quindi solo l'ultimo PQC viene applicato a `Bits`.

**Rimedio:** Ristrutturare per raccogliere tutti i PQC types in una slice.

### 30. String matching PQC vulnerabile a falsi positivi

**File:** `pkg/certificate/parser.go:54-63`, `pkg/privatekey/parser.go:36-46`

**Problema:** `strings.Contains` è troppo permissivo. Un algoritmo "dummy-ml-dsa-test" verrebbe riconosciuto come PQC. Bug: `" sphincs"` ha spazio iniziale.

**Rimedio:** Usare regex con word boundary.

### 31. Resource leak con file aperti

**File:** `pkg/certificate/parser.go:196-203`, `pkg/privatekey/parser.go:190-197`

**Problema:** Nessun `defer f.Close()` dopo `os.Open`.

**Rimedio:** Aggiungere `defer f.Close()` in entrambe le funzioni.

### 32. Panic potenziale con chiave nil

**File:** `pkg/certificate/parser.go:34-52`

**Problema:** Nessuna validazione se `key.N` o `key.Curve` sono nil.

**Rimedio:** Aggiungere controlli nil prima di accedere ai campi.

---

## Errori da Sistemare Aggiuntivi

### 33. Duplicazione logica PQC tra package

**Problema:** Funzioni PQC duplicate in `pkg/certificate/parser.go` e `pkg/privatekey/parser.go`.

**Rimedio:** Creare package centralizzato `pkg/pqc/detector.go`.

### 34. Costanti sparse nel codebase

**Problema:** Costanti definite senza centralizzazione.

**Rimedio:** Creare `pkg/config/constants.go`.

### 35. Error handling inconsistente

**Problema:** Errori gestiti in modo diverso tra package.

**Rimedio:** Definire errori standard in `pkg/errors/errors.go`.

---

## Funzionalità Aggiuntive

### 41. Flag per report JSON strutturato con errori

**File:** `cmd/*.go`

Aggiungere output JSON che include metadata, errori e statistiche.

### 42. Progress bar per operazioni su directory grandi

**Rimedio:** Usare libreria per mostrare progresso durante `SummarizeDirectoryRecursive`.

### 43. Filtri per estensione file

**Rimedio:** Aggiungere flag `--ext .crt,.cer` per filtrare i file processati.

### 44. Output machine-readable per errore

**Rimedio:** Aggiungere flag `--quiet` che disabilita messaggi umani.

### 45. Configurazione via file

**Rimedio:** Supportare file di configurazione `.certinfo.yaml`.

### 46. Verbose mode per debugging

**Rimedio:** Aggiungere flag `-v/--verbose` per debug output.

---

## Riepilogo Attivita

| #   | Attivita                                            | Stato |
| --- | --------------------------------------------------- | ----- |
| 1   | Aggiornamento go.mod a Go 1.25                      | ✅    |
| 2   | Creazione package `pkg/pem`                         | ✅    |
| 3   | Refactoring `pkg/certificate/parser.go`             | ✅    |
| 4   | Refactoring `pkg/privatekey/parser.go`              | ✅    |
| 5   | Fix parsing duplicato PKCS8                         | ✅    |
| 6   | Fix potenziale panic chiave sconosciuta             | ✅    |
| 7   | Fix errori ignorati time.Parse                      | ✅    |
| 8   | Fix errori ignorati json.MarshalIndent              | ✅    |
| 9   | Aggiunta costante dateFormat                        | ✅    |
| 10  | Unificazione logica status con getCertStatus()      | ✅    |
| 11  | Magic number giorni scadenza                        | ✅    |
| 12  | Costante dateFormat in output.go                    | ✅    |
| 13  | CertificateInfo usa time.Time                       | ✅    |
| 14  | Pre-allocazione slice summary                       | ✅    |
| 15  | Flag -f e -r unificati in root                      | ✅    |
| 16  | Supporto Post-Quantum Cryptography                  | ✅    |
| 17  | Magic string per header tabella                     | ⚠️    |
| 18  | Usare `context.Context` per cancellazione           | ⚠️    |
| 19  | Usare `filepath.Clean` per normalizzare percorsi    | ⚠️    |
| 20  | Commenti godoc mancanti                             | ⚠️    |
| 21  | Unificare output formatting con generici            | ⚠️    |
| 22  | Loop infinito in `FindBlock` con file PEM malformed | ⚠️    |
| 23  | Errori silenziati in `filepath.Walk`                | ⚠️    |
| 24  | Nessun limite dimensione file                       | ⚠️    |
| 25  | Parsing PKCS8 con loop PQC incompleto               | ⚠️    |
| 26  | String matching PQC vulnerabile a falsi positivi    | ⚠️    |
| 27  | Resource leak con file aperti                       | ⚠️    |
| 28  | Panic potenziale con chiave nil                     | ⚠️    |
| 29  | Duplicazione logica PQC tra package                 | ⚠️    |
| 30  | Costanti sparse nel codebase                        | ⚠️    |
| 31  | Error handling inconsistente                        | ⚠️    |
| 32  | Flag per report JSON strutturato con errori         | ⚠️    |
| 33  | Progress bar per operazioni su directory grandi     | ⚠️    |
| 34  | Filtri per estensione file                          | ⚠️    |
| 35  | Output machine-readable per errore                  | ⚠️    |
| 36  | Configurazione via file                             | ⚠️    |
| 37  | Verbose mode per debugging                          | ⚠️    |

**Totale:** 16 completati, 21 da completare
