# TODO - Miglioramenti al codice Go

Questo file traccia i problemi e i miglioramenti necessari per il progetto.

## 🔴 Problemi Critici
Questi problemi possono causare crash, vulnerabilità di sicurezza o loop infiniti. Priorità assoluta.

### 1. Loop infinito in `FindBlock` con file PEM malformed (ex #26)
**File:** `pkg/pem/pem.go:31-45`
**Problema:** Se `pem.Decode` restituisce un blocco ma non consuma tutto l'input o se c'è un comportamento inatteso con file corrotti, il loop `for` diventa infinito.
**Soluzione:** Aggiungere un limite massimo di iterazioni (es. `maxPEMBlocks = 100`) e un controllo per verificare se `rest` si sta riducendo o se è vuoto.

### 2. Nessun limite dimensione file (ex #28)
**File:** `pkg/certificate/parser.go:197`, `pkg/privatekey/parser.go:191`
**Problema:** `os.ReadFile` legge l'intero file in memoria. Un file malevolo di grandi dimensioni può causare Denial of Service (OOM).
**Soluzione:** Implementare una lettura limitata (es. `io.LimitReader` o controllo dimensione prima di leggere) con una costante `MaxFileSizeBytes` (es. 10MB).

### 3. Potenziale panic con chiave nil (ex #32)
**File:** `pkg/certificate/parser.go:34-52` (`getKeyBitsAndType`)
**Problema:** Se `x509.ParseCertificate` ritorna un certificato con `PublicKey` valida ma con campi interni nil (o in casi edge di type assertion), l'accesso diretto a `key.N` o `key.Curve` può causare panic.
**Soluzione:** Aggiungere controlli difensivi per verificare che i campi della chiave non siano nil prima dell'accesso.

## 🟠 Bug ad Alta Priorità
Bug che causano comportamenti errati, dati falsati o errori silenziati.

### 4. Parsing PKCS8 con loop PQC incompleto (ex #29)
**File:** `pkg/privatekey/parser.go:318`
**Problema:** Il loop `for _, pqc := range pqcTypes` sovrascrive `info.KeyType`, `info.Bits` etc. ad ogni iterazione. Solo l'ultimo tipo PQC rilevato viene salvato.
**Soluzione:** Ristrutturare la logica per gestire multiple detection o fermarsi alla prima valida, oppure aggregare le informazioni correttamente.

### 5. String matching PQC vulnerabile a falsi positivi (ex #30)
**File:** `pkg/certificate/parser.go:56`, `pkg/privatekey/parser.go:38`
**Problema:** `strings.Contains` è troppo generico. Un file contenente testo come "dummy-ml-dsa-test" viene erroneamente identificato come algoritmo PQC.
**Soluzione:** Utilizzare regex con word boundaries o matching più stretto per evitare falsi positivi.

### 6. Errori silenziati in `filepath.Walk` (ex #27)
**File:** `pkg/certificate/analyzer.go:71`, `pkg/privatekey/parser.go:377`
**Problema:** La funzione callback di `filepath.Walk` ritorna `nil` anche in caso di errore (es. permessi negati), nascondendo il problema all'utente.
**Soluzione:** Raccogliere gli errori o loggarli su stderr (magari in verbose mode) invece di ignorarli silenziosamente.

## 🟡 Refactoring & Tech Debt
Miglioramenti alla qualità del codice, manutenibilità e standardizzazione.

### 7. Centralizzazione Logica PQC (ex #33)
**File:** `pkg/certificate/parser.go`, `pkg/privatekey/parser.go`
**Problema:** Logica di detection PQC duplicata e inconsistente tra i package.
**Soluzione:** Estrarre tutta la logica di identificazione PQC in un nuovo package `pkg/pqc`.

### 8. Centralizzazione Costanti (ex #34)
**Problema:** Stringhe magiche ("ML-DSA", "ML-KEM", ecc.) sparse nel codice.
**Soluzione:** Creare un package `pkg/consts` o simile per definire costanti globali per algoritmi e configurazioni.

### 9. Header tabelle hardcoded (ex #17)
**File:** `pkg/utils/output.go`
**Problema:** Le definizioni delle tabelle sono cablate nel codice di output.
**Soluzione:** Definire le strutture delle tabelle in modo più dichiarativo o come costanti.

### 10. Commenti Godoc mancanti (ex #23)
**Problema:** Molte funzioni esportate non hanno commenti di documentazione standard.
**Soluzione:** Aggiungere commenti godoc per tutte le funzioni e tipi esportati (`Public`).

### 11. Unificare output formatting con Generics (ex #25)
**File:** `pkg/utils/output.go`
**Problema:** Codice duplicato per stampare tabelle/JSON di certificati e chiavi.
**Soluzione:** Usare i Generics di Go 1.18+ per creare una funzione di output polimorfica.

### 12. Normalizzazione percorsi (ex #20)
**Problema:** Uso diretto di path senza `filepath.Clean`.
**Soluzione:** Applicare `filepath.Clean` ai path di input per evitare problemi con `..` o separatori doppi.

## 🟢 Funzionalità Aggiuntive
Nuove feature per arricchire il tool.

### 13. Output JSON strutturato con metadati (ex #41)
**Descrizione:** L'output JSON attuale è una lista piatta. Aggiungere un wrapper con metadati (timestamp scansione, versione tool, errori riscontrati).

### 14. Configurazione via file (ex #45)
**Descrizione:** Supportare un file `.certinfo.yaml` per definire default (es. output format, esclusioni directory).

### 15. Filtri per estensione (ex #43)
**Descrizione:** Flag `--ext` per specificare quali estensioni analizzare (default: tutte o smart detection).

### 16. Verbose / Quiet Mode (ex #46, #44)
**Descrizione:** Flag `-v` per debug (mostra file saltati, errori) e `-q` per output minimale (solo JSON/Table, niente log).

### 17. Progress Bar (ex #42)
**Descrizione:** Per scansioni ricorsive su grandi directory, mostrare una progress bar.

---
*Ultimo aggiornamento automatizzato: 30 Gennaio 2026*
