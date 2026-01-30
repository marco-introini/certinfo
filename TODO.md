# TODO - Miglioramenti al codice Go

Questo file traccia i problemi, i bug e i miglioramenti necessari per il progetto `certinfo`.

## 🔴 Problemi Critici (Sicurezza & Stabilità)
Problemi che possono causare crash, vulnerabilità (DoS) o loop infiniti.

### 1. Loop infinito in `FindBlock` con file PEM malformed
**File:** `pkg/pem/pem.go:31-45`
**Problema:** Il loop `for` non ha un limite di iterazioni e non verifica se `rest` si riduce. Con input corrotto o specifici pattern, può andare in loop infinito.
**Soluzione:** Introdurre un limite massimo di blocchi (es. 100) e verificare il progresso del parsing.

### 2. Nessun limite dimensione file (Rischio DoS)
**File:** `pkg/certificate/parser.go:197`, `pkg/privatekey/parser.go:191`
**Problema:** `os.ReadFile` carica l'intero file in RAM. Un file enorme (bomb) può causare OOM.
**Soluzione:** Usare `io.LimitReader` o controllare `FileInfo.Size()` prima di leggere, impostando un limite (es. 10MB).

### 3. Errori silenziati in `filepath.Walk`
**File:** `pkg/certificate/analyzer.go:71`, `pkg/privatekey/parser.go:377`
**Problema:** Le callback di `filepath.Walk` ritornano `nil` anche in caso di errore (es. "permission denied"), nascondendo fallimenti parziali all'utente.
**Soluzione:** Collezionare gli errori o loggarli su stderr (visibili in modalità verbose).

## 🟠 Bug ad Alta Priorità
Bug che compromettono la correttezza dei dati analizzati.

### 4. Parsing PKCS8 con sovrascrittura PQC
**File:** `pkg/privatekey/parser.go:318`
**Problema:** Il loop `for _, pqc := range pqcTypes` sovrascrive i campi `info` ad ogni iterazione. Se vengono rilevati più tipi (o falsi positivi), vince l'ultimo, perdendo i precedenti.
**Soluzione:** Raccogliere tutti i tipi rilevati o fermarsi al primo match valido e confermato.

### 5. String matching PQC vulnerabile a falsi positivi
**File:** `pkg/certificate/parser.go:56`, `pkg/privatekey/parser.go:38`
**Problema:** `strings.Contains` è troppo permissivo. Un file con testo "dummy-ml-dsa-test" viene flaggato come PQC.
**Soluzione:** Usare regex con word boundaries o parsing più stretto degli OID/stringhe.

### 6. Robustezza `getKeyBitsAndType` per chiavi sconosciute
**File:** `pkg/certificate/parser.go:34-52`
**Problema:** La funzione assume tipi standard. Se arriva un tipo inatteso (ma non nil), il fallback `default` è sicuro, ma l'accesso ai campi in casi ibridi potrebbe essere fragile.
**Soluzione:** Aggiungere controlli espliciti sui campi (es. `key.N != nil`) prima dell'accesso.

## 🟡 Qualità del Codice & Refactoring
Miglioramenti per manutenibilità e pulizia.

### 7. Centralizzazione Logica PQC
**Problema:** La logica di detection PQC è duplicata (e leggermente diversa) tra `certificate` e `privatekey`.
**Soluzione:** Estrarre tutto in un package `pkg/pqc` o `pkg/crypto/pqc`.

### 8. Centralizzazione Costanti (Magic Strings)
**Problema:** Stringhe come "ML-DSA", "ML-KEM", "expired" sono hardcoded in più punti.
**Soluzione:** Creare `pkg/consts` per algoritmi, formati e stati.

### 9. Rimozione Duplicazione Structs
**File:** `pkg/privatekey/parser.go`, `pkg/certificate/analyzer.go`
**Problema:** `KeyInfo` e `KeySummary` sono quasi identici. Idem per `CertificateInfo` e `CertificateSummary`.
**Soluzione:** Unificare le struct o usare embedding per evitare definizioni ridondanti.

### 10. Rimozione Magic Numbers
**File:** `pkg/certificate/analyzer.go`
**Problema:**
- `const daysUntilExpiring = 30`: Valore fisso, dovrebbe essere configurabile o almeno una costante esportata.
- `summaries := make(..., 0, 32)`: Capacità iniziale arbitraria in scansioni ricorsive.
**Soluzione:** Estrarre costanti e rendere configurabile la soglia di scadenza.

### 11. Header Tabelle Hardcoded
**File:** `pkg/utils/output.go`
**Problema:** Le intestazioni delle tabelle sono definite dentro le funzioni di stampa.
**Soluzione:** Definire le colonne come costanti o configurazione.

### 12. Normalizzazione Percorsi
**Problema:** I path dei file non vengono puliti con `filepath.Clean` prima dell'uso/output.
**Soluzione:** Sanitizzare tutti i path in ingresso.

### 13. Aggiunta Commenti Godoc
**Problema:** Molte funzioni esportate (`Public`) mancano di documentazione.
**Soluzione:** Aggiungere commenti standard Go per migliorare l'intellisense e la documentazione generata.

## 🟢 Nuove Funzionalità (Future)

### 14. Output JSON Strutturato
Wrapper JSON con metadati (timestamp, versione, errori) invece di lista piatta array.

### 15. File di Configurazione
Supporto per `.certinfo.yaml` per default personalizzati (es. soglia scadenza, colori).

### 16. Filtri Estensioni
Flag `--ext` per limitare la scansione a certe estensioni (es. solo `.pem`, `.crt`).

### 17. Verbose / Quiet Mode
Flag `-v` (debug log) e `-q` (solo output dati).

### 18. Progress Bar
Indicatore visivo per scansioni di directory molto grandi.

---
*Ultimo aggiornamento: 30 Gennaio 2026*
