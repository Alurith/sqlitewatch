
# SQLiteWatch — Specifiche MVP

## 1. Obiettivo

SQLiteWatch è un tool da riga di comando per analizzare il comportamento runtime delle query SQLite eseguite da un'applicazione, senza richiedere modifiche al codice sorgente dell'applicazione stessa.

Il tool deve essere indipendente da:

* linguaggio di programmazione dell'applicazione;
* framework;
* ORM;
* driver SQLite utilizzato.

L'obiettivo principale dell'MVP è permettere di eseguire un qualsiasi comando sotto il controllo di SQLiteWatch:

```bash
sqlitewatch -- <command>
```

Esempi:

```bash
sqlitewatch -- pytest
sqlitewatch -- python manage.py test
sqlitewatch -- node app.js
sqlitewatch -- ./my-application
```

SQLiteWatch deve intercettare le query SQLite eseguite dal processo target, raccogliere metriche runtime relative agli statement e produrre un report finale.

---

# 2. Scope MVP

L'MVP deve:

1. avviare un processo target;
2. rilevare l'utilizzo di SQLite nel processo;
3. intercettare le principali funzioni della SQLite C API;
4. identificare gli statement SQL eseguiti;
5. raccogliere statistiche runtime tramite `sqlite3_stmt_status()`;
6. aggregare query equivalenti;
7. identificare potenziali problemi di performance;
8. produrre un report leggibile;
9. restituire un exit code utilizzabile in CI;
10. rilevare e segnalare chiaramente quando l'instrumentation non è possibile.

L'MVP non deve modificare il database né alterare le query eseguite.

---

# 3. Modello di utilizzo

Interfaccia principale:

```bash
sqlitewatch [options] -- <command> [args...]
```

Esempio:

```bash
sqlitewatch -- pytest
```

Flusso:

```text
SQLiteWatch
    │
    ├── avvia il processo target
    │
    ├── attiva l'instrumentation
    │
    ▼
Applicazione
    │
    ▼
SQLite C API
    │
    ├── SQLiteWatch osserva gli statement
    │
    ▼
Database SQLite
```

Quando il processo termina:

```text
Process terminato
        │
        ▼
Aggregazione statistiche
        │
        ▼
Valutazione regole
        │
        ▼
Report
        │
        ▼
Exit code
```

---

# 4. Requisito fondamentale: zero modifiche all'applicazione

L'applicazione target non deve:

* importare SQLiteWatch;
* installare middleware;
* modificare il proprio ORM;
* registrare callback;
* modificare le connessioni SQLite;
* usare una build SQLite personalizzata.

Il seguente codice, per esempio:

```python
User.objects.filter(email="test@example.com")
```

oppure:

```javascript
db.prepare("SELECT * FROM users WHERE email = ?").get(email)
```

deve essere osservabile senza modificare l'applicazione.

SQLiteWatch deve operare sul livello della SQLite C API utilizzata dal processo.

---

# 5. Compatibilità SQLite

L'MVP deve utilizzare esclusivamente API disponibili nelle normali build SQLite.

Non deve richiedere:

```text
SQLITE_ENABLE_STMT_SCANSTATUS
```

o altre compile-time option non normalmente disponibili.

Le metriche principali devono essere ottenute tramite:

```text
sqlite3_stmt_status()
```

Utilizzando almeno:

```text
SQLITE_STMTSTATUS_FULLSCAN_STEP
SQLITE_STMTSTATUS_SORT
SQLITE_STMTSTATUS_AUTOINDEX
SQLITE_STMTSTATUS_VM_STEP
```

---

# 6. Funzioni SQLite da intercettare

L'MVP deve osservare almeno il ciclo di vita dei prepared statement.

Funzioni principali:

```text
sqlite3_prepare_v2
sqlite3_prepare_v3
sqlite3_reset
sqlite3_finalize
```

È possibile supportare ulteriori entry point equivalenti utilizzati da specifiche versioni o binding SQLite.

Per ogni prepared statement deve essere mantenuta un'associazione:

```text
sqlite3_stmt* → StatementContext
```

Esempio:

```text
0x12345678
    │
    ├── SQL
    ├── database
    ├── numero esecuzioni
    └── statistiche
```

---

# 7. Ciclo di raccolta dati

Quando viene creato uno statement:

```text
sqlite3_prepare_v2()
```

SQLiteWatch registra almeno:

```text
statement pointer
SQL originale
database connection
```

Prima di:

```text
sqlite3_reset()
```

o:

```text
sqlite3_finalize()
```

SQLiteWatch legge le metriche dello statement tramite:

```text
sqlite3_stmt_status()
```

Le statistiche minime raccolte sono:

```text
fullscan_steps
sort_operations
autoindex_operations
vm_steps
```

L'esecuzione originale deve quindi proseguire normalmente.

---

# 8. Metriche per statement

Ogni esecuzione di uno statement deve poter produrre logicamente un record equivalente a:

```json
{
  "sql": "SELECT * FROM users WHERE email = ?",
  "fullscan_steps": 15000,
  "sorts": 0,
  "autoindex": 0,
  "vm_steps": 43000
}
```

Le metriche richieste nell'MVP sono:

### Full scan steps

Numero di step associati a scansioni complete.

Utilizzato per identificare query che possono scalare linearmente con la dimensione della tabella.

### VM steps

Numero complessivo di operazioni eseguite dalla macchina virtuale SQLite.

Utilizzato come indicatore approssimativo del lavoro computazionale richiesto dalla query.

### Sort

Numero di operazioni di ordinamento.

Serve a evidenziare query che richiedono sort espliciti.

### Automatic index

Utilizzo o creazione di indici automatici da parte di SQLite.

Può indicare query per cui un indice persistente potrebbe essere opportuno.

---

# 9. Normalizzazione delle query

Le query equivalenti devono essere aggregate.

Per esempio:

```sql
SELECT * FROM users WHERE id = 42;
```

e:

```sql
SELECT * FROM users WHERE id = 73;
```

dovrebbero essere considerate la stessa query quando possibile.

La normalizzazione non deve però alterare query già parametrizzate:

```sql
SELECT * FROM users WHERE id = ?;
```

L'MVP può utilizzare una strategia conservativa.

È preferibile non normalizzare una query piuttosto che aggregare erroneamente query semanticamente diverse.

---

# 10. Aggregazione

Per ogni query normalizzata devono essere mantenute almeno:

```text
executions
total_fullscan_steps
max_fullscan_steps
total_vm_steps
max_vm_steps
total_sorts
total_autoindex
```

Esempio:

```text
SELECT * FROM users WHERE email = ?

executions:          425
fullscan total:      4,250,000
fullscan max:        10,000
vm steps total:      13,720,312
vm steps max:        45,231
sorts:               0
autoindex:           0
```

---

# 11. Rilevazione problemi

L'MVP deve classificare almeno quattro categorie.

## Full table scan significativo

Una query presenta un numero di `FULLSCAN_STEP` superiore alla soglia configurata.

Esempio:

```text
FULL SCAN
fullscan_steps: 150000
```

## Query computazionalmente costosa

Una query supera una soglia di:

```text
VM_STEP
```

Esempio:

```text
HIGH VM WORK
vm_steps: 1200000
```

## Sort

Una query esegue operazioni di ordinamento.

Non deve necessariamente essere considerato un errore.

Deve essere segnalabile.

## Automatic index

SQLite utilizza un indice automatico.

La query deve essere segnalata come potenziale candidata alla creazione di un indice persistente.

---

# 12. Soglie

L'MVP deve supportare almeno:

```text
--fail-fullscan-steps <N>
--fail-vm-steps <N>
--fail-on-autoindex
```

Possibile esempio:

```bash
sqlitewatch \
    --fail-fullscan-steps 10000 \
    --fail-vm-steps 1000000 \
    --fail-on-autoindex \
    -- pytest
```

Il semplice verificarsi di un full scan non deve causare automaticamente un errore.

Un full scan su una tabella molto piccola può essere perfettamente legittimo.

---

# 13. Report CLI

Output minimo:

```text
SQLiteWatch
────────────────────────────────

SQLite statements:         12,419
Unique queries:               183

Potential issues:

Full scans:                    4
Expensive full scans:          2
Sort operations:              12
Automatic indexes:             1
High VM workloads:             3
```

Dettaglio:

```text
[1] EXPENSIVE FULL SCAN

SELECT *
FROM users
WHERE email = ?

Executions:            425
Max fullscan steps:  10,000
Total fullscan:    4,250,000
Max VM steps:        45,231

Possible performance issue.
```

Le query problematiche devono essere ordinate per severità.

---

# 14. Exit code

SQLiteWatch deve preservare il risultato del processo target.

Esempio:

```text
pytest fallisce
→ sqlitewatch fallisce
```

In aggiunta, SQLiteWatch può fallire quando una propria regola viene violata.

Esempio:

```text
pytest: PASS

SQLiteWatch:
fullscan_steps > threshold

→ exit code != 0
```

Il report deve distinguere chiaramente:

```text
Application failure
```

da:

```text
SQLiteWatch performance rule failure
```

---

# 15. Modalità CI

Caso d'uso principale:

```yaml
- run: sqlitewatch --fail-fullscan-steps 10000 -- pytest
```

La CI deve fallire quando:

```text
application exit code != 0
```

oppure:

```text
una regola SQLiteWatch configurata viene violata
```

---

# 16. Supporto SQLite dinamico

L'MVP deve supportare SQLite caricato come libreria dinamica quando le funzioni della C API sono individuabili nel processo.

Esempi concettuali:

```text
libsqlite3.so
libsqlite3.dylib
sqlite3.dll
```

SQLiteWatch deve rilevare automaticamente i moduli caricati dal processo target e cercare le funzioni SQLite necessarie.

---

# 17. Supporto SQLite embedded

L'MVP dovrebbe supportare SQLite compilato direttamente dentro:

```text
eseguibile
native module
shared object
Node native addon
Python extension
```

quando le funzioni SQLite necessarie sono individuabili nel modulo.

Esempio:

```text
application
└── native_module
    └── sqlite3.c
        ├── sqlite3_prepare_v2
        ├── sqlite3_finalize
        └── sqlite3_stmt_status
```

SQLiteWatch deve cercare le funzioni SQLite nei moduli caricati.

Se le funzioni sono individuabili:

```text
✓ instrumentation supported
```

Se SQLite è embedded ma le funzioni non sono individuabili:

```text
✗ unsupported SQLite build
```

L'MVP non deve implementare binary fingerprinting avanzato per ricostruire funzioni SQLite in binari completamente stripped.

---

# 18. Detection failure

È fondamentale evitare falsi positivi in CI.

SQLiteWatch non deve mai restituire un report "pulito" semplicemente perché non è riuscito a intercettare SQLite.

Se l'applicazione utilizza SQLite ma l'instrumentation non è attiva, deve essere prodotto un errore esplicito.

Esempio:

```text
SQLiteWatch

SQLite detected: embedded
Instrumentation: unavailable
Reason: required SQLite symbols not found

ERROR: SQLite activity cannot be monitored.
```

In modalità CI questo caso deve produrre exit code diverso da zero.

---

# 19. Doctor mode

Deve essere prevista una modalità diagnostica:

```bash
sqlitewatch doctor -- <command>
```

Obiettivo:

verificare se SQLiteWatch è in grado di instrumentare l'applicazione.

Esempio:

```text
SQLiteWatch Doctor

SQLite detected: yes
SQLite version: 3.x.x

Implementation:
embedded SQLite

Module:
better-sqlite3.node

Required functions:
✓ sqlite3_prepare_v2
✓ sqlite3_finalize
✓ sqlite3_reset
✓ sqlite3_stmt_status

Instrumentation:
✓ supported
```

Oppure:

```text
SQLite detected: yes

Implementation:
embedded SQLite

Required symbols:
✗ unavailable

Instrumentation:
✗ unsupported
```

---

# 20. Output machine-readable

Oltre al report umano deve essere possibile produrre JSON:

```bash
sqlitewatch --format json -- pytest
```

Struttura indicativa:

```json
{
  "summary": {
    "statements": 12419,
    "unique_queries": 183
  },
  "queries": [
    {
      "sql": "SELECT * FROM users WHERE email = ?",
      "executions": 425,
      "fullscan_steps": {
        "total": 4250000,
        "max": 10000
      },
      "vm_steps": {
        "total": 13720312,
        "max": 45231
      },
      "sorts": 0,
      "autoindex": 0
    }
  ]
}
```

Questo formato deve poter essere salvato:

```bash
sqlitewatch --format json --output report.json -- pytest
```

---

# 21. Baseline

La baseline è una funzionalità altamente desiderabile per l'MVP, ma può essere considerata opzionale nella prima iterazione.

Creazione:

```bash
sqlitewatch --output baseline.json -- pytest
```

Confronto:

```bash
sqlitewatch \
    --baseline baseline.json \
    --fail-on-regression \
    -- pytest
```

Obiettivo:

rilevare regressioni rispetto a una versione precedente.

Esempio:

```text
PERFORMANCE REGRESSION

SELECT * FROM users WHERE email = ?

Baseline:
max fullscan steps: 0
max VM steps:       120

Current:
max fullscan steps: 10000
max VM steps:       45231
```

Questo permette di identificare regressioni senza dover definire soglie universali.

---

# 22. Non-obiettivi MVP

L'MVP non deve:

* suggerire automaticamente SQL `CREATE INDEX`;
* modificare lo schema;
* creare indici;
* riscrivere query;
* modificare il database;
* intercettare SQLite WASM;
* supportare binary fingerprinting di SQLite stripped;
* sostituire un APM;
* individuare automaticamente query N+1;
* misurare performance HTTP;
* analizzare query non effettivamente eseguite;
* richiedere una build SQLite custom.

---

# 23. Sicurezza

SQLiteWatch deve essere un osservatore passivo.

Non deve:

```text
modificare SQL
modificare parametri
modificare risultati
modificare transazioni
modificare SQLite pragmas
```

Un'applicazione eseguita:

```bash
sqlitewatch -- application
```

deve avere comportamento funzionale equivalente a:

```bash
application
```

salvo l'overhead introdotto dall'instrumentation.

---

# 24. Requisiti di performance

L'instrumentation deve minimizzare l'overhead.

In particolare:

* evitare scritture su disco per ogni statement;
* aggregare dati in memoria;
* evitare logging sincrono per ogni query;
* evitare di eseguire `EXPLAIN QUERY PLAN` automaticamente per ogni statement;
* raccogliere esclusivamente le metriche necessarie.

Il report può essere costruito alla fine dell'esecuzione.

---

# 25. EXPLAIN QUERY PLAN

`EXPLAIN QUERY PLAN` non deve essere utilizzato come sistema principale di detection.

Le metriche runtime SQLite devono essere la fonte primaria.

In una fase successiva, SQLiteWatch può utilizzare `EXPLAIN QUERY PLAN` come strumento diagnostico aggiuntivo per query già identificate come problematiche.

Esempio futuro:

```text
EXPENSIVE FULL SCAN

SELECT *
FROM users
WHERE email = ?

Runtime:
150,000 fullscan steps

Query plan:
SCAN users
```

---

# 26. Piattaforme target

Obiettivo finale:

```text
Linux
macOS
Windows
```

Per l'MVP iniziale è accettabile implementare una singola piattaforma, purché l'architettura dell'instrumentation non sia legata al linguaggio dell'applicazione target.

La priorità iniziale consigliata è:

```text
Linux x86_64
```

seguendo con:

```text
macOS
Windows
```

---

# 27. Criteri di successo del POC

Prima di sviluppare l'intero MVP deve essere validato un POC.

Il POC deve riuscire a intercettare:

```text
sqlite3_prepare_v2()
```

e ottenere il testo SQL eseguito in almeno:

1. un programma che utilizza SQLite dinamicamente;
2. un programma che incorpora `sqlite3.c`;
3. Python con il modulo SQLite standard;
4. Node.js con un binding SQLite nativo.

Il POC è considerato riuscito se lo stesso sistema di instrumentation può osservare almeno questi scenari senza modificare il codice delle applicazioni.

---

# 28. Criteri di successo MVP

L'MVP è considerato completo quando il seguente scenario funziona:

```bash
sqlitewatch \
    --fail-fullscan-steps 10000 \
    -- pytest
```

e SQLiteWatch:

1. avvia correttamente `pytest`;
2. rileva SQLite;
3. intercetta gli statement;
4. identifica SQL e prepared statement;
5. raccoglie `FULLSCAN_STEP`;
6. raccoglie `VM_STEP`;
7. raccoglie `SORT`;
8. raccoglie `AUTOINDEX`;
9. aggrega le query;
10. produce un report;
11. fallisce quando una soglia configurata viene superata;
12. preserva eventuali errori del processo target;
13. segnala esplicitamente quando SQLite non può essere instrumentato.

L'obiettivo finale dell'MVP è rendere possibile questa esperienza:

```text
$ sqlitewatch --fail-fullscan-steps 10000 -- pytest

================ tests ================
128 passed
=======================================

SQLiteWatch

183 unique queries analyzed

⚠ Performance issues detected

SELECT *
FROM users
WHERE email = ?

Executions:           425
Max fullscan steps: 10000
Max VM steps:       45231

SQLiteWatch performance checks failed.
```

senza che il progetto analizzato contenga una singola riga di codice specifica per SQLiteWatch.
